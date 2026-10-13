"""Declared versions, and the rule for refusing a mismatched participant.

WHY THIS EXISTS
---------------
Improvements are delivered in stages, so a deployment can briefly contain nodes
built from different revisions. Without a declared version, a mixed deployment
fails in the middle of a round, or worse, silently exchanges messages that the
two sides interpret differently. This module is the single place that names the
wire protocol and the on-disk record formats, and the rule for rejecting a
participant that cannot speak the required version.

WHERE A VERSION GOES, AND WHERE IT MUST NOT
-------------------------------------------
The protocol version travels in the RPC message and in the `health` capability
set. It is deliberately NOT placed in the round context: `ctx` is digested into
`context_hash`, which binds every proof challenge and every recorded evidence
row. Adding a field there would change the hash of historical rounds and break
comparability with already published evidence, which this project does not do.

HISTORICAL RECORDS
------------------
Records written before a field existed are read through an explicit historical
branch keyed on the version they declare, never by assuming the current shape.
`accepts_record` answers that question for readers.
"""
from __future__ import annotations

from dgfl import __version__

# Wire protocol between the coordinator and a role node.
PROTOCOL_VERSION = 1
SUPPORTED_PROTOCOL_VERSIONS = (1,)

# On-disk record shapes. Each is bumped only when the stored shape changes.
RECORD_SCHEMA_VERSION = 1
CHECKPOINT_SCHEMA_VERSION = 1
IDENTITY_REGISTRY_VERSION = 1
SCREENING_VERSION = 1

# The oldest protocol this build still accepts from a peer. A peer older than
# this cannot be reasoned about safely, so the round never starts.
MINIMUM_PROTOCOL_VERSION = 1

# Human-facing name of the release that produced a record.
IMPLEMENTATION_VERSION = __version__

# Field set of one RPC message. The version field is optional because a peer
# built before it existed sends the historical two-field message; the version
# guarantee is enforced before a round starts, not by message shape. Declared here
# because both the direct request path and the chunked-body reassembly validate
# the same message.
MESSAGE_REQUIRED_FIELDS = frozenset({'action', 'payload'})
MESSAGE_OPTIONAL_FIELDS = frozenset({'protocol_version'})


def is_message_shape(value) -> bool:
    """True when a decoded mapping is one RPC message of a known shape."""
    if not isinstance(value, dict):
        return False
    keys = set(value)
    return (keys >= MESSAGE_REQUIRED_FIELDS
            and keys <= MESSAGE_REQUIRED_FIELDS | MESSAGE_OPTIONAL_FIELDS
            and isinstance(value.get('action'), str) and bool(value.get('action'))
            and isinstance(value.get('payload'), dict))


class VersionMismatch(ValueError):
    """A participant or record declares a version this build cannot accept."""

    def __init__(self, subject: str, required, available, *, detail: str = ''):
        self.subject = subject
        self.required = required
        self.available = available
        self.detail = detail
        message = f'{subject}: 需要版本 {_render(required)}，本节点支持 {_render(available)}'
        if detail:
            message += f'（{detail}）'
        super().__init__(message)


def _render(value) -> str:
    if isinstance(value, (tuple, list, set, frozenset)):
        return '、'.join(str(item) for item in sorted(value))
    return str(value)


def version_declaration() -> dict:
    """What this build speaks, for `health` and the control status page."""
    return {'implementation': IMPLEMENTATION_VERSION,
            'protocol_version': PROTOCOL_VERSION,
            'supported_protocol_versions': list(SUPPORTED_PROTOCOL_VERSIONS),
            'minimum_protocol_version': MINIMUM_PROTOCOL_VERSION,
            'record_schema_version': RECORD_SCHEMA_VERSION,
            'checkpoint_schema_version': CHECKPOINT_SCHEMA_VERSION,
            'identity_registry_version': IDENTITY_REGISTRY_VERSION,
            'screening_version': SCREENING_VERSION}


def parse_protocol_version(value, *, subject='消息'):
    """Read a declared protocol version, rejecting an absent or malformed one."""
    if type(value) is not int or value < 1:
        raise VersionMismatch(subject, PROTOCOL_VERSION, SUPPORTED_PROTOCOL_VERSIONS,
                              detail='消息未声明有效的协议版本')
    return value


def accepts_protocol(value) -> bool:
    """True when this build can interpret a peer that declares `value`."""
    return type(value) is int and value in SUPPORTED_PROTOCOL_VERSIONS


def require_protocol(value, *, subject='消息'):
    """Raise unless this build can interpret the declared protocol version.

    Used on both sides of every role RPC, so a mixed deployment fails at the
    first exchange with a readable reason instead of mid-round.
    """
    version = parse_protocol_version(value, subject=subject)
    if not accepts_protocol(version):
        raise VersionMismatch(subject, PROTOCOL_VERSION, SUPPORTED_PROTOCOL_VERSIONS,
                              detail=f'对方声明 {version}')
    return version


def require_participants(nodes, *, action='训练', strict=False):
    """Refuse to start an operation when a participant cannot speak this protocol.

    `nodes` is the advertised capability set of each participant, as returned by
    the role `health` action. The check happens before any round starts, which is
    the required behaviour: a mixed deployment must produce a clear error rather
    than a partially executed round.

    A participant that declares a version this build cannot interpret is always
    refused. A participant that declares **no** version is refused only when
    `strict` is set. The two cases are genuinely different: an unsupported
    declaration is a known incompatibility, while a missing one cannot be
    distinguished from a peer built before the field existed. This project's own
    role service always declares the version, so a real deployment is checked in
    full; `strict` exists for an operator who has upgraded every machine and wants
    the stronger guarantee enforced as well.
    """
    unsupported = {}
    undeclared = {}
    for name in sorted(nodes):
        declaration = nodes[name] or {}
        if not isinstance(declaration, dict):
            undeclared[name] = '未声明能力'
            continue
        version = declaration.get('protocol_version')
        if version is None:
            undeclared[name] = '未声明协议版本'
        elif not accepts_protocol(version):
            unsupported[name] = f'协议版本 {version}'
    if unsupported or (strict and undeclared):
        offenders = {**unsupported, **undeclared}
        detail = '；'.join(f'{name}：{reason}' for name, reason in offenders.items())
        raise VersionMismatch(f'{action}前的参与节点版本核对',
                              PROTOCOL_VERSION, SUPPORTED_PROTOCOL_VERSIONS, detail=detail)
    return {'checked': len(nodes) - len(undeclared), 'undeclared': sorted(undeclared)}


def accepts_record(version, *, expected=RECORD_SCHEMA_VERSION, subject='记录'):
    """Whether a stored record declares a shape this build can read.

    Readers use this to pick an explicit historical branch instead of assuming
    the current field set. An unreadable version is refused rather than guessed.
    """
    if type(version) is not int or version < 1:
        raise VersionMismatch(subject, expected, (expected,), detail='记录未声明有效的格式版本')
    if version > expected:
        raise VersionMismatch(subject, expected, (expected,),
                              detail=f'记录来自更新的格式版本 {version}，本实现不向前兼容')
    return version


def describe() -> str:
    """One-line summary for a CLI banner or a log line."""
    return (f'dgfl {IMPLEMENTATION_VERSION}；协议 v{PROTOCOL_VERSION}；'
            f'记录格式 v{RECORD_SCHEMA_VERSION}；检查点 v{CHECKPOINT_SCHEMA_VERSION}；'
            f'身份登记 v{IDENTITY_REGISTRY_VERSION}；筛选 v{SCREENING_VERSION}')
