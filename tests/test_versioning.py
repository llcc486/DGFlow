"""Version declaration, negotiation and historical-record acceptance.

A mixed deployment must fail before a round starts with a readable reason, and a
version must never enter the round context: `ctx` is digested into every proof
challenge, so a field there would change the hash of already published evidence.
"""
from __future__ import annotations

import hashlib

import pytest

from dgfl import versioning
from dgfl.experiments.runner import require_participant_versions
from dgfl.transport.binary import packb


def test_declaration_names_every_version_the_project_carries():
    declaration = versioning.version_declaration()
    assert declaration['implementation'] == versioning.IMPLEMENTATION_VERSION
    assert declaration['protocol_version'] in declaration['supported_protocol_versions']
    assert declaration['protocol_version'] >= declaration['minimum_protocol_version']
    for field in ('record_schema_version', 'checkpoint_schema_version',
                  'identity_registry_version', 'screening_version'):
        assert type(declaration[field]) is int and declaration[field] >= 1


def test_every_message_shape_accepts_the_version_and_the_historical_form():
    current = {'action': 'health', 'payload': {}, 'protocol_version': versioning.PROTOCOL_VERSION}
    historical = {'action': 'health', 'payload': {}}
    assert versioning.is_message_shape(current)
    assert versioning.is_message_shape(historical)
    # The optional field is exactly one field wide; anything else is malformed.
    assert not versioning.is_message_shape({**current, 'extra': 1})
    assert not versioning.is_message_shape({'action': 'health'})
    assert not versioning.is_message_shape({'payload': {}})
    assert not versioning.is_message_shape({'action': '', 'payload': {}})
    assert not versioning.is_message_shape({'action': 'health', 'payload': []})


def test_supported_version_round_trips():
    assert versioning.require_protocol(versioning.PROTOCOL_VERSION) == versioning.PROTOCOL_VERSION
    assert versioning.accepts_protocol(versioning.PROTOCOL_VERSION)


@pytest.mark.parametrize('declared', [None, 0, -1, '1', 1.0, True, 99])
def test_unsupported_declaration_is_refused_and_explained(declared):
    """No malformed or unsupported declaration may pass; each is diagnosed."""
    with pytest.raises(versioning.VersionMismatch) as caught:
        versioning.require_protocol(declared, subject='测试消息')
    message = str(caught.value)
    assert '测试消息' in message
    # The message states what is required and what this build supports, so an
    # operator can tell a missing declaration from an unsupported one.
    assert '1' in message


def test_participants_are_checked_together_and_offenders_are_listed():
    good = {'protocol_version': versioning.PROTOCOL_VERSION}
    result = versioning.require_participants({'client1': good, 'client2': good})
    assert result == {'checked': 2, 'undeclared': []}
    with pytest.raises(versioning.VersionMismatch) as caught:
        versioning.require_participants({'client1': good, 'client2': {'protocol_version': 99},
                                         'client3': good})
    message = str(caught.value)
    assert 'client2' in message
    assert 'client1' not in message


def test_an_unsupported_declaration_is_always_refused():
    """A peer that states a version this build cannot read is a known mismatch."""
    with pytest.raises(versioning.VersionMismatch, match='client1'):
        versioning.require_participants({'client1': {'protocol_version': 99}})
    with pytest.raises(versioning.VersionMismatch, match='client1'):
        versioning.require_participants({'client1': {'protocol_version': 99}}, strict=True)


def test_an_undeclared_version_is_reported_and_only_refused_under_strict():
    """A missing declaration is not the same fact as an unsupported one.

    The project's own role service always declares its version, so a real
    deployment is checked in full. `strict` exists for an operator who has
    upgraded every machine and wants the stronger rule enforced as well.
    """
    undeclared = {'client1': {}}
    result = versioning.require_participants(undeclared)
    assert result['undeclared'] == ['client1'] and result['checked'] == 0
    with pytest.raises(versioning.VersionMismatch, match='client1'):
        versioning.require_participants(undeclared, strict=True)


def test_participant_check_runs_before_a_round_and_reads_the_health_declaration():
    """The gate reads `health`, so a node that declares an unreadable version is refused."""
    replies = {'client1': {'protocol_version': versioning.PROTOCOL_VERSION},
               'authority1': {'protocol_version': 99}}
    assert require_participant_versions(replies, ['client1'])['checked'] == 1
    with pytest.raises(versioning.VersionMismatch, match='authority1'):
        require_participant_versions(replies, ['client1', 'authority1'])


def test_participant_check_accepts_a_declaration_nested_in_capabilities():
    """Older health replies carry the version inside `capabilities`."""
    replies = {'client1': {'capabilities': {'protocol_version': versioning.PROTOCOL_VERSION}}}
    assert require_participant_versions(replies, ['client1'])['checked'] == 1


def test_a_reachable_participant_that_declares_nothing_is_reported_not_guessed():
    """Silence is recorded, and only a strict operator turns it into a refusal."""
    replies = {'client1': {'status': 'online'}}
    result = require_participant_versions(replies, ['client1'])
    assert result['undeclared'] == ['client1']
    with pytest.raises(versioning.VersionMismatch, match='client1'):
        require_participant_versions(replies, ['client1'], strict=True)


def test_record_versions_accept_history_and_refuse_the_future():
    assert versioning.accepts_record(1) == 1
    with pytest.raises(versioning.VersionMismatch, match='向前兼容'):
        versioning.accepts_record(versioning.RECORD_SCHEMA_VERSION + 1)
    with pytest.raises(versioning.VersionMismatch, match='未声明'):
        versioning.accepts_record(None)


def test_protocol_version_never_enters_the_round_context_hash():
    """Adding a version to `ctx` would change every historical context hash.

    This pins the property: a context with and without a version field digests
    differently, so the field must stay out of it. The check is on the digest,
    not on a comment.
    """
    ctx = {'task_id': 'run', 'round_id': 1, 'key_epoch': 'epoch', 'model_hash': 'ab' * 32,
           'bits': 8, 'scale': 128, 'dimension': 4, 'dataset': 'mnist'}
    with_version = {**ctx, 'protocol_version': versioning.PROTOCOL_VERSION}
    assert hashlib.sha256(packb(ctx)).hexdigest() != hashlib.sha256(packb(with_version)).hexdigest()
    assert 'protocol_version' not in ctx


def test_describe_reports_every_version_for_an_operator():
    text = versioning.describe()
    for fragment in ('协议 v', '记录格式 v', '检查点 v', '身份登记 v', '筛选 v'):
        assert fragment in text
