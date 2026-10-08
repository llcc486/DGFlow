"""DKG share verification: exactness preserved, and the batch check is sound.

The batch path collapses every row into one MSM. That is only sound with random
weights, so the key test here crafts two rows whose residuals cancel -- which a
naive unweighted sum would accept -- and requires the implementation to reject it.
"""
import pytest

from dgfl.crypto import backend as b
from dgfl.crypto import protocol as p

D = 8
CLIENTS = ['c1', 'c2']
MEMBERS = [1, 2, 3]
THRESHOLD = 2
EPOCH = 'e'


def build(verification='deterministic'):
    nodes = [p.Authority(m, MEMBERS, CLIENTS, D, THRESHOLD, EPOCH, verification=verification)
             for m in MEMBERS]
    commits = {n.node_id: n.commitments() for n in nodes}
    for receiver in nodes:
        receiver.set_commitments(commits)
    shares = {(d.node_id, r.node_id): d.share_for(r.node_id)
              for d in nodes for r in nodes}
    return nodes, shares


def test_expected_matches_the_original_inline_expression():
    """`_expected` must be the identical point the old g1_sum loop produced."""
    nodes, _ = build()
    node = nodes[0]
    commits = [[b.g1_load(x) for x in row] for row in nodes[1].commitments()['points']]
    for row in commits:
        legacy = b.g1_sum(
            c * b.scalar(pow(node.node_id, j, b.ORDER)) for j, c in enumerate(row))
        assert node._expected(row) == legacy


def test_expected_handles_a_wider_threshold():
    nodes = [p.Authority(m, MEMBERS, CLIENTS, D, 3, EPOCH) for m in MEMBERS]
    node = nodes[0]
    commits = {n.node_id: n.commitments() for n in nodes}
    parsed = {nid: [[b.g1_load(x) for x in row] for row in c['points']]
              for nid, c in commits.items()}
    for row in parsed[nodes[1].node_id]:
        legacy = b.g1_sum(
            c * b.scalar(pow(node.node_id, j, b.ORDER)) for j, c in enumerate(row))
        assert node._expected(row) == legacy


def test_deterministic_path_accepts_honest_shares():
    nodes, shares = build('deterministic')
    for (dealer, recipient), msg in shares.items():
        next(n for n in nodes if n.node_id == recipient).receive_share(dealer, msg)
    for n in nodes:
        n.finalize()


def test_randomized_path_accepts_honest_shares():
    nodes, shares = build('randomized')
    for (dealer, recipient), msg in shares.items():
        next(n for n in nodes if n.node_id == recipient).receive_share(dealer, msg)
    for n in nodes:
        n.finalize()


@pytest.mark.parametrize('verification', ['deterministic', 'randomized'])
def test_corrupted_share_is_rejected(verification):
    nodes, shares = build(verification)
    dealer, recipient = 1, 2
    msg = dict(shares[(dealer, recipient)])
    raw = bytearray(msg['s'][0])
    raw[-1] ^= 0x01
    msg['s'] = [bytes(raw), *msg['s'][1:]]
    with pytest.raises(ValueError, match='violates commitment'):
        next(n for n in nodes if n.node_id == recipient).receive_share(dealer, msg)


@pytest.mark.parametrize('verification', ['deterministic', 'randomized'])
def test_two_cancelling_residuals_are_rejected(verification):
    """The attack that defeats an unweighted sum of rows.

    Row 0 is shifted by +delta and row 1 by -delta, so the two residuals are
    G*delta and -G*delta. Their unweighted sum is the identity, but neither row
    is valid. Random weights must still reject this.
    """
    nodes, shares = build(verification)
    dealer, recipient = 1, 2
    msg = dict(shares[(dealer, recipient)])
    delta = 12345678901234567890
    s = [b.scalar_load(x) for x in msg['s']]
    s[0] = (s[0] + delta) % b.ORDER
    s[1] = (s[1] - delta) % b.ORDER
    msg['s'] = [b.scalar_dump(x) for x in s]
    with pytest.raises(ValueError, match='violates commitment'):
        next(n for n in nodes if n.node_id == recipient).receive_share(dealer, msg)


def test_unweighted_row_sum_would_have_accepted_the_cancelling_pair():
    """Demonstrates why the weights are required: the naive sum is fooled."""
    nodes, shares = build('deterministic')
    recipient = next(n for n in nodes if n.node_id == 2)
    msg = dict(shares[(1, 2)])
    delta = 12345678901234567890
    s = [b.scalar_load(x) for x in msg['s']]
    s[0] = (s[0] + delta) % b.ORDER
    s[1] = (s[1] - delta) % b.ORDER
    rows = recipient._all_commits[1]
    points, coefficients = [], []
    for value, r, row in zip(s, [b.scalar_load(x) for x in msg['r']], rows):
        points += [b.G, b.H, row[0], row[1]]
        coefficients += [value, r, -1, -recipient._id_powers[1]]
    assert b.g1_msm(points, coefficients) == b.G1.identity(), (
        'a naive unweighted sum accepts two rows whose residuals cancel')
