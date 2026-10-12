import numpy as np
import pytest

from dgfl.validation import policy


def test_fixed_batches_drop_collateral_and_do_not_rebatch():
    result=policy.apply_batches({'client1','client3','client4','client5','client6'},6)
    assert result==['client3','client4','client5','client6']


def test_detector_does_not_force_rejection_in_clean_cluster():
    assert policy.select({'a':.8,'b':.85,'c':.82,'d':.79})=={'a','b','c','d'}
    assert policy.select({'a':.8,'b':.8})=={'a','b'}
    assert policy.select({'a':-.9,'b':.8,'c':.85})=={'b','c'}


def test_quantization_and_zero_reference_are_explicit():
    assert policy.quantize([.125,-.125,2.0],scale=8,bits=5)==[1,-1,15]
    with pytest.raises(ValueError): policy.quantize([float('nan')],8,5)
    with pytest.raises(ValueError): policy.cosine(0,0,1)
    assert policy.cosine(5,5,5)==1.0


def test_same_direction_amplification_is_rejected_using_verified_norms():
    scores=dict.fromkeys(['a','b','c','d'],1.0)
    norms={'a':100,'b':121,'c':100,'d':1600}
    chosen,reasons=policy.screen(scores,norms,policy.SCREENING_DEFAULTS)
    assert chosen=={'a','b','c'}
    assert '中位数' in reasons['d']


def test_independent_norm_and_similarity_limits_apply_without_clustering():
    chosen,reasons=policy.screen({'a':.9,'b':.9,'c':-.1}, {'a':100,'b':401,'c':100},
                                {'max_norm_squared':400,'min_cosine':0})
    assert chosen=={'a'}
    assert '平方范数' in reasons['b'] and '相似度' in reasons['c']


def test_regroup_retains_honest_partner_and_odd_survivors_but_never_singleton():
    survivors={'client2','client3','client4','client5','client6'}
    assert policy.apply_batches(survivors,6,strategy='regroup')==sorted(survivors)
    assert policy.apply_batches({'client1','client3'},6,strategy='regroup')==['client1','client3']
    assert policy.apply_batches({'client1'},6,strategy='regroup')==[]


@pytest.mark.parametrize('settings', [
    {'min_cosine':float('nan')},{'min_cosine':True},{'max_norm_squared':1.5},
    {'max_norm_squared':False},{'max_norm_ratio':.9},{'max_norm_ratio':float('inf')},
    {'batch_strategy':'unchecked'}])
def test_screening_settings_reject_invalid_controls(settings):
    with pytest.raises(ValueError): policy.screening_settings(settings)


def test_legacy_omitted_settings_retain_explicit_ablation_behavior():
    assert policy.screening_settings({})=={}
    chosen,_=policy.screen({'a':-.1,'b':-.1},{'a':1,'b':100},{})
    assert chosen=={'a','b'}


def test_new_task_defaults_preserve_fixed_batches_and_leave_lower_norm_disabled():
    settings=policy.screening_settings({},defaults=True)
    assert settings['batch_strategy']=='fixed'
    assert settings['min_norm_ratio'] is None
    assert policy.screening_settings({})=={}


@pytest.mark.parametrize('squared_norm,accepted',[(63,False),(64,True),(65,True)])
def test_lower_norm_ratio_is_a_decimal_l2_ratio_with_an_inclusive_boundary(squared_norm,accepted):
    scores=dict.fromkeys(['candidate','honest1','honest2'],.9)
    norms={'candidate':squared_norm,'honest1':100,'honest2':100}
    chosen,reasons=policy.screen(scores,norms,{'min_norm_ratio':.8})
    assert ('candidate' in chosen) is accepted
    assert ('candidate' in reasons) is not accepted


@pytest.mark.parametrize('squared_norm,accepted',[(120,True),(121,True),(122,False)])
def test_upper_norm_ratio_uses_the_same_decimal_l2_ratio_boundary(squared_norm,accepted):
    scores=dict.fromkeys(['candidate','honest1','honest2'],.9)
    norms={'candidate':squared_norm,'honest1':100,'honest2':100}
    chosen,reasons=policy.screen(scores,norms,{'max_norm_ratio':1.1})
    assert ('candidate' in chosen) is accepted
    assert ('candidate' in reasons) is not accepted


def test_norm_ratio_gates_are_symmetric_and_do_not_round_huge_verified_integers():
    unit=10**600
    norms={'too_small':25*unit-1,'lower_boundary':25*unit,'median':100*unit,
           'upper_boundary':400*unit,'too_large':400*unit+1}
    chosen,reasons=policy.screen(dict.fromkeys(norms,.9),norms,
                                 {'min_norm_ratio':.5,'max_norm_ratio':2.0})
    assert chosen=={'lower_boundary','median','upper_boundary'}
    assert reasons=={'too_small':'范数幅度低于群体中位数门限',
                     'too_large':'范数幅度超过群体中位数门限'}


@pytest.mark.parametrize('bad',[True,False,None,'0.9',[],{},float('nan'),float('inf'),-1.01,1.01])
def test_malformed_scores_are_rejected_before_empty_or_clean_cluster_shortcuts(bad):
    scores={'candidate':bad}
    with pytest.raises(ValueError,match='similarity'):
        policy.select(scores)
    with pytest.raises(ValueError,match='similarity'):
        policy.screen(scores,{'candidate':1},{'min_cosine':1})


@pytest.mark.parametrize('bad',[None,[],[('candidate',.9)],0,True])
def test_malformed_score_mapping_is_rejected_even_when_empty(bad):
    with pytest.raises(ValueError,match='similarity'):
        policy.select(bad)


@pytest.mark.parametrize('bad',[None,[],{'candidate':True},{'candidate':1.0},{'candidate':0},{}])
def test_verified_squared_norms_require_matching_positive_integer_values(bad):
    with pytest.raises(ValueError,match='verified squared norms'):
        policy.screen({'candidate':.9},bad,{})


@pytest.mark.parametrize('settings',[
    {'min_norm_ratio':True},{'min_norm_ratio':False},{'min_norm_ratio':float('nan')},
    {'min_norm_ratio':float('inf')},{'min_norm_ratio':0},{'min_norm_ratio':1.01},
    {'max_norm_ratio':True},{'max_norm_ratio':False},None,[],0])
def test_lower_norm_and_mapping_settings_reject_malformed_controls(settings):
    with pytest.raises(ValueError):
        policy.screening_settings(settings)


def _selection_matrix(candidate_sets,strategy):
    members=policy.client_members(6)
    return np.asarray([[int(cid in policy.apply_batches(candidates,6,strategy=strategy))
                        for cid in members] for candidates in candidate_sets],dtype=int)


def test_fixed_batch_selection_columns_stay_identical_across_changing_rounds():
    members=policy.client_members(6)
    candidates=[set(members),set(members[:4]),set(members[:2]+members[4:]),
                set(members[2:]),set(members)-{'client1'},set(members)-{'client4'}]
    matrix=_selection_matrix(candidates,'fixed')
    for first in (0,2,4):
        np.testing.assert_array_equal(matrix[:,first],matrix[:,first+1])
    assert np.linalg.matrix_rank(matrix)==3
    # Equal columns leave the same-batch difference unobservable, even when
    # selection changes every round. This is the paper's MRPL premise, not a
    # claim that local training or colluding clients are hidden by this test.
    np.testing.assert_array_equal(matrix@np.asarray([1,-1,0,0,0,0]),np.zeros(len(matrix)))


def test_regroup_minimum_two_is_insufficient_to_preserve_the_mrpl_premise():
    members=set(policy.client_members(6))
    candidates=[members]+[members-{cid} for cid in sorted(members)]
    matrix=_selection_matrix(candidates,'regroup')
    assert np.all(matrix.sum(axis=1)>=2)
    assert np.linalg.matrix_rank(matrix)==6
    values=np.asarray([3,5,7,11,13,17])
    recovered=np.linalg.lstsq(matrix,matrix@values,rcond=None)[0]
    np.testing.assert_allclose(recovered,values,rtol=0,atol=1e-12)
