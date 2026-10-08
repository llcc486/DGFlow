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
