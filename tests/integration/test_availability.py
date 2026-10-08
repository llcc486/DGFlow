import pytest

from dgfl.experiments.runner import choose_participants


def test_one_missing_cloud_and_client_do_not_abort_entire_task():
    online={f'client{i}' for i in range(2,7)}|{'authority1','authority2','authority3','aggregator1','aggregator2'}
    clients,clouds=choose_participants(online,'dgflow',0)
    assert clients==['client2','client3','client4','client5','client6']
    assert clouds==['aggregator1','aggregator2']
    with pytest.raises(ValueError,match='2/3'):
        choose_participants(online-{'aggregator2'},'dgflow',0)

