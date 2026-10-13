"""Series reads replay measurements without collecting or changing protocol work."""
import json
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient

from dgfl.experiments.monitor_series import MonitorSeries
from dgfl.experiments.monitoring import RunNodeMonitor
from dgfl.services.control import create_control_app

RUN = 'series-run'


def resource(sequence, index=None, *, value=25, machine=False, time=None):
    index = sequence - 1 if index is None else index
    payload = {'sample_index': index, 'round_id': 1,
               'processes': {'cpu_percent': value, 'rss_bytes': 1024}}
    if machine:
        payload.update(cpu={'system_utilization_percent': value},
                       system={'memory_percent': 40}, gpu={'utilization_percent': None})
    return {'sequence': sequence, 'kind': 'resource',
            'time': time or f'2026-10-13T01:00:{index:02d}+00:00', 'payload': payload}


def epoch(sequence, step, value=.75):
    return {'sequence': sequence, 'kind': 'epoch', 'time': '2026-10-13T01:01:00+00:00',
            'payload': {'step': step, 'round_id': 1, 'epoch': step, 'accuracy': value, 'loss': .5}}


def record():
    return {'run_id': RUN, 'status': 'completed', 'config': {'local_epochs': 2}, 'evidence': {
        'monitor_local_machine': 'local',
        'node_snapshot': [
            {'id': 'client1', 'role': 'client', 'machine': 'local', 'host': 'https://old:1'},
            {'id': 'authority1', 'role': 'authority', 'machine': 'B', 'host': 'https://old:2'},
            {'id': 'aggregator1', 'role': 'aggregator', 'machine': 'B', 'host': 'https://old:3'}]}}


def append(tmp_path, node, events, segment='a'):
    directory = tmp_path / 'monitoring' / RUN
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f'{node}.{segment}.jsonl'
    with path.open('a', encoding='utf8') as stream:
        for event in events:
            stream.write(json.dumps({'node_id': node, 'event': event}) + '\n')
    return path


def query(reader, **kwargs):
    return reader.query(record(), scope='node', target='client1', metric='processes.cpu_percent', **kwargs)


def test_pagination_retry_incremental_append_and_null_gaps(tmp_path):
    append(tmp_path, 'client1', [resource(1, value=0), resource(2, value=None), resource(3, value=30)])
    reader = MonitorSeries(tmp_path)
    first = query(reader, limit=2)
    assert [point['value'] for point in first['points']] == [0, None]
    assert first['has_more'] is True and first['source'] == 'journal'
    second = query(reader, limit=2, cursor=first['next_cursor'])
    retry = query(reader, limit=2, cursor=first['next_cursor'])
    assert second['points'] == retry['points']
    assert [point['step'] for point in second['points']] == [2]
    assert second['has_more'] is False
    append(tmp_path, 'client1', [resource(4, value=40)])
    third = query(reader, cursor=second['next_cursor'])
    assert [point['value'] for point in third['points']] == [40]
    assert third['points'][0]['time'] == '2026-10-13T01:00:03.000Z'
    assert len({point['id'] for page in (first, second, third) for point in page['points']}) == 4


def test_segments_merge_by_sequence_and_duplicate_replays_are_not_repeated(tmp_path):
    append(tmp_path, 'client1', [resource(1), resource(2)], 'z-old')
    append(tmp_path, 'client1', [resource(2), resource(3)], 'a-new')
    reader = MonitorSeries(tmp_path)
    first = query(reader, limit=1)
    points = list(first['points'])
    cursor = first['next_cursor']
    for _ in range(4):
        page = query(reader, cursor=cursor, limit=1)
        points.extend(page['points'])
        cursor = page['next_cursor']
        if not page['has_more']:
            break
    assert [point['step'] for point in points] == [0, 1, 2]
    append(tmp_path, 'client1', [resource(1), resource(4)], 'b-restart')
    assert [point['step'] for point in query(reader, cursor=cursor)['points']] == [3]


def test_epoch_metric_never_interpolates_or_exposes_resource_or_private_fields(tmp_path):
    append(tmp_path, 'client1', [resource(1), epoch(2, 1), epoch(3, 2, float('nan'))])
    result = MonitorSeries(tmp_path).query(record(), scope='node', target='client1', metric='training.accuracy')
    assert [point['value'] for point in result['points']] == [.75, None]
    assert [point['epoch'] for point in result['points']] == [1, 2]
    assert result['unit'] == 'ratio'
    with pytest.raises(ValueError, match='不支持'):
        MonitorSeries(tmp_path).query(record(), scope='node', target='client1', metric='training.private_key')


def test_machine_metrics_use_only_the_frozen_machine_representative(tmp_path):
    append(tmp_path, 'authority1', [resource(1, machine=True)])
    append(tmp_path, 'aggregator1', [resource(1, machine=False)])
    append(tmp_path, 'client1', [resource(1, machine=True, value=99)])
    result = MonitorSeries(tmp_path).query(record(), scope='machine', target='B',
                                          metric='cpu.system_utilization_percent')
    assert [point['value'] for point in result['points']] == [25]
    assert result['points'][0]['id'] == 'machine:B:authority1:resource:0'


def test_declared_machine_source_never_opens_other_same_machine_journals(tmp_path, monkeypatch):
    import dgfl.experiments.monitor_series as module
    historical = record()
    historical['evidence']['node_monitoring'] = {'machines': [
        {'id': 'B', 'source_node': 'authority1'}]}
    append(tmp_path, 'authority1', [resource(1, machine=True, value=25)])
    append(tmp_path, 'aggregator1', [resource(1, machine=True, value=99)])
    opened = []
    original = module._safe_open
    def tracked_open(path, flags):
        opened.append(path.name)
        return original(path, flags)
    monkeypatch.setattr(module, '_safe_open', tracked_open)
    result = MonitorSeries(tmp_path).query(historical, scope='machine', target='B',
                                          metric='cpu.system_utilization_percent')
    assert opened == ['authority1.a.jsonl']
    assert [point['value'] for point in result['points']] == [25]
    assert result['points'][0]['source_node'] == 'authority1'


@pytest.mark.parametrize('declared_source', [True, False])
def test_machine_history_supports_the_maximum_164_node_topology(tmp_path, declared_source):
    maximum = record()
    nodes = [{'id': f'{role}{index}', 'role': role, 'machine': 'B'}
             for role, count in [('client', 100), ('authority', 32), ('aggregator', 32)]
             for index in range(1, count + 1)]
    maximum['evidence']['node_snapshot'] = nodes
    if declared_source:
        maximum['evidence']['node_monitoring'] = {'machines': [
            {'id': 'B', 'source_node': 'authority1'}]}
    for node in nodes:
        append(tmp_path, node['id'], [resource(1, machine=node['id'] == 'authority1')])
    result = MonitorSeries(tmp_path).query(maximum, scope='machine', target='B',
                                          metric='cpu.system_utilization_percent')
    assert [point['value'] for point in result['points']] == [25]
    assert result['points'][0]['source_node'] == 'authority1'


def test_legacy_different_machine_sources_with_the_same_index_have_distinct_ids(tmp_path):
    append(tmp_path, 'authority1', [resource(1, machine=True, value=25)])
    append(tmp_path, 'aggregator1', [resource(1, machine=True, value=30)])
    reader = MonitorSeries(tmp_path)
    params = {'scope': 'machine', 'target': 'B', 'metric': 'cpu.system_utilization_percent'}
    first = reader.query(record(), **params, limit=1)
    second = reader.query(record(), **params, cursor=first['next_cursor'], limit=1)
    points = first['points'] + second['points']
    assert len({point['id'] for point in points}) == 2
    assert {point['source_node'] for point in points} == {'authority1', 'aggregator1'}
    assert {point['value'] for point in points} == {25, 30}


def test_more_than_128_append_only_segments_can_be_replayed(tmp_path):
    for index in range(164):
        append(tmp_path, 'client1', [resource(index + 1, index,
                                            time='2026-10-13T01:00:00Z')], f'segment-{index:03d}')
    result = query(MonitorSeries(tmp_path))
    assert len(result['points']) == 164
    assert result['has_more'] is False


@pytest.mark.parametrize('value', [float('nan'), float('inf'), -1, True, '22'])
def test_nonfinite_invalid_numeric_values_become_explicit_gaps(tmp_path, value):
    append(tmp_path, 'client1', [resource(1, value=value)])
    assert query(MonitorSeries(tmp_path))['points'][0]['value'] is None


def test_time_window_uses_actual_timezone_aware_time_and_binds_cursor(tmp_path):
    append(tmp_path, 'client1', [resource(1), resource(2), resource(3)])
    reader = MonitorSeries(tmp_path)
    params = {'start': '2026-10-13T09:00:01+08:00', 'end': '2026-10-13T01:00:02Z'}
    page = query(reader, **params)
    assert [point['step'] for point in page['points']] == [1, 2]
    assert query(reader, cursor=page['next_cursor'], **params)['points'] == []
    with pytest.raises(ValueError, match='参数'):
        query(reader, cursor=page['next_cursor'])
    with pytest.raises(ValueError, match='时区'):
        query(reader, start='2026-10-13T01:00:00')
    with pytest.raises(ValueError, match='不得晚于'):
        query(reader, start=params['end'], end=params['start'])


def test_torn_tail_does_not_hide_other_segments_and_can_later_complete(tmp_path):
    path = append(tmp_path, 'client1', [resource(1)], 'a')
    serialized = json.dumps({'node_id': 'client1', 'event': resource(2)}) + '\n'
    with path.open('a', encoding='utf8') as stream:
        stream.write(serialized[:20])
    append(tmp_path, 'client1', [resource(3)], 'b')
    reader = MonitorSeries(tmp_path)
    page = query(reader)
    assert [point['step'] for point in page['points']] == [0, 2]
    # A recovered earlier sequence fills a remembered hole instead of being lost.
    with path.open('a', encoding='utf8') as stream:
        stream.write(serialized[20:])
    recovered = query(reader, cursor=page['next_cursor'])
    assert [point['step'] for point in recovered['points']] == [1]
    assert query(reader, cursor=recovered['next_cursor'])['points'] == []


def test_scan_budget_pages_large_irrelevant_journals_without_loading_all(tmp_path, monkeypatch):
    import dgfl.experiments.monitor_series as module
    monkeypatch.setattr(module, 'MAX_SCAN_ROWS', 2)
    append(tmp_path, 'client1', [epoch(1, 1), epoch(2, 2), resource(3)])
    reader = MonitorSeries(tmp_path)
    first = query(reader)
    assert first['points'] == [] and first['has_more'] is True
    second = query(reader, cursor=first['next_cursor'])
    assert [point['step'] for point in second['points']] == [2]
    assert second['has_more'] is False


def test_byte_budget_across_segments_does_not_skip_an_unconsumed_head(tmp_path, monkeypatch):
    import dgfl.experiments.monitor_series as module
    append(tmp_path, 'client1', [resource(1), resource(2)], 'z-old')
    append(tmp_path, 'client1', [resource(3)], 'a-new')
    # Enough budget to discover both segment heads but not the next event.
    monkeypatch.setattr(module, 'MAX_SCAN_BYTES', 500)
    reader = MonitorSeries(tmp_path)
    result, points = query(reader), []
    for _ in range(5):
        points.extend(result['points'])
        if not result['has_more']:
            break
        result = query(reader, cursor=result['next_cursor'])
    assert [point['step'] for point in points] == [0, 1, 2]
    assert result['has_more'] is False


def test_budget_smaller_than_segment_heads_still_advances_the_cursor(tmp_path, monkeypatch):
    import dgfl.experiments.monitor_series as module
    append(tmp_path, 'client1', [resource(1)], 'a')
    append(tmp_path, 'client1', [resource(2)], 'b')
    monkeypatch.setattr(module, 'MAX_SCAN_ROWS', 1)
    reader = MonitorSeries(tmp_path)
    page = query(reader)
    assert [point['step'] for point in page['points']] == [0]
    assert page['has_more'] is True
    next_page = query(reader, cursor=page['next_cursor'])
    assert [point['step'] for point in next_page['points']] == [1]
    assert next_page['has_more'] is False


def test_truncated_log_requires_a_new_cursor_instead_of_silently_replaying(tmp_path):
    path = append(tmp_path, 'client1', [resource(1), resource(2)])
    reader = MonitorSeries(tmp_path)
    cursor = query(reader)['next_cursor']
    path.write_text('')
    with pytest.raises(ValueError, match='截断'):
        query(reader, cursor=cursor)


def test_segment_count_and_directory_discovery_are_bounded(tmp_path, monkeypatch):
    import dgfl.experiments.monitor_series as module
    append(tmp_path, 'client1', [resource(1)], 'a')
    append(tmp_path, 'client1', [resource(2)], 'b')
    monkeypatch.setattr(module, 'MAX_FILES', 1)
    with pytest.raises(ValueError, match='分段'):
        query(MonitorSeries(tmp_path))
    monkeypatch.setattr(module, 'MAX_FILES', 128)
    monkeypatch.setattr(module, 'MAX_DIRECTORY_ENTRIES', 1)
    with pytest.raises(ValueError, match='目录'):
        query(MonitorSeries(tmp_path))


def test_legacy_local_retained_samples_are_paginated_with_stable_ids(tmp_path):
    old = record()
    old['evidence']['resources'] = {'hardware': {'samples': [
        {'sample_index': i, 'time': f'2026-10-13T01:00:{i:02d}Z',
         'cpu': {'system_utilization_percent': 25 + i}} for i in (0, 4, 8)]}}
    reader = MonitorSeries(tmp_path)
    params = {'scope': 'machine', 'target': 'local', 'metric': 'cpu.system_utilization_percent'}
    first = reader.query(old, **params, limit=2)
    assert first['retention'] == 'adaptive' and first['source'] == 'retained_samples'
    assert [point['step'] for point in first['points']] == [0, 4]
    second = reader.query(old, **params, cursor=first['next_cursor'])
    assert [point['step'] for point in second['points']] == [8]
    assert second['has_more'] is False


def test_retained_local_history_transitions_to_journal_without_repeating_stable_ids(tmp_path):
    historical = record()
    historical['evidence']['resources'] = {'hardware': {'samples': [
        {'sample_index': i, 'time': f'2026-10-13T01:00:{i:02d}Z',
         'cpu': {'system_utilization_percent': 25 + i}} for i in (0, 1)]}}
    reader = MonitorSeries(tmp_path)
    params = {'scope': 'machine', 'target': 'local', 'metric': 'cpu.system_utilization_percent'}
    retained = reader.query(historical, **params)
    append(tmp_path, 'coordinator', [resource(i + 1, i, machine=True, value=25 + i) for i in range(3)])
    journal = reader.query(historical, **params, cursor=retained['next_cursor'])
    replay = reader.query(historical, **params)
    assert journal['source'] == 'journal' and journal['retention'] == 'full'
    assert [point['step'] for point in journal['points']] == [2]
    assert [point['id'] for point in replay['points'][:2]] == [point['id'] for point in retained['points']]
    assert len({point['id'] for point in retained['points'] + journal['points']}) == 3
    assert all(point['source_node'] == 'coordinator' for point in replay['points'])


def test_local_observation_is_persisted_once_and_is_available_as_machine_history(tmp_path):
    class Logs:
        def write_machine_sample(self, *args):
            pass
    monitor = RunNodeMonitor(tmp_path, RUN, [], Logs())
    sample = {'sample_index': 0, 'time': '2026-10-13T01:00:00Z',
              'cpu': {'system_utilization_percent': 42}, 'sample_duration_ms': 1.0}
    monitor.observe_local(sample)
    monitor.observe_local(sample)
    monitor.finish()
    files = list((tmp_path / 'monitoring' / RUN).glob('coordinator.*.jsonl'))
    assert len(files) == 1 and len(files[0].read_text().splitlines()) == 1
    page = MonitorSeries(tmp_path).query(record(), scope='machine', target='local',
                                        metric='cpu.system_utilization_percent')
    assert page['source'] == 'journal' and page['points'][0]['value'] == 42


def test_slow_local_journal_does_not_hold_snapshot_lock_or_observation_caller(tmp_path, monkeypatch):
    class Logs:
        def write_machine_sample(self, *args):
            pass
    monitor = RunNodeMonitor(tmp_path, RUN, [], Logs())
    entered, release = threading.Event(), threading.Event()
    def slow_write(*args):
        entered.set()
        assert release.wait(5)
    monkeypatch.setattr(monitor, '_append', slow_write)
    sample = {'sample_index': 0, 'time': '2026-10-13T01:00:00Z',
              'cpu': {'system_utilization_percent': 42}}
    try:
        # This direct business-thread call must return while the writer is blocked.
        monitor.observe_local(sample)
        assert entered.wait(1)
        with ThreadPoolExecutor(max_workers=1) as pool:
            snapshot = pool.submit(monitor.snapshot).result(timeout=.5)
        assert snapshot['machines'][0]['latest']['sample_index'] == 0
        summary = monitor.finish()['summary']
        assert summary['local_journal_pending'] == 1 and summary['cleanup_complete'] is False
    finally:
        release.set()
        monitor.finish()


def test_full_local_journal_queue_preserves_latest_resource_snapshot_and_reports_drops(tmp_path, monkeypatch):
    class Logs:
        def write_machine_sample(self, *args):
            pass
    monitor = RunNodeMonitor(tmp_path, RUN, [], Logs())
    entered, release = threading.Event(), threading.Event()
    persisted = []
    def slow_write(_source, event):
        entered.set()
        assert release.wait(5)
        persisted.append(event['payload']['sample_index'])
    monkeypatch.setattr(monitor, '_append', slow_write)
    def sample(index):
        return {'sample_index': index, 'time': '2026-10-13T01:00:00Z',
                'cpu': {'system_utilization_percent': index}}
    try:
        monitor.observe_local(sample(0))
        assert entered.wait(1)
        for index in range(1, 35):
            monitor.observe_local(sample(index))
        snapshot = monitor.snapshot()
        assert snapshot['machines'][0]['latest']['sample_index'] == 34
        assert snapshot['summary']['log_failures'] == 2
        assert '队列已满' in snapshot['summary']['last_error']
        with monitor._lock:
            assert len(monitor._local_queue) == 32
            assert len(monitor._local_pending) == 33
        release.set()
        assert monitor.finish()['summary']['local_journal_pending'] == 0
        assert persisted == list(range(33))
        monitor.observe_local(sample(34))
        assert monitor.finish()['summary']['cleanup_complete'] is True
        assert persisted == [*range(33), 34], 'a previously dropped sample can be retried without duplicating persisted samples'
    finally:
        release.set()
        monitor.finish()


def test_local_journal_failure_is_reported_and_can_retry_without_changing_resources(tmp_path, monkeypatch):
    class Logs:
        def write_machine_sample(self, *args):
            pass
    monitor = RunNodeMonitor(tmp_path, RUN, [], Logs())
    original = monitor._append
    def fail_write(*args):
        raise OSError('private disk location')
    monkeypatch.setattr(monitor, '_append', fail_write)
    sample = {'sample_index': 0, 'time': '2026-10-13T01:00:00Z',
              'cpu': {'system_utilization_percent': 42}}
    monitor.observe_local(sample)
    failed = monitor.finish()
    assert failed['summary']['log_failures'] == 1
    assert 'private disk location' not in failed['summary']['last_error']
    assert failed['machines'][0]['latest'] == sample
    monkeypatch.setattr(monitor, '_append', original)
    monitor.observe_local(sample)
    assert monitor.finish()['summary']['cleanup_complete'] is True
    page = MonitorSeries(tmp_path).query(record(), scope='machine', target='local',
                                        metric='cpu.system_utilization_percent')
    assert len(page['points']) == 1 and page['points'][0]['value'] == 42


def test_training_event_does_not_refresh_resource_sample_timestamp(tmp_path):
    class Logs:
        def write_node_event(self, *args):
            return {'available': True}
    node = record()['evidence']['node_snapshot'][0]
    monitor = RunNodeMonitor(tmp_path, RUN, [node], Logs(), local_epochs=2)
    monitor._accept(node, {'node_id': 'client1', 'task_id': RUN, 'active': True,
                           'events': [resource(1), epoch(2, 1)]})
    row = monitor.snapshot()['nodes'][0]
    assert row['last_seen'] == '2026-10-13T01:01:00+00:00'
    assert row['resource_time'] == '2026-10-13T01:00:00+00:00'


def test_missing_history_is_explicit_and_does_not_create_files(tmp_path):
    result = query(MonitorSeries(tmp_path))
    assert result['points'] == [] and result['source'] == 'none' and result['retention'] == 'unavailable'
    assert not (tmp_path / 'monitoring').exists()


@pytest.mark.parametrize('target', ['../outside', 'unknown', 'CON'])
def test_target_and_path_validation_rejects_outside_experiment(tmp_path, target):
    with pytest.raises(ValueError):
        MonitorSeries(tmp_path).query(record(), scope='machine', target=target, metric='system.memory_percent')


def test_cursor_tampering_and_metric_changes_are_rejected(tmp_path):
    reader = MonitorSeries(tmp_path)
    page = query(reader)
    with pytest.raises(ValueError, match='游标'):
        query(reader, cursor=page['next_cursor'][:-1] + 'x')
    with pytest.raises(ValueError, match='参数'):
        reader.query(record(), scope='node', target='client1', metric='processes.rss_bytes',
                     cursor=page['next_cursor'])


def test_api_validation_missing_run_and_no_new_role_queries(tmp_path, monkeypatch):
    app = create_control_app(tmp_path, auto_prepare_compute=False)
    app.state.manager.records[RUN] = record()
    append(tmp_path, 'client1', [resource(1)])
    def forbidden(*args, **kwargs):
        raise AssertionError('history read must not query roles or sensors')
    monkeypatch.setattr('dgfl.transport.client.RPCClient.call', forbidden)
    with TestClient(app) as client:
        url = f'/api/runs/{RUN}/monitor/series'
        params = {'scope': 'node', 'target': 'client1', 'metric': 'processes.cpu_percent'}
        response = client.get(url, params=params)
        assert response.status_code == 200 and response.json()['points'][0]['value'] == 25
        for patch in ({'limit': 0}, {'limit': 601}, {'scope': 'all'}, {'target': '../x'},
                      {'metric': 'secret'}, {'start': 'not-a-time'}, {'cursor': 'invalid'}):
            assert client.get(url, params={**params, **patch}).status_code == 422
        assert client.get('/api/runs/missing/monitor/series', params=params).status_code == 404


def test_symlink_journal_is_rejected(tmp_path):
    outside = tmp_path / 'outside.jsonl'
    outside.write_text('{}\n')
    directory = tmp_path / 'monitoring' / RUN
    directory.mkdir(parents=True)
    try:
        (directory / 'client1.a.jsonl').symlink_to(outside)
    except OSError:
        pytest.skip('symlink permission unavailable')
    with pytest.raises(ValueError, match='符号链接'):
        query(MonitorSeries(tmp_path))
