"""Chinese UI adaptation is bounded, same-origin, and never rewrites data."""
import asyncio
import shutil
import subprocess
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from dgfl.services.tensorboard import _HTML_LIMIT, EmbeddedTensorBoard, _localized_html


def adapt(body, *, path='/tensorboard/', method='GET', content_type=b'text/html; charset=utf-8',
          status=200, extra_headers=(), split=None):
    messages = []

    async def app(scope, receive, send):
        await send({'type': 'http.response.start', 'status': status,
                    'headers': [(b'content-type', content_type), (b'content-length', str(len(body)).encode()),
                                (b'etag', b'original'), *extra_headers]})
        if split:
            await send({'type': 'http.response.body', 'body': body[:split], 'more_body': True})
            await send({'type': 'http.response.body', 'body': body[split:], 'more_body': False})
        else:
            await send({'type': 'http.response.body', 'body': body, 'more_body': False})

    async def receive():
        return {'type': 'http.request', 'body': b''}

    async def send(message):
        messages.append(message)

    asyncio.run(_localized_html(app, {'type': 'http', 'path': path, 'method': method}, receive, send))
    return messages[0], b''.join(message.get('body', b'') for message in messages[1:]), messages


@pytest.mark.parametrize('path', ['/tensorboard/', '/tensorboard/index.html'])
def test_homepage_injects_only_local_resources_and_preserves_native_html(path):
    html = b'<html><head><script src="index.js"></script></head><body>native</body></html>'
    start, body, _ = adapt(html, path=path, split=21)
    assert body.count(b'data-dgflow-locale="zh-CN"') == 2
    assert b'/tensorboard/dgflow-i18n/zh-CN.js' in body
    assert b'/tensorboard/dgflow-i18n/zh-CN.css' in body
    assert b'<script src="index.js"></script>' in body and b'<body>native</body>' in body
    assert b'https://' not in body
    assert dict(start['headers'])[b'content-length'] == str(len(body)).encode()
    assert b'etag' not in dict(start['headers'])
    assert adapt(body)[1] == body  # Idempotent injection.


@pytest.mark.parametrize('options', [
    {'path': '/tensorboard/data/plugin/timeseries/tags'},
    {'path': '/tensorboard/index.js'}, {'method': 'HEAD'}, {'method': 'POST'},
    {'content_type': b'application/json'}, {'status': 503},
    {'extra_headers': [(b'content-encoding', b'gzip')]},
])
def test_non_homepage_native_responses_are_byte_for_byte_unchanged(options):
    html = b'<head></head><body>{"run":"Settings","tag":"evaluation/accuracy"}</body>'
    start, body, _ = adapt(html, **options)
    assert body == html
    assert dict(start['headers'])[b'etag'] == b'original'


def test_oversized_stream_is_forwarded_without_injection_or_retaining_complete_body():
    html = b'<head></head><body>' + b'x' * _HTML_LIMIT + b'</body>'
    start, body, messages = adapt(html, split=_HTML_LIMIT + 1)
    assert body == html and dict(start['headers'])[b'etag'] == b'original'
    assert len(messages) == 3 and messages[-1]['more_body'] is False


def test_fixed_locale_assets_work_without_initializing_tensorboard():
    service = EmbeddedTensorBoard(None)
    service._prepare = lambda: pytest.fail('Static assets must not initialize TB or read event files')
    app = FastAPI()
    app.mount('/tensorboard', service)
    with TestClient(app) as http:
        for name, content_type in [('zh-CN.js', 'javascript'), ('zh-CN.css', 'css')]:
            response = http.get('/tensorboard/dgflow-i18n/' + name)
            assert response.status_code == 200
            assert content_type in response.headers['content-type']
            assert response.headers['x-content-type-options'] == 'nosniff'
            assert len(response.content) > 100
            head = http.head('/tensorboard/dgflow-i18n/' + name)
            assert head.content == b'' and head.headers['content-length'] == response.headers['content-length']
        labels = http.get('/tensorboard/dgflow-i18n/labels.json').json()
        assert labels['fields']['accuracy']['label'] == '准确率'
        assert labels['groups']['evaluation'] == '全局测试集'
        # The console adapter reads the run list from this catalog. With no logs
        # object it must degrade to an empty list, not fail the endpoint.
        assert labels['runs'] == []
        assert http.get('/tensorboard/dgflow-i18n/not-a-file.js').status_code == 404
        assert http.get('/tensorboard/dgflow-i18n/assets/zh-CN.js').status_code == 404
        assert http.post('/tensorboard/dgflow-i18n/zh-CN.js').status_code == 405


def test_run_catalog_lists_exactly_the_native_run_directories(tmp_path):
    """The dropdown's options come from the server, not from rendered markup.

    `runtime/tensorboard/<run_id>` is the native run name, so listing those
    directories yields the same set the native Runs selector shows.
    """
    from dgfl.experiments.tensorboard import TensorBoardLogs
    logs = TensorBoardLogs(tmp_path)
    (logs.logdir / 'run-bbb').mkdir(parents=True)
    (logs.logdir / 'run-aaa').mkdir()
    (logs.logdir / 'loose.txt').write_text('x', encoding='utf8')
    service = EmbeddedTensorBoard(logs)
    app = FastAPI()
    app.mount('/tensorboard', service)
    with TestClient(app) as http:
        runs = http.get('/tensorboard/dgflow-i18n/labels.json').json()['runs']
    # Only directories are run names, and the order is stable for the dropdown.
    assert runs == ['run-aaa', 'run-bbb']


def test_ui_translation_dictionary_protects_user_data_and_keeps_native_preferences():
    node = shutil.which('node')
    if node is None:
        pytest.skip('Node.js is required to execute the packaged browser adapter')
    script = Path(__file__).resolve().parents[2] / 'src/dgfl/services/assets/zh-CN.js'
    program = r"""
const assert = require('node:assert/strict');
const ui = require(process.argv[2]);
const catalog = {fields: {accuracy: {label:'准确率',unit:'比例 0–1'},
  combine_cpu_s:{label:'合并 CPU 时间',unit:'CPU 秒'}},
  groups: {evaluation:'全局测试集',protocol:'协议',stages:'阶段耗时',combine:'聚合合并'},kernels:[]};
assert.equal(ui.translate('  Settings\n'), '  设置\n');
assert.equal(ui.translate('Filter runs (regex)'), '筛选实验（正则表达式）');
assert.equal(ui.translate('user Settings experiment'), 'user Settings experiment');
assert.equal(ui.translate('evaluation/accuracy'), 'evaluation/accuracy');
assert.equal(ui.translate('0.725'), '0.725');
assert.equal(ui.translate('31 cards'), '31 个图表');
assert.equal(ui.translate('Link by step 5'), '按步数关联 5');
assert.equal(ui.translate('Nearest Pixel'), '最近像素');
const protectedRow = {closest(selector) {return selector.includes('tb-data-table-content-row') ? {} : null;}};
const title = {closest(selector) {return selector.includes('tb-truncated-path') ? {} : null;}};
const button = {closest(selector) {return selector.includes('settings-dialog-component') ? {} : null;}};
assert.equal(ui.eligible(protectedRow), false);
assert.equal(ui.eligible(title), false);
assert.equal(ui.eligible(button), true);
const panel={id:'native-axis-panel'};
const option={closest(selector){return selector==='[role="listbox"]'?panel:null;}};
const axisOption={ownerDocument:{querySelectorAll(){return [{getAttribute(){return panel.id;}}];}},
 closest(selector){return selector.includes('mat-option')?option:null;}};
const runOption={...axisOption,ownerDocument:{querySelectorAll(){return [];}}};
assert.equal(ui.eligible(axisOption),true); // Linked native settings overlay.
assert.equal(ui.eligible(runOption),false); // A download run may be named Step.
assert.deepEqual(ui.metricLabel('evaluation/accuracy', catalog),
 {prefix:'全局测试集',suffix:' / 准确率（比例 0–1）'});
assert.equal(ui.metricLabel('user/accuracy', catalog), null);
assert.equal(ui.metricLabel('evaluation/custom_tag', catalog), null);
assert.equal(ui.metricLabel('evaluation/../../../accuracy', catalog), null);
assert.ok(ui.metricLabel('combine/combine_cpu_s_max',catalog).suffix.includes('各边缘进程最大值'));
assert.equal(ui.groupLabel('protocol/stages',catalog),'协议 / 阶段耗时');
assert.equal(ui.groupLabel('user/stages',catalog),null);
// Exercise batching, duplicate startup, shutdown, and bfcache restart without
// requiring browser-only packages or touching a real native preference object.
let observed=0, disconnected=0, scheduled=0, cancelled=0;
const listeners={}, callbacks=new Map();
const html={nodeType:1,isConnected:true,lang:'',closest(){return null;},
 matches(){return false;},querySelectorAll(){return []}};
const document={documentElement:html,createTreeWalker(){return {nextNode(){return null;}}}};
const window={MutationObserver:class {constructor(callback){this.callback=callback;}
 observe(){observed++;}disconnect(){disconnected++;}},
 requestAnimationFrame(callback){callbacks.set(++scheduled,callback);return scheduled;},
 cancelAnimationFrame(id){callbacks.delete(id);cancelled++;},
 addEventListener(name,callback){listeners[name]=callback;},
 localStorage:{getItem(){throw Error('adapter must not access native preferences');},
 setItem(){throw Error('adapter must not change native preferences');}}};
const controller=ui.start(document,window);
assert.equal(html.lang,'zh-CN');assert.equal(scheduled,1);
assert.equal(ui.start(document,window),controller);
callbacks.get(1)();assert.equal(observed,2);assert.equal(disconnected,1);
listeners.pagehide();assert.equal(disconnected,2);
listeners.pageshow();assert.equal(scheduled,2);
controller.close();assert.equal(cancelled,1);
"""
    result = subprocess.run([node, '-', str(script)], input=program, capture_output=True,
                            text=True, encoding='utf8', timeout=15)
    assert result.returncode == 0, result.stdout + result.stderr


def test_evaluation_legend_distinguishes_training_and_test_without_changing_native_labels():
    node = shutil.which('node')
    if node is None:
        pytest.skip('Node.js is required to execute the packaged browser adapter')
    script = Path(__file__).resolve().parents[2] / 'src/dgfl/services/assets/zh-CN.js'
    program = r"""
const assert = require('node:assert/strict');
const ui = require(process.argv[2]);
let note=null, inserted=0;
const grid={id:'native-grid'};
const container={querySelector(selector){
  assert.equal(selector,':scope > .dgflow-evaluation-legend');return note;
},insertBefore(element,next){
  assert.equal(next,grid);note=element;inserted++;
}};
const toolbar={parentElement:container,nextSibling:grid};
const group={getAttribute(name){assert.equal(name,'title');return 'evaluation';},
 closest(selector){return selector==='.card-group'?container:toolbar;}};
const document={createElement(tag){assert.equal(tag,'p');return {};}};
ui.evaluationLegend(group,document);
assert.equal(note.className,'dgflow-evaluation-legend');
assert.ok(note.textContent.includes('实验根记录 = 聚合模型·全局测试集'));
assert.ok(note.textContent.includes('nodes/clientN（有记录时）= 客户端·本地训练集'));
assert.ok(note.textContent.includes('每轮最后一个 epoch'));
assert.ok(note.textContent.includes('横轴均为全局轮次'));
assert.ok(note.textContent.includes('两者使用不同评估集'));
// Refreshing or adding native curves must not duplicate the explanation.
ui.evaluationLegend(group,document);
assert.equal(inserted,1);
assert.equal(group.getAttribute('title'),'evaluation');
// No other groups or native run names are touched.
ui.evaluationLegend({getAttribute(){return 'training';},
 closest(){throw Error('other groups must be unchanged');}},document);
assert.equal(inserted,1);
// A detached/native alternate layout stays untouched rather than being forced.
ui.evaluationLegend({getAttribute(){return 'evaluation';},closest(){return null;}},document);
assert.equal(inserted,1);
"""
    result = subprocess.run([node, '-', str(script)], input=program, capture_output=True,
                            text=True, encoding='utf8', timeout=15)
    assert result.returncode == 0, result.stdout + result.stderr


def test_run_filter_regex_box_is_replaced_by_a_run_dropdown_that_drives_native_state():
    """The dropdown must speak TensorBoard's own keyup contract, not a private hook.

    TensorBoard 2.21 reads that box on `keyup`: onFilterKeyUp -> emit ->
    dispatch(IE({regexString})). The replacement therefore has to set the native
    input's value and dispatch a bubbling keyup, which is what this pins. Run
    names come from the server catalog, not from scraping rendered cells.
    """
    node = shutil.which('node')
    if node is None:
        pytest.skip('Node.js is required to execute the packaged browser adapter')
    script = Path(__file__).resolve().parents[2] / 'src/dgfl/services/assets/zh-CN.js'
    program = r"""
const assert = require('node:assert/strict');
const ui = require(process.argv[2]);

function element(tag, text) {
  const node = {tagName: tag, textContent: text || '', children: [], attributes: {}, style: {},
    className: '', value: '', listeners: {}, dispatched: [], parentNode: null,
    setAttribute(name, value) { this.attributes[name] = String(value); },
    getAttribute(name) { return name in this.attributes ? this.attributes[name] : null; },
    addEventListener(name, callback) { (this.listeners[name] = this.listeners[name] || []).push(callback); },
    dispatchEvent(event) { this.dispatched.push(event.type);
      for (const callback of this.listeners[event.type] || []) callback(event); return true; },
    appendChild(child) { child.parentNode = this; this.children.push(child); return child; },
    removeChild(child) {
      const index = this.children.indexOf(child);
      if (index >= 0) this.children.splice(index, 1);
      return child;
    },
    insertBefore(child, next) {
      child.parentNode = this;
      const index = this.children.indexOf(next);
      if (index < 0) this.children.push(child); else this.children.splice(index, 0, child);
      return child;
    }};
  return node;
}

// Two runs, one of them containing the other's name as a substring, plus a name
// with regex metacharacters that must still match literally.
const runs = ['887e7f260038415f8e2081c3c5957ec6',
              '887e7f260038415f8e2081c3c5957ec6/nodes/client1',
              'run (seed 42)+x'];
const input = element('input');
input.placeholder = 'Filter runs (regex)';
input.value = '^887e7f';
const host = element('tb-filter-input');
host.className = 'run-filter';
host.appendChild(input);
host.querySelector = selector => (selector === 'input' ? input : null);
// The tag filter shares the same component tag and must stay untouched.
const tagHost = element('tb-filter-input');
tagHost.className = 'tag-filter';
const tagInput = element('input');
tagHost.appendChild(tagInput);
tagHost.querySelector = selector => (selector === 'input' ? tagInput : null);

const document = {
  querySelector(selector) { return selector === 'tb-filter-input.run-filter' ? host : null; },
  createElement(tag) { return element(tag); },
};
const window = { Event: class { constructor(type, init) { this.type = type; Object.assign(this, init || {}); } } };

const dropdown = ui.runFilterDropdown(document, window);
// The control is replaced immediately; the run list fills in when the catalog
// arrives. Before that it still offers the reset option and the live filter.
assert.equal(dropdown.apply(), true);
assert.equal(dropdown.applied(), true);
assert.equal(dropdown.names().length, 0);
assert.equal(input.style.display, 'none');
assert.equal(host.children.length, 2);

assert.equal(dropdown.setRuns(runs), true);
assert.equal(dropdown.names().length, 3);
// The native input is hidden but preserved: nothing native is destroyed.
assert.equal(input.getAttribute('aria-hidden'), 'true');
assert.equal(input.getAttribute('tabindex'), '-1');
assert.equal(tagInput.style.display, undefined);
const select = host.children[1];
assert.equal(select.tagName, 'select');
// "all" + three runs + the pending expression, which stays reachable.
assert.equal(select.children.length, 5, JSON.stringify(select.children.map(c => c.value)));
assert.equal(select.children[0].value, '');
assert.equal(select.children[1].textContent, runs[0]);
// Each option is anchored, so one run's name cannot also match another.
assert.equal(select.children[1].value, '^' + runs[0] + '$');
assert.equal(select.children[2].value, '^887e7f260038415f8e2081c3c5957ec6/nodes/client1$');
// Metacharacters in a run name are escaped, not treated as a pattern.
assert.equal(select.children[3].value, '^run \\(seed 42\\)\\+x$');
assert.equal(select.children[4].value, '^887e7f');

// Choosing a run drives the native input through its own keyup contract.
select.value = select.children[2].value;
select.dispatchEvent(new window.Event('change'));
assert.equal(input.value, select.children[2].value);
assert.deepEqual(input.dispatched, ['keyup']);

// Clearing the dropdown restores the unfiltered view.
select.value = '';
select.dispatchEvent(new window.Event('change'));
assert.equal(input.value, '');
assert.deepEqual(input.dispatched, ['keyup', 'keyup']);

// The catalog is authoritative, so a different set replaces the options.
assert.equal(dropdown.setRuns(['887e7f260038415f8e2081c3c5957ec6']), true);
assert.equal(dropdown.names().length, 1);
// Re-sending the same set is a no-op, so catalog polling cannot thrash.
assert.equal(dropdown.setRuns(['887e7f260038415f8e2081c3c5957ec6']), false);
// Newly finished runs are picked up.
assert.equal(dropdown.setRuns(runs.concat(['new-run'])), true);
assert.equal(dropdown.names().length, 4);
// A missing or malformed catalog is ignored rather than fatal.
assert.equal(dropdown.setRuns(undefined), false);
assert.equal(dropdown.setRuns('nope'), false);

// A second apply is a no-op, so re-renders cannot stack duplicate selects.
assert.equal(dropdown.apply(), true);
assert.equal(host.children.length, 2);

// Without the native control present, nothing is replaced or fabricated.
const empty = ui.runFilterDropdown({querySelector() { return null; }}, window);
assert.equal(empty.setRuns(runs), true);
assert.equal(empty.apply(), false);

// A minimal document (no querySelector at all) must not throw.
const minimal = ui.runFilterDropdown({}, window);
assert.equal(minimal.flush(), false);
"""
    result = subprocess.run([node, '-', str(script)], input=program, capture_output=True,
                            text=True, encoding='utf8', timeout=15)
    assert result.returncode == 0, result.stdout + result.stderr
