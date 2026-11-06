const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const source = fs.readFileSync(path.join(__dirname, '../browser-extension/bridge.js'), 'utf8');

function bridge(sendMessage) {
    let onMessage;
    const replies = [];
    const window = {
        addEventListener(type, listener) { onMessage = listener; },
        postMessage(message) { replies.push(message); },
    };
    vm.runInNewContext(source, {window, chrome: {runtime: {sendMessage}}});
    return {
        replies,
        request(id, op = 'create') {
            onMessage({source: window, data: {linuxPasskey: 'request', id, op}});
        },
    };
}

const flush = () => new Promise(resolve => setImmediate(resolve));

test('successful native replies preserve the page request ID', async () => {
    const result = {type: 'public-key'};
    const page = bridge(() => Promise.resolve({id: 7, result}));
    page.request(1);
    await flush();
    assert.equal(page.replies[0].id, 1);
    assert.equal(page.replies[0].linuxPasskey, 'reply');
    assert.equal(page.replies[0].result, result);
});

test('native errors preserve the page request ID', async () => {
    const error = {name: 'NotAllowedError', message: 'Cancelled'};
    const page = bridge(() => Promise.resolve({id: 8, error}));
    page.request(2);
    await flush();
    assert.equal(page.replies[0].id, 2);
    assert.equal(page.replies[0].error, error);
});

test('out-of-order native replies keep their corresponding page IDs', async () => {
    const pending = [];
    const page = bridge(() => new Promise(resolve => pending.push(resolve)));
    page.request(1);
    page.request(2, 'get');
    pending[1]({id: 10, result: 'second'});
    pending[0]({id: 9, result: 'first'});
    await flush();
    assert.equal(page.replies[0].id, 2);
    assert.equal(page.replies[0].result, 'second');
    assert.equal(page.replies[1].id, 1);
    assert.equal(page.replies[1].result, 'first');
});
