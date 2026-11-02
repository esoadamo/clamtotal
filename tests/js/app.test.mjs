import test from 'node:test';
import assert from 'node:assert/strict';
import '../../app/static/app.js';

const CT = globalThis.ClamTotal;

test('sha256HexPure matches known vectors', () => {
  assert.equal(
    CT.sha256HexPure(new TextEncoder().encode('')),
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
  );
  assert.equal(
    CT.sha256HexPure(new TextEncoder().encode('abc')),
    'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
  );
  const long = new TextEncoder().encode('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq');
  assert.equal(
    CT.sha256HexPure(long),
    '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1'
  );
});

test('sha256Hex works (subtle in node, pure fallback otherwise)', async () => {
  const buf = new TextEncoder().encode('hello clamtotal').buffer;
  const viaApi = await CT.sha256Hex(buf);
  const viaPure = CT.sha256HexPure(new Uint8Array(buf));
  assert.equal(viaApi, viaPure);
  assert.match(viaApi, /^[0-9a-f]{64}$/);
});

test('defang neutralizes urls, domains and ips', () => {
  assert.equal(CT.defang('https://evil-example.com/x'), 'hxxps://evil-example[.]com/x');
  assert.equal(CT.defang('http://185.220.101.4/a'), 'hxxp://185[.]220[.]101[.]4/a');
  assert.equal(CT.defang('plain text'), 'plain text');
});

test('modal open/close with a minimal DOM stub', () => {
  const overlay = { classList: { add(c) { this._c = c; }, remove(c) { this._c = null; } } };
  const title = { textContent: '' };
  const body = { innerHTML: '' };
  globalThis.document = {
    getElementById: (id) => ({ 'modal-overlay': overlay, 'modal-title': title, 'modal-body': body }[id] || null),
  };
  CT.openModal('Upload file?', '<b>x</b>');
  assert.equal(overlay.classList._c, 'open');
  assert.equal(title.textContent, 'Upload file?');
  assert.equal(body.innerHTML, '<b>x</b>');
  CT.closeModal();
  assert.equal(overlay.classList._c, null);
  delete globalThis.document;
});

test('modal functions are safe without a document', () => {
  delete globalThis.document;
  assert.doesNotThrow(() => CT.openModal('t', 'b'));
  assert.doesNotThrow(() => CT.closeModal());
  assert.doesNotThrow(() => CT.initTabs());
  assert.doesNotThrow(() => CT.initPolling());
  assert.doesNotThrow(() => CT.initUpload());
});

test('initPolling polls and reloads when done', async () => {
  let calls = 0;
  let reloaded = false;
  let cleared = false;
  const el = { dataset: { sha: 'ab'.repeat(32), interval: '5' } };
  globalThis.document = { getElementById: (id) => (id === 'pending-data' ? el : null) };
  globalThis.fetch = async () => {
    calls += 1;
    return { json: async () => ({ status: calls >= 2 ? 'done' : 'pending' }) };
  };
  let intervalId = null;
  globalThis.setInterval = (fn, ms) => { intervalId = { fn, ms }; return 1; };
  globalThis.clearInterval = () => { cleared = true; };
  Object.defineProperty(globalThis, 'location', { value: { reload: () => { reloaded = true; } }, configurable: true });

  CT.initPolling();
  assert.equal(intervalId.ms, 5);
  await intervalId.fn();
  assert.equal(calls, 1);
  assert.equal(reloaded, false);
  await intervalId.fn();
  assert.equal(calls, 2);
  assert.equal(cleared, true);
  assert.equal(reloaded, true);

  delete globalThis.document;
  delete globalThis.fetch;
  delete globalThis.setInterval;
  delete globalThis.clearInterval;
  delete globalThis.location;
});

test('initTabs wires tab clicks with a DOM stub', () => {
  const makeEl = (id) => ({
    id,
    dataset: {},
    listeners: {},
    classList: {
      _set: new Set(),
      toggle(c, on) { on ? this._set.add(c) : this._set.delete(c); },
    },
    addEventListener(ev, fn) { this.listeners[ev] = fn; },
  });
  const tabA = makeEl('tab-a'); tabA.dataset.tab = 'detection';
  const tabB = makeEl('tab-b'); tabB.dataset.tab = 'details';
  const panelA = makeEl('tab-detection');
  const panelB = makeEl('tab-details');
  globalThis.document = {
    querySelectorAll: (sel) => (sel === '.tab' ? [tabA, tabB] : [panelA, panelB]),
  };
  CT.initTabs();
  tabB.listeners.click();
  assert.ok(tabB.classList._set.has('active'));
  assert.ok(!tabA.classList._set.has('active'));
  assert.ok(panelB.classList._set.has('active'));
  assert.ok(!panelA.classList._set.has('active'));
  delete globalThis.document;
});

test('hashFileWithProgress reports progress and returns the right hash', async () => {
  const data = new TextEncoder().encode('x'.repeat(9 * 1024 * 1024)); // > 2 chunks of 4MB
  const file = {
    size: data.length,
    slice: (a, b) => ({ size: b - a, _buf: data.slice(a, b) }),
  };
  globalThis.FileReader = class {
    readAsArrayBuffer(slice) {
      this.result = slice._buf.buffer.slice(slice._buf.byteOffset, slice._buf.byteOffset + slice._buf.length);
      queueMicrotask(() => this.onload());
    }
  };
  const pcts = [];
  const hash = await CT.hashFileWithProgress(file, (p) => pcts.push(p));
  assert.match(hash, /^[0-9a-f]{64}$/);
  assert.equal(hash, CT.sha256HexPure(data));
  assert.ok(pcts.length >= 2, 'multiple progress callbacks');
  assert.equal(pcts[pcts.length - 1], 100);
  assert.ok(pcts.every((p, i, arr) => i === 0 || p >= arr[i - 1]), 'monotonic');
  delete globalThis.FileReader;
});

test('hashFileWithProgress handles empty file', async () => {
  const file = { size: 0, slice: () => { throw new Error('no slice'); } };
  const hash = await CT.hashFileWithProgress(file, () => {});
  assert.equal(hash, 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
});

test('onFileSelected shows hashing modal first (DOM contract)', () => {
  const ids = ['modal-overlay', 'modal-title', 'modal-body'];
  const els = {};
  ids.forEach((id) => {
    els[id] = {
      classList: { _open: false, add(c) { this._open = c === 'open'; }, remove() { this._open = false; } },
      textContent: '',
      innerHTML: '',
    };
  });
  globalThis.document = { getElementById: (id) => els[id] || null, querySelectorAll: () => [] };
  CT.openModal('Hashing a.bin…', '<div class="spinner"></div>');
  assert.equal(els['modal-overlay'].classList._open, true);
  assert.match(els['modal-title'].textContent, /Hashing/);
  assert.match(els['modal-body'].innerHTML, /spinner/);
  delete globalThis.document;
});
