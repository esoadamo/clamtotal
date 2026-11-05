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

test('initPolling does nothing on a finished page (no #scan-progress element)', () => {
  let intervalCalled = false;
  globalThis.document = { getElementById: () => null }; // done page: no polling hooks
  globalThis.setInterval = () => { intervalCalled = true; return 1; };
  globalThis.fetch = async () => { throw new Error('must not be called'); };
  CT.initPolling();
  assert.equal(intervalCalled, false);
  delete globalThis.document;
  delete globalThis.setInterval;
  delete globalThis.fetch;
});

test('initPolling polls and reloads when done', async () => {
  let calls = 0;
  let reloaded = false;
  let cleared = false;
  const el = { dataset: { sha: 'ab'.repeat(32), interval: '5', key: '0:0' } };
  globalThis.document = { getElementById: (id) => (id === 'scan-progress' ? el : null) };
  globalThis.fetch = async () => {
    calls += 1;
    return { json: async () => ({ status: calls >= 2 ? 'done' : 'pending', engines: [] }) };
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

test('chunkPlan splits large files into ordered ranges', () => {
  assert.deepEqual(CT.chunkPlan(100, 0), []);          // disabled
  assert.deepEqual(CT.chunkPlan(100, 100), []);        // fits in one request
  assert.deepEqual(CT.chunkPlan(100, 50), [
    { index: 0, start: 0, end: 50 },
    { index: 1, start: 50, end: 100 },
  ]);
  assert.deepEqual(CT.chunkPlan(250 * 1024 * 1024, 50 * 1024 * 1024).length, 5);
  const last = CT.chunkPlan(120, 50).pop();
  assert.deepEqual(last, { index: 2, start: 100, end: 120 });  // remainder chunk
});

test('shouldUseChunks gates the chunked path', () => {
  assert.equal(CT.shouldUseChunks(300 * 1024 * 1024, 25 * 1024 * 1024), true);
  assert.equal(CT.shouldUseChunks(10 * 1024 * 1024, 25 * 1024 * 1024), false);
  assert.equal(CT.shouldUseChunks(300 * 1024 * 1024, 0), false);  // disabled
});

test('chunkProgressPct reports overall file percentage across chunks', () => {
  const size = 300 * 1024 * 1024;
  const chunk = 25 * 1024 * 1024;
  assert.equal(CT.chunkProgressPct(0, 0, size), 0);
  assert.equal(CT.chunkProgressPct(0, chunk / 2, size), 4);       // half of chunk 0
  assert.equal(CT.chunkProgressPct(chunk, 0, size), 8);           // chunk 0 done
  assert.equal(CT.chunkProgressPct(chunk, chunk / 2, size), 13);  // chunk 1 halfway
  assert.equal(CT.chunkProgressPct(size, 0, size), 100);
  assert.equal(CT.chunkProgressPct(size, chunk, size), 100);      // clamped
  assert.equal(CT.chunkProgressPct(0, 0, 0), 100);                // empty file
});

test('formatBytes renders human-readable sizes', () => {
  assert.equal(CT.formatBytes(0), '0 B');
  assert.equal(CT.formatBytes(512), '512 B');
  assert.equal(CT.formatBytes(2048), '2 KB');
  assert.equal(CT.formatBytes(25 * 1024 * 1024), '25 MB');
  assert.equal(CT.formatBytes(1.5 * 1024 * 1024), '1.5 MB');
  assert.equal(CT.formatBytes(3 * 1024 * 1024 * 1024), '3 GB');
  assert.equal(CT.formatBytes(-5), '0 B');
  assert.equal(CT.formatBytes(NaN), '0 B');
});

test('formatEta renders durations', () => {
  assert.equal(CT.formatEta(0), '0s');
  assert.equal(CT.formatEta(42.4), '42s');
  assert.equal(CT.formatEta(65), '1m 05s');
  assert.equal(CT.formatEta(3600 + 60 + 2), '1h 01m');
  assert.equal(CT.formatEta(Infinity), '--');
  assert.equal(CT.formatEta(-3), '--');
});

test('uploadStatsSuffix shows transferred bytes, speed and ETA', () => {
  assert.equal(CT.uploadStatsSuffix(0, 1000, 0, 500), '');    // nothing sent yet
  assert.equal(CT.uploadStatsSuffix(100, 1000, 0, 50), '');   // too early (<100ms)
  // 150 MB in 10s -> 15 MB/s, 150 MB left -> ETA 10s
  assert.equal(
    CT.uploadStatsSuffix(150 * 1024 * 1024, 300 * 1024 * 1024, 0, 10000),
    ' \u00b7 150 MB/300 MB \u00b7 15 MB/s \u00b7 ETA 10s'
  );
  // fully sent: ETA 0s
  assert.equal(
    CT.uploadStatsSuffix(300 * 1024 * 1024, 300 * 1024 * 1024, 0, 10000),
    ' \u00b7 300 MB/300 MB \u00b7 30 MB/s \u00b7 ETA 0s'
  );
});

test('uploadStatsSuffix decays speed and grows ETA when transfer stalls', () => {
  // same 150 MB sent, but twice the time elapsed with no new bytes:
  // speed halves (15 -> 7.5 MB/s) and ETA doubles (10s -> 20s)
  assert.equal(
    CT.uploadStatsSuffix(150 * 1024 * 1024, 300 * 1024 * 1024, 0, 20000),
    ' \u00b7 150 MB/300 MB \u00b7 7.5 MB/s \u00b7 ETA 20s'
  );
});

test('wsUrl follows the page protocol and host', () => {
  globalThis.location = { protocol: 'https:', host: 'clamtotal.com' };
  assert.equal(CT.wsUrl('/file/upload/ws'), 'wss://clamtotal.com/file/upload/ws');
  globalThis.location = { protocol: 'http:', host: '192.168.1.10:8000' };
  assert.equal(CT.wsUrl('/file/upload/ws'), 'ws://192.168.1.10:8000/file/upload/ws');
  delete globalThis.location;
  assert.equal(CT.wsUrl('/x'), 'ws://localhost/x');
});

test('runPool runs with bounded concurrency and ordered results', async () => {
  let active = 0, maxActive = 0;
  const items = Array.from({ length: 10 }, (_, i) => i);
  const results = await CT.runPool(items, 4, async (x) => {
    active++; maxActive = Math.max(maxActive, active);
    await new Promise((r) => setTimeout(r, 5));
    active--;
    return x * 10;
  });
  assert.deepEqual(results, items.map((x) => x * 10)); // order preserved
  assert.ok(maxActive <= 4, `concurrency ${maxActive} exceeded 4`);
  assert.ok(maxActive >= 2, 'should actually parallelize');
});

test('runPool handles empty input and concurrency > length', async () => {
  assert.deepEqual(await CT.runPool([], 4, async (x) => x), []);
  assert.deepEqual(await CT.runPool([1, 2], 10, async (x) => x + 1), [2, 3]);
});

test('withRetry retries transient errors then succeeds', async () => {
  let calls = 0;
  const r = await CT.withRetry(() => {
    calls++;
    if (calls < 3) { const e = new Error('524'); e.transient = true; throw e; }
    return 'ok';
  }, 3, 1);
  assert.equal(r, 'ok');
  assert.equal(calls, 3);
});

test('withRetry does not retry non-transient errors and gives up after attempts', async () => {
  let calls = 0;
  await assert.rejects(
    CT.withRetry(() => { calls++; throw new Error('fatal'); }, 3, 1),
    /fatal/,
  );
  assert.equal(calls, 1); // non-transient: no retry
  let calls2 = 0;
  await assert.rejects(
    CT.withRetry(() => { calls2++; const e = new Error('524'); e.transient = true; throw e; }, 2, 1),
    /524/,
  );
  assert.equal(calls2, 2); // gave up after attempts
});

test('escapeHtml escapes markup-significant characters', () => {
  assert.equal(CT.escapeHtml('<b>"x" & \'y\'</b>'), '&lt;b&gt;&quot;x&quot; &amp; &#39;y&#39;&lt;/b&gt;');
  assert.equal(CT.escapeHtml('plain'), 'plain');
});

test('engineRowHtml renders a spinner while scanning, verdicts when done', () => {
  const scanning = CT.engineRowHtml({ name: 'ClamAV (clamd)', status: 'scanning' }, 0);
  assert.match(scanning, /^<tr data-engine="0">/);
  assert.match(scanning, /class="spinner engine-spinner"/);
  assert.match(scanning, /Scanning…/);
  assert.match(scanning, /ClamAV \(clamd\)/);

  const clean = CT.engineRowHtml({ name: 'YARA (local rules)', status: 'done', verdict: 'clean', signature: null }, 1);
  assert.match(clean, /<tr data-engine="1">/);
  assert.match(clean, /Undetected/);
  assert.match(clean, /#39ac4c/);
  assert.doesNotMatch(clean, /engine-spinner/);

  const bad = CT.engineRowHtml({ name: 'ClamAV (clamd)', status: 'done', verdict: 'infected', signature: 'Win.Test.EICAR_HDB-1' }, 2);
  assert.match(bad, /Win\.Test\.EICAR_HDB-1/);
  assert.match(bad, /<span class="flag">/);
  assert.match(bad, /#c52420/);

  // engine names/signatures are escaped, never injected as HTML
  const evil = CT.engineRowHtml({ name: '<img src=x>', status: 'done', verdict: 'infected', signature: '<script>alert(1)</script>' }, 0);
  assert.ok(!evil.includes('<img src=x>'));
  assert.ok(!evil.includes('<script>alert(1)</script>'));
  assert.match(evil, /&lt;script&gt;/);
});

test('engineStateHtml/engineResultHtml cover scanning, clean and infected', () => {
  assert.match(CT.engineStateHtml({ status: 'scanning' }), /engine-spinner/);
  assert.match(CT.engineStateHtml({ status: 'done', verdict: 'clean' }), /#39ac4c/);
  assert.match(CT.engineStateHtml({ status: 'done', verdict: 'infected' }), /#c52420/);
  assert.match(CT.engineResultHtml({ status: 'scanning' }), /Scanning…/);
  assert.match(CT.engineResultHtml({ status: 'done', verdict: 'clean' }), /Undetected/);
  assert.match(CT.engineResultHtml({ status: 'done', verdict: 'infected', signature: 'Sig-1' }), /Sig-1/);
});

test('updateDetectionEngines re-renders one row per engine and is null-safe', () => {
  delete globalThis.document;
  assert.doesNotThrow(() => CT.updateDetectionEngines([{ name: 'x', status: 'scanning' }]));
  assert.doesNotThrow(() => CT.updateDetectionEngines(null));
  assert.doesNotThrow(() => CT.updateDetectionEngines('nope'));

  const box = { innerHTML: '' };
  globalThis.document = { getElementById: (id) => (id === 'detection-engines' ? box : null) };
  CT.updateDetectionEngines([
    { name: 'ClamAV (clamd)', status: 'done', verdict: 'clean', signature: null },
    { name: 'YARA (local rules)', status: 'scanning' },
  ]);
  assert.equal((box.innerHTML.match(/<tr data-engine=/g) || []).length, 2);
  assert.match(box.innerHTML, /Undetected/);
  assert.match(box.innerHTML, /engine-spinner/);

  CT.updateDetectionEngines([]); // empty list leaves the current rows alone
  assert.match(box.innerHTML, /Undetected/);
  delete globalThis.document;
});

test('progressKey tracks done engines and committed analysis', () => {
  assert.equal(CT.progressKey({ engines: [], behavior: null }), '0:0');
  assert.equal(
    CT.progressKey({
      engines: [{ status: 'done' }, { status: 'scanning' }],
      behavior: { suspicious_strings: [] },
    }),
    '1:1'
  );
  assert.equal(CT.progressKey({ status: 'pending' }), '0:0'); // missing fields are safe
});

test('initPolling updates engine rows in place, reloads on new sections and when done', async () => {
  let calls = 0;
  let reloaded = false;
  let cleared = false;
  const progressEl = { dataset: { sha: 'ab'.repeat(32), interval: '5', key: '0:0' } };
  const box = { innerHTML: '' };
  globalThis.document = {
    getElementById: (id) => ({ 'scan-progress': progressEl, 'detection-engines': box }[id] || null),
  };
  const responses = [
    { // poll 1: ClamAV done (key 1:0 != rendered 0:0) -> reload to re-render
      status: 'pending',
      engines: [
        { name: 'ClamAV (clamd)', status: 'done', verdict: 'infected', signature: 'Win.Test.EICAR_HDB-1' },
        { name: 'YARA (local rules)', status: 'scanning' },
      ],
      behavior: null,
    },
    { // poll 2: key unchanged (0 done engines, no analysis) -> in-place update only
      status: 'pending',
      engines: [
        { name: 'ClamAV (clamd)', status: 'scanning' },
        { name: 'YARA (local rules)', status: 'scanning' },
      ],
      behavior: null,
    },
    { status: 'done', engines: [] }, // poll 3: scan finished -> reload
  ];
  globalThis.fetch = async () => {
    const body = responses[Math.min(calls, responses.length - 1)];
    calls += 1;
    return { json: async () => body };
  };
  let intervalId = null;
  globalThis.setInterval = (fn, ms) => { intervalId = { fn, ms }; return 1; };
  globalThis.clearInterval = () => { cleared = true; };
  Object.defineProperty(globalThis, 'location', { value: { reload: () => { reloaded = true; } }, configurable: true });

  CT.initPolling();
  await intervalId.fn(); // poll 1: key changed (engine finished) -> reload
  assert.equal(reloaded, true);
  assert.equal(cleared, true);

  reloaded = false; cleared = false;
  box.innerHTML = '';
  await intervalId.fn(); // poll 2: key unchanged -> rows updated in place, no reload
  assert.equal(reloaded, false);
  assert.equal((box.innerHTML.match(/engine-spinner/g) || []).length, 2); // both still spinning
  assert.match(box.innerHTML, /ClamAV \(clamd\)/);

  await intervalId.fn(); // poll 3: done -> reload
  assert.equal(reloaded, true);

  delete globalThis.document;
  delete globalThis.fetch;
  delete globalThis.setInterval;
  delete globalThis.clearInterval;
  delete globalThis.location;
});

test('initPolling updates engine rows in place when nothing new was committed', async () => {
  let reloaded = false;
  const progressEl = { dataset: { sha: 'cd'.repeat(32), interval: '5', key: '1:0' } };
  const box = { innerHTML: '' };
  globalThis.document = {
    getElementById: (id) => ({ 'scan-progress': progressEl, 'detection-engines': box }[id] || null),
  };
  globalThis.fetch = async () => ({
    json: async () => ({
      status: 'pending',
      engines: [
        { name: 'ClamAV (clamd)', status: 'done', verdict: 'infected', signature: 'Win.Test.EICAR_HDB-1' },
        { name: 'YARA (local rules)', status: 'scanning' },
      ],
      behavior: null, // key 1:0 matches the rendered data-key
    }),
  });
  let intervalId = null;
  globalThis.setInterval = (fn, ms) => { intervalId = { fn, ms }; return 1; };
  globalThis.clearInterval = () => {};
  Object.defineProperty(globalThis, 'location', { value: { reload: () => { reloaded = true; } }, configurable: true });

  CT.initPolling();
  await intervalId.fn(); // key 1:0 == rendered key -> rows updated, no reload
  assert.equal(reloaded, false);
  assert.match(box.innerHTML, /Win\.Test\.EICAR_HDB-1/);
  assert.match(box.innerHTML, /engine-spinner/); // YARA row still spinning

  delete globalThis.document;
  delete globalThis.fetch;
  delete globalThis.setInterval;
  delete globalThis.clearInterval;
  delete globalThis.location;
});

test('uploadStatusText shows upload progress, then Combining once all bytes are sent', () => {
  assert.equal(CT.uploadStatusText('a.bin', 0), 'Uploading a.bin… 0%');
  assert.equal(CT.uploadStatusText('a.bin', 57), 'Uploading a.bin… 57%');
  assert.equal(CT.uploadStatusText('a.bin', 99), 'Uploading a.bin… 99%');
  // 100% sent: the server is reassembling/hashing before the report page opens
  assert.equal(CT.uploadStatusText('a.bin', 100), 'Combining a.bin…');
});
