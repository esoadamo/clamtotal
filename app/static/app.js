/* ClamTotal frontend logic. Pure functions are exported on globalThis.ClamTotal
   so they can be unit-tested with node --test. All DOM wiring is null-safe. */
(function (global) {
  'use strict';

  var K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ];

  function rotr(x, n) { return (x >>> n) | (x << (32 - n)); }

  /* Pure-JS SHA-256, used as fallback when crypto.subtle is unavailable
     (e.g. plain HTTP on a LAN IP — not a secure context). */
  function sha256HexPure(bytes) {
    var h = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    var bitLen = bytes.length * 8;
    var padded = Array.from(bytes);
    padded.push(0x80);
    while (padded.length % 64 !== 56) padded.push(0);
    for (var i = 7; i >= 0; i--) padded.push((bitLen / Math.pow(2, i * 8)) & 0xff);
    var w = new Array(64);
    for (var block = 0; block < padded.length; block += 64) {
      for (var t = 0; t < 16; t++) {
        w[t] = (padded[block + t * 4] << 24) | (padded[block + t * 4 + 1] << 16) |
               (padded[block + t * 4 + 2] << 8) | padded[block + t * 4 + 3];
      }
      for (t = 16; t < 64; t++) {
        var s0 = rotr(w[t - 15], 7) ^ rotr(w[t - 15], 18) ^ (w[t - 15] >>> 3);
        var s1 = rotr(w[t - 2], 17) ^ rotr(w[t - 2], 19) ^ (w[t - 2] >>> 10);
        w[t] = (w[t - 16] + s0 + w[t - 7] + s1) | 0;
      }
      var a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
      for (t = 0; t < 64; t++) {
        var S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        var ch = (e & f) ^ (~e & g);
        var t1 = (hh + S1 + ch + K[t] + w[t]) | 0;
        var S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        var maj = (a & b) ^ (a & c) ^ (b & c);
        var t2 = (S0 + maj) | 0;
        hh = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
      }
      h[0] = (h[0] + a) | 0; h[1] = (h[1] + b) | 0; h[2] = (h[2] + c) | 0; h[3] = (h[3] + d) | 0;
      h[4] = (h[4] + e) | 0; h[5] = (h[5] + f) | 0; h[6] = (h[6] + g) | 0; h[7] = (h[7] + hh) | 0;
    }
    return h.map(function (x) { return ('00000000' + (x >>> 0).toString(16)).slice(-8); }).join('');
  }

  function toHex(digest) {
    return Array.from(new Uint8Array(digest)).map(function (b) {
      return b.toString(16).padStart(2, '0');
    }).join('');
  }

  function sha256Hex(buf) {
    var subtle = global.crypto && global.crypto.subtle;
    if (subtle && (global.isSecureContext !== false)) {
      return subtle.digest('SHA-256', buf).then(toHex);
    }
    return Promise.resolve(sha256HexPure(new Uint8Array(buf)));
  }

  /* Read the file in chunks, reporting progress, then hash it. */
  function hashFileWithProgress(file, onProgress) {
    var CHUNK = 4 * 1024 * 1024;
    var parts = [];
    var loaded = 0;
    function readNext(offset) {
      if (offset >= file.size) {
        return mergeParts(parts).then(function (all) { return sha256Hex(all); });
      }
      return new Promise(function (resolve, reject) {
        var reader = new FileReader();
        var slice = file.slice(offset, Math.min(offset + CHUNK, file.size));
        reader.onload = function () {
          parts.push(reader.result);
          loaded += slice.size;
          if (onProgress) onProgress(Math.min(100, Math.round((loaded / file.size) * 100)));
          resolve();
        };
        reader.onerror = reject;
        reader.readAsArrayBuffer(slice);
      }).then(function () { return readNext(offset + CHUNK); });
    }
    function mergeParts(arr) {
      var total = arr.reduce(function (n, p) { return n + p.byteLength; }, 0);
      var out = new Uint8Array(total);
      var off = 0;
      arr.forEach(function (p) { out.set(new Uint8Array(p), off); off += p.byteLength; });
      return Promise.resolve(out.buffer);
    }
    if (file.size === 0) return Promise.resolve(sha256Hex(new ArrayBuffer(0)));
    return readNext(0);
  }

  function defang(value) {
    return String(value).replace(/http/gi, 'hxxp').replace(/\./g, '[.]');
  }

  function $(id) { return global.document ? global.document.getElementById(id) : null; }

  function openModal(title, bodyHtml) {
    var overlay = $('modal-overlay');
    if (!overlay) return;
    var t = $('modal-title'); if (t && title) t.textContent = title;
    var b = $('modal-body'); if (b && bodyHtml) b.innerHTML = bodyHtml;
    overlay.classList.add('open');
  }

  function closeModal() {
    var overlay = $('modal-overlay');
    if (overlay) overlay.classList.remove('open');
  }

  function initTabs() {
    var tabs = global.document ? global.document.querySelectorAll('.tab') : [];
    tabs.forEach(function (btn) {
      btn.addEventListener('click', function () {
        global.document.querySelectorAll('.tab').forEach(function (b) { b.classList.toggle('active', b === btn); });
        global.document.querySelectorAll('.tab-panel').forEach(function (p) {
          p.classList.toggle('active', p.id === 'tab-' + btn.dataset.tab);
        });
      });
    });
  }

  function initPolling() {
    var el = $('pending-data');
    if (!el) return;
    var sha = el.dataset.sha;
    var interval = parseInt(el.dataset.interval || '3000', 10);
    var timer = global.setInterval(function () {
      return global.fetch('/api/v2/files/' + sha)
        .then(function (r) { return r.json(); })
        .then(function (data) {
          if (data.status === 'done') { global.clearInterval(timer); global.location.reload(); }
        })
        .catch(function () {});
    }, interval);
  }

  function initUpload() {
    var dz = $('dropzone'), form = $('upload-form'), input = $('file-input');
    var idle = $('dz-idle'), progress = $('dz-progress'), spinner = $('dz-spinner');
    var status = $('dz-status'), bar = $('progress-bar'), errorBox = $('dz-error');
    if (!dz || !form || !input) return;
    var pendingFile = null;

    function startUpload(file, sha256) {
      closeModal();
      if (idle) idle.style.display = 'none';
      if (errorBox) errorBox.style.display = 'none';
      if (progress) progress.style.display = 'block';
      if (spinner) spinner.style.display = 'none';
      if (status) status.textContent = 'Uploading ' + file.name + '…';
      if (bar) bar.style.width = '0%';
      var xhr = new global.XMLHttpRequest();
      xhr.open('POST', form.action);
      xhr.upload.onprogress = function (e) {
        if (e.lengthComputable && bar && status) {
          var pct = Math.round((e.loaded / e.total) * 100);
          bar.style.width = pct + '%';
          status.textContent = 'Uploading ' + file.name + '… ' + pct + '%';
        }
      };
      xhr.upload.onload = function () { if (bar) bar.style.width = '100%'; };
      xhr.onload = function () {
        if (xhr.status === 200 || xhr.status === 202) {
          global.location.href = '/ui/file/' + sha256;
        } else if (progress && idle && errorBox) {
          progress.style.display = 'none';
          idle.style.display = 'block';
          errorBox.style.display = 'block';
          errorBox.textContent = 'Upload failed (' + xhr.status + '): ' + xhr.responseText.slice(0, 200);
        }
      };
      xhr.onerror = function () {
        if (progress && idle && errorBox) {
          progress.style.display = 'none';
          idle.style.display = 'block';
          errorBox.style.display = 'block';
          errorBox.textContent = 'Network error while uploading.';
        }
      };
      var fd = new FormData();
      fd.append('file', file, file.name);
      xhr.send(fd);
    }

    function onFileSelected(file) {
      if (errorBox) errorBox.style.display = 'none';
      openModal('Hashing ' + file.name + '…',
        '<div class="spinner" style="margin:8px auto 0"></div>' +
        '<div class="dz-status" id="hash-status">Hashing… 0%</div>' +
        '<div class="progress-track"><div class="progress-bar" id="hash-bar"></div></div>');
      hashFileWithProgress(file, function (pct) {
        var s = $('hash-status'); if (s) s.textContent = 'Hashing… ' + pct + '%';
        var b = $('hash-bar'); if (b) b.style.width = pct + '%';
      }).then(function (sha256) {
        // Any failure here (404 = not analyzed yet, but also network errors or a
        // transient 404 while another upload of the same file is still being
        // processed) must fall through to the upload prompt — never leave the
        // modal stuck on "Hashing..." with no way to proceed.
        global.fetch('/api/v2/files/' + sha256)
          .then(function (resp) { return resp.ok; })
          .catch(function () { return false; })
          .then(function (alreadyAnalyzed) {
          if (alreadyAnalyzed) { global.location.href = '/ui/file/' + sha256; return; }
          pendingFile = { file: file, sha256: sha256 };
          openModal('Upload file?',
            'This file has <strong>not been analyzed yet</strong>.<br><br>' +
            '<span class="muted">Name:</span> ' + file.name + '<br>' +
            '<span class="muted">Size:</span> ' + file.size + ' bytes<br>' +
            '<span class="muted">SHA-256:</span> <span class="mono">' + sha256 + '</span><br><br>' +
            'Do you want to upload it for scanning?');
        });
      });
    }

    var cancelBtn = $('modal-cancel'), confirmBtn = $('modal-confirm');
    if (cancelBtn) cancelBtn.addEventListener('click', function () { closeModal(); input.value = ''; });
    if (confirmBtn) confirmBtn.addEventListener('click', function () {
      if (pendingFile) startUpload(pendingFile.file, pendingFile.sha256);
    });
    input.addEventListener('change', function () { if (input.files.length) onFileSelected(input.files[0]); });
    form.addEventListener('submit', function (e) { e.preventDefault(); });
    ['dragover', 'dragenter'].forEach(function (ev) {
      dz.addEventListener(ev, function (e) { e.preventDefault(); dz.style.borderColor = '#d97706'; });
    });
    ['dragleave', 'drop'].forEach(function (ev) {
      dz.addEventListener(ev, function (e) { e.preventDefault(); dz.style.borderColor = ''; });
    });
    dz.addEventListener('drop', function (e) {
      if (e.dataTransfer.files.length) onFileSelected(e.dataTransfer.files[0]);
    });
  }

  global.ClamTotal = {
    sha256Hex: sha256Hex,
    sha256HexPure: sha256HexPure,
    hashFileWithProgress: hashFileWithProgress,
    defang: defang,
    openModal: openModal,
    closeModal: closeModal,
    initTabs: initTabs,
    initPolling: initPolling,
    initUpload: initUpload,
  };

  if (global.document) {
    global.document.addEventListener('DOMContentLoaded', function () {
      initTabs();
      initPolling();
      initUpload();
    });
  }
})(typeof window !== 'undefined' ? window : globalThis);
