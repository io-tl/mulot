// mulotCrypto — synchronous crypto primitives injected into the page by the
// browser_inject tool. These fill the gaps in crypto.subtle: legacy hashes
// (MD5, SHA-1) it never had, and — crucially — hashing that works on an
// insecure context (http:// non-localhost), where crypto.subtle is undefined.
// Pure, dependency-free, and namespaced under window.mulotCrypto.
//
// Public API (input is a string [utf-8] or a Uint8Array/byte array):
//   mulotCrypto.md5(input)            -> hex
//   mulotCrypto.sha1(input)           -> hex
//   mulotCrypto.sha256(input)         -> hex
//   mulotCrypto.hmac(name, key, msg)  -> hex   (name: 'md5'|'sha1'|'sha256')
//   mulotCrypto.rc4(key, data)        -> hex   (keystream XOR, hex out)
//   mulotCrypto.hex(bytes) / .bytes(input) / .utf8(str)   helpers
(function (root) {
  'use strict';

  function utf8(str) { return new TextEncoder().encode(String(str)); }

  function toBytes(input) {
    if (input instanceof Uint8Array) return input;
    if (Array.isArray(input)) return new Uint8Array(input);
    return utf8(input);
  }

  function hex(bytes) {
    var s = '';
    for (var i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, '0');
    return s;
  }

  // ── MD5 (RFC 1321) ──────────────────────────────────────────
  function md5Bytes(msg) {
    function rl(x, c) { return (x << c) | (x >>> (32 - c)); }
    function add(a, b) { return (a + b) | 0; }
    var S = [7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
             5,9,14,20, 5,9,14,20, 5,9,14,20, 5,9,14,20,
             4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
             6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21];
    var K = new Int32Array(64);
    for (var i = 0; i < 64; i++) K[i] = (Math.floor(Math.abs(Math.sin(i + 1)) * 4294967296)) | 0;

    var ml = msg.length;
    var withPad = new Uint8Array(((ml + 8) >> 6) * 64 + 64);
    withPad.set(msg);
    withPad[ml] = 0x80;
    var bits = ml * 8;
    // 64-bit little-endian length (low 32 bits suffice for our inputs, but write both)
    var lenLo = bits >>> 0, lenHi = Math.floor(ml / 0x20000000) >>> 0;
    var p = withPad.length - 8;
    withPad[p] = lenLo & 255; withPad[p+1] = (lenLo>>>8)&255; withPad[p+2] = (lenLo>>>16)&255; withPad[p+3] = (lenLo>>>24)&255;
    withPad[p+4] = lenHi & 255; withPad[p+5] = (lenHi>>>8)&255; withPad[p+6] = (lenHi>>>16)&255; withPad[p+7] = (lenHi>>>24)&255;

    var a0 = 0x67452301, b0 = 0xefcdab89 | 0, c0 = 0x98badcfe | 0, d0 = 0x10325476;
    var M = new Int32Array(16);
    for (var off = 0; off < withPad.length; off += 64) {
      for (var j = 0; j < 16; j++) {
        M[j] = withPad[off+j*4] | (withPad[off+j*4+1]<<8) | (withPad[off+j*4+2]<<16) | (withPad[off+j*4+3]<<24);
      }
      var A = a0, B = b0, C = c0, D = d0;
      for (var k = 0; k < 64; k++) {
        var F, g;
        if (k < 16) { F = (B & C) | (~B & D); g = k; }
        else if (k < 32) { F = (D & B) | (~D & C); g = (5*k + 1) & 15; }
        else if (k < 48) { F = B ^ C ^ D; g = (3*k + 5) & 15; }
        else { F = C ^ (B | ~D); g = (7*k) & 15; }
        F = add(add(add(F, A), K[k]), M[g]);
        A = D; D = C; C = B; B = add(B, rl(F, S[k]));
      }
      a0 = add(a0, A); b0 = add(b0, B); c0 = add(c0, C); d0 = add(d0, D);
    }
    var out = new Uint8Array(16);
    [a0,b0,c0,d0].forEach(function (w, idx) {
      out[idx*4]   = w & 255; out[idx*4+1] = (w>>>8)&255; out[idx*4+2] = (w>>>16)&255; out[idx*4+3] = (w>>>24)&255;
    });
    return out;
  }

  // ── SHA-1 (RFC 3174) ────────────────────────────────────────
  function sha1Bytes(msg) {
    function rl(x, c) { return (x << c) | (x >>> (32 - c)); }
    var ml = msg.length;
    var withPad = new Uint8Array(((ml + 8) >> 6) * 64 + 64);
    withPad.set(msg);
    withPad[ml] = 0x80;
    var bits = ml * 8;
    var lenHi = Math.floor(ml / 0x20000000) >>> 0, lenLo = (bits >>> 0);
    var p = withPad.length - 8;
    withPad[p]   = (lenHi>>>24)&255; withPad[p+1] = (lenHi>>>16)&255; withPad[p+2] = (lenHi>>>8)&255; withPad[p+3] = lenHi&255;
    withPad[p+4] = (lenLo>>>24)&255; withPad[p+5] = (lenLo>>>16)&255; withPad[p+6] = (lenLo>>>8)&255; withPad[p+7] = lenLo&255;

    var h0=0x67452301, h1=0xEFCDAB89|0, h2=0x98BADCFE|0, h3=0x10325476, h4=0xC3D2E1F0|0;
    var W = new Int32Array(80);
    for (var off = 0; off < withPad.length; off += 64) {
      for (var i = 0; i < 16; i++) {
        W[i] = (withPad[off+i*4]<<24) | (withPad[off+i*4+1]<<16) | (withPad[off+i*4+2]<<8) | withPad[off+i*4+3];
      }
      for (i = 16; i < 80; i++) W[i] = rl(W[i-3]^W[i-8]^W[i-14]^W[i-16], 1);
      var a=h0,b=h1,c=h2,d=h3,e=h4;
      for (i = 0; i < 80; i++) {
        var f, k;
        if (i < 20) { f = (b & c) | (~b & d); k = 0x5A827999; }
        else if (i < 40) { f = b ^ c ^ d; k = 0x6ED9EBA1; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC | 0; }
        else { f = b ^ c ^ d; k = 0xCA62C1D6 | 0; }
        var t = (rl(a,5) + f + e + k + W[i]) | 0;
        e = d; d = c; c = rl(b, 30); b = a; a = t;
      }
      h0=(h0+a)|0; h1=(h1+b)|0; h2=(h2+c)|0; h3=(h3+d)|0; h4=(h4+e)|0;
    }
    var out = new Uint8Array(20);
    [h0,h1,h2,h3,h4].forEach(function (w, idx) {
      out[idx*4]=(w>>>24)&255; out[idx*4+1]=(w>>>16)&255; out[idx*4+2]=(w>>>8)&255; out[idx*4+3]=w&255;
    });
    return out;
  }

  // ── SHA-256 (FIPS 180-4) ────────────────────────────────────
  var SHA256_K = new Int32Array([
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2]);

  function sha256Bytes(msg) {
    function rr(x, c) { return (x >>> c) | (x << (32 - c)); }
    var ml = msg.length;
    var withPad = new Uint8Array(((ml + 8) >> 6) * 64 + 64);
    withPad.set(msg);
    withPad[ml] = 0x80;
    var bits = ml * 8;
    var lenHi = Math.floor(ml / 0x20000000) >>> 0, lenLo = (bits >>> 0);
    var p = withPad.length - 8;
    withPad[p]   = (lenHi>>>24)&255; withPad[p+1] = (lenHi>>>16)&255; withPad[p+2] = (lenHi>>>8)&255; withPad[p+3] = lenHi&255;
    withPad[p+4] = (lenLo>>>24)&255; withPad[p+5] = (lenLo>>>16)&255; withPad[p+6] = (lenLo>>>8)&255; withPad[p+7] = lenLo&255;

    var h = new Int32Array([0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]);
    var W = new Int32Array(64);
    for (var off = 0; off < withPad.length; off += 64) {
      for (var i = 0; i < 16; i++) {
        W[i] = (withPad[off+i*4]<<24) | (withPad[off+i*4+1]<<16) | (withPad[off+i*4+2]<<8) | withPad[off+i*4+3];
      }
      for (i = 16; i < 64; i++) {
        var s0 = rr(W[i-15],7) ^ rr(W[i-15],18) ^ (W[i-15]>>>3);
        var s1 = rr(W[i-2],17) ^ rr(W[i-2],19) ^ (W[i-2]>>>10);
        W[i] = (W[i-16] + s0 + W[i-7] + s1) | 0;
      }
      var a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
      for (i = 0; i < 64; i++) {
        var S1 = rr(e,6) ^ rr(e,11) ^ rr(e,25);
        var ch = (e & f) ^ (~e & g);
        var t1 = (hh + S1 + ch + SHA256_K[i] + W[i]) | 0;
        var S0 = rr(a,2) ^ rr(a,13) ^ rr(a,22);
        var maj = (a & b) ^ (a & c) ^ (b & c);
        var t2 = (S0 + maj) | 0;
        hh=g; g=f; f=e; e=(d+t1)|0; d=c; c=b; b=a; a=(t1+t2)|0;
      }
      h[0]=(h[0]+a)|0; h[1]=(h[1]+b)|0; h[2]=(h[2]+c)|0; h[3]=(h[3]+d)|0;
      h[4]=(h[4]+e)|0; h[5]=(h[5]+f)|0; h[6]=(h[6]+g)|0; h[7]=(h[7]+hh)|0;
    }
    var out = new Uint8Array(32);
    for (var k = 0; k < 8; k++) {
      out[k*4]=(h[k]>>>24)&255; out[k*4+1]=(h[k]>>>16)&255; out[k*4+2]=(h[k]>>>8)&255; out[k*4+3]=h[k]&255;
    }
    return out;
  }

  // ── RC4 (keystream XOR) ─────────────────────────────────────
  function rc4Bytes(key, data) {
    var K = toBytes(key), D = toBytes(data);
    var S = new Uint8Array(256);
    for (var i = 0; i < 256; i++) S[i] = i;
    for (i = 0, j = 0; i < 256; i++) {
      j = (j + S[i] + K[i % K.length]) & 255;
      var t = S[i]; S[i] = S[j]; S[j] = t;
    }
    var out = new Uint8Array(D.length);
    var x = 0, y = 0, j;
    for (var n = 0; n < D.length; n++) {
      x = (x + 1) & 255; y = (y + S[x]) & 255;
      var tmp = S[x]; S[x] = S[y]; S[y] = tmp;
      out[n] = D[n] ^ S[(S[x] + S[y]) & 255];
    }
    return out;
  }

  var HASHES = {
    md5:    { fn: md5Bytes,    block: 64 },
    sha1:   { fn: sha1Bytes,   block: 64 },
    sha256: { fn: sha256Bytes, block: 64 },
  };

  // HMAC over any of the embedded sync hashes.
  function hmacBytes(name, key, msg) {
    var h = HASHES[name];
    if (!h) throw new Error('unknown hash: ' + name);
    var k = toBytes(key);
    if (k.length > h.block) k = h.fn(k);
    var pad = new Uint8Array(h.block); pad.set(k);
    var ipad = new Uint8Array(h.block), opad = new Uint8Array(h.block);
    for (var i = 0; i < h.block; i++) { ipad[i] = pad[i] ^ 0x36; opad[i] = pad[i] ^ 0x5c; }
    var m = toBytes(msg);
    var inner = new Uint8Array(h.block + m.length); inner.set(ipad); inner.set(m, h.block);
    var ih = h.fn(inner);
    var outer = new Uint8Array(h.block + ih.length); outer.set(opad); outer.set(ih, h.block);
    return h.fn(outer);
  }

  root.mulotCrypto = {
    utf8: utf8,
    bytes: toBytes,
    hex: hex,
    md5: function (input) { return hex(md5Bytes(toBytes(input))); },
    sha1: function (input) { return hex(sha1Bytes(toBytes(input))); },
    sha256: function (input) { return hex(sha256Bytes(toBytes(input))); },
    hmac: function (name, key, msg) { return hex(hmacBytes(name, key, msg)); },
    rc4: function (key, data) { return hex(rc4Bytes(key, data)); },
    rc4Bytes: rc4Bytes,
  };
})(typeof window !== 'undefined' ? window : globalThis);
