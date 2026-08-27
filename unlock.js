// unlock.js -- shared decrypt/unlock logic for gated ARG stage pages.
// Crypto parameters must match build.py exactly (PBKDF2-HMAC-SHA256 -> AES-256-GCM).

(function () {
  const PBKDF2_ITERATIONS_FALLBACK = 250000; // used only if payload.iterations is missing
  const IV_LEN = 12; // bytes -- must match build.py

  const MIME_TYPES = {
    png: "image/png", jpg: "image/jpeg", jpeg: "image/jpeg", gif: "image/gif",
    wav: "audio/wav", mp3: "audio/mpeg", ogg: "audio/ogg", mp4: "video/mp4",
    flac: "audio/flac", m4a: "audio/mp4", opus: "audio/ogg",
  };

  function guessMime(path) {
    const clean = path.replace(/\.enc$/, "");
    const ext = clean.split(".").pop().toLowerCase();
    return MIME_TYPES[ext] || "application/octet-stream";
  }

  function normalize(answer) {
    // lowercase + strip whitespace.
    // MUST MATCH normalize() in build.py (Python). This is a cross-language
    // sync point: if the two ever disagree, every derived key silently differs
    // and decryption fails with an opaque AES-GCM DOMException.
    return answer.trim().toLowerCase();
  }

  function b64ToBytes(b64) {
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  }

  async function deriveKey(password, salt, iterations) {
    const baseKey = await crypto.subtle.importKey(
      "raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveKey"]
    );
    return crypto.subtle.deriveKey(
      { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
      baseKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["decrypt"]
    );
  }

  // PBKDF2 -> raw bits, hex-encoded. Used by in-page answer gates to verify a
  // typed answer without a fast-hash oracle: a plain sha256 check would let an
  // attacker brute-force the answer at billions of guesses/sec, while this costs
  // the same per guess as attacking the encrypted payload itself.
  async function deriveBitsHex(password, salt, iterations) {
    const baseKey = await crypto.subtle.importKey(
      "raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]
    );
    const bits = await crypto.subtle.deriveBits(
      { name: "PBKDF2", salt, iterations, hash: "SHA-256" }, baseKey, 256
    );
    return Array.from(new Uint8Array(bits))
      .map((b) => b.toString(16).padStart(2, "0")).join("");
  }

  // Streams a response body so callers can report download progress. AES-GCM
  // can't be decrypted incrementally (the auth tag is at the very end), so this
  // only makes the *download* observable -- which is the part that takes seconds.
  // Falls back to a plain read where the browser gives no streaming body.
  async function readWithProgress(res, onProgress) {
    const total = Number(res.headers.get("Content-Length")) || null;
    if (!res.body || !res.body.getReader) {
      const buf = new Uint8Array(await res.arrayBuffer());
      onProgress(buf.length, total || buf.length);
      return buf;
    }
    const reader = res.body.getReader();
    const chunks = [];
    let received = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
      received += value.length;
      onProgress(received, total);
    }
    const out = new Uint8Array(received);
    let offset = 0;
    for (const chunk of chunks) { out.set(chunk, offset); offset += chunk.length; }
    return out;
  }

  // Fetches <path>.enc (iv[12] || ciphertext+tag, written raw by build.py),
  // decrypts it with the page's already-derived key, and returns a Blob URL.
  // Optional onProgress(receivedBytes, totalBytes|null) fires during the
  // download, so a stage carrying a multi-megabyte asset can show a real
  // progress bar instead of sitting on a blank page.
  async function decryptAsset(path, onProgress) {
    const res = await fetch(path);
    const buf = onProgress
      ? await readWithProgress(res, onProgress)
      : new Uint8Array(await res.arrayBuffer());
    const iv = buf.slice(0, IV_LEN);
    const ciphertext = buf.slice(IV_LEN);
    const plainBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, window.ARG.key, ciphertext);
    return URL.createObjectURL(new Blob([plainBuf], { type: guessMime(path) }));
  }

  // crypto.subtle only exists in a secure context -- https, or localhost. Open
  // the site over plain http (a LAN IP while testing from a phone, say) and it
  // is simply undefined, so every unlock throws before it ever looks at the
  // answer. Returns the message to show, or null when crypto is usable.
  function cryptoUnavailable() {
    if (window.crypto && window.crypto.subtle) return null;
    return window.isSecureContext === false
      ? "This page must be opened over https (or localhost)."
      : "This browser can't run the crypto this page needs.";
  }

  async function tryUnlock(rawAnswer, payload, errorEl) {
    const blocked = cryptoUnavailable();
    if (blocked) {
      console.error("[unlock] " + blocked + " (crypto.subtle is unavailable)");
      if (errorEl) errorEl.textContent = blocked;
      return false;
    }
    try {
      const password = normalize(rawAnswer);
      const salt = b64ToBytes(payload.salt);
      const iv = b64ToBytes(payload.iv);
      const ciphertext = b64ToBytes(payload.ciphertext);
      const iterations = payload.iterations || PBKDF2_ITERATIONS_FALLBACK;

      const key = await deriveKey(password, salt, iterations);

      // Only an AES-GCM auth-tag rejection means "wrong answer". Everything
      // outside this inner try is a fault in the page, not in what was typed,
      // and saying "Incorrect answer." to those is what sent us chasing a
      // passphrase that had never changed.
      let plaintextBuf;
      try {
        plaintextBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
      } catch (e) {
        if (errorEl) errorEl.textContent = "Incorrect answer.";
        return false;
      }
      const html = new TextDecoder().decode(plaintextBuf);

      // Same window survives document.open()/write()/close(), so anything
      // attached here is still reachable from the newly-written document's
      // own scripts -- lets a stage page fetch+decrypt its own binary assets
      // (images/audio) with the same key, without re-deriving from a password.
      window.ARG = { key, decryptAsset };

      // Full document replace so any <script> in the decrypted stage runs normally
      // (innerHTML would not execute embedded scripts).
      document.open();
      document.write(html);
      document.close();
      return true;
    } catch (e) {
      console.error("[unlock] failed:", e);
      if (errorEl) errorEl.textContent = "Something went wrong -- see the browser console.";
      return false;
    }
  }

  // Shared crypto primitives, exposed so nothing else has to redefine them.
  // Used by the /share/ page (which loads this file purely as a library -- the
  // DOMContentLoaded handler below no-ops without a #stage-data element) and by
  // in-page answer gates inside decrypted stages. The same window survives
  // document.open()/write()/close(), so this stays reachable after a stage is
  // written out. Nothing secret is exposed: deriveKey() marks the key
  // non-extractable, and all of this source is public anyway.
  window.ARGCrypto = { normalize, b64ToBytes, deriveKey, deriveBitsHex, cryptoUnavailable, IV_LEN };

  document.addEventListener("DOMContentLoaded", () => {
    const dataEl = document.getElementById("stage-data");
    if (!dataEl) return;
    const payload = JSON.parse(dataEl.textContent);

    const form = document.getElementById("unlock-form");
    const input = document.getElementById("unlock-input");
    const errorEl = document.getElementById("unlock-error");

    // (b) URL fragment unlock, for QR codes: https://site/<hash>/#the-answer
    // location.hash is never sent to the server or written to access logs.
    if (location.hash.length > 1) {
      const fromHash = decodeURIComponent(location.hash.slice(1));
      tryUnlock(fromHash, payload, errorEl);
    }

    // (a) manual form unlock
    if (form) {
      form.addEventListener("submit", async (e) => {
        e.preventDefault();
        errorEl.textContent = "";
        await tryUnlock(input.value, payload, errorEl);
      });
    }
  });
})();
