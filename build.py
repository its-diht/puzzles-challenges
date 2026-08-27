#!/usr/bin/env python3
"""
build.py -- generates encrypted, gated stage pages for the ARG.

Each stage is unlocked by the answer to the *previous* stage:
    folder name    = an explicit random constant, set in stages_local.py
    encryption key = normalize(previous_answer)

SECURITY: the folder name must NEVER be derived from the answer. It used to be
sha256(normalize(previous_answer))[:32], which leaked every answer: folder names
are public (they're the URL, and the repo is public), and an unsalted single-pass
sha256 is ~76,000x cheaper to attack than the 250k-iteration PBKDF2 protecting the
payload. Anyone could dictionary-attack the folder name to recover the answer and
skip the puzzle -- 3 of 4 answers fell to a 30k-word list in 0.02s. Keep folder
names random and unrelated to the answers.

Requires: pip install cryptography
"""

import base64
import hashlib
import json
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Must match the constants in unlock.js exactly.
PBKDF2_ITERATIONS = 250_000
SALT_LEN = 16   # bytes
IV_LEN = 12     # bytes, required nonce length for AES-GCM
KEY_LEN = 32    # bytes -> AES-256

OUTPUT_DIR = "."                  # site root; stage -> <OUTPUT_DIR>/<hash>/index.html
UNLOCK_JS_PATH = "../unlock.js"   # relative path from a stage page to the shared script


def normalize(answer: str) -> str:
    """lowercase + strip whitespace.

    MUST MATCH normalize() in unlock.js (JavaScript). This is a cross-language
    sync point -- the only duplicated crypto logic left, since every JS caller
    now shares the one definition via window.ARGCrypto. If the two ever
    disagree, keys derive differently and decryption fails with an opaque
    AES-GCM DOMException rather than anything that points here.
    """
    return answer.strip().lower()


def derive_key(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS, dklen=KEY_LEN
    )


def encrypt_html(html: str, key: bytes, salt: bytes) -> dict:
    iv = os.urandom(IV_LEN)
    ciphertext = AESGCM(key).encrypt(iv, html.encode("utf-8"), None)  # tag appended
    return {
        "salt": base64.b64encode(salt).decode(),
        "iv": base64.b64encode(iv).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "iterations": PBKDF2_ITERATIONS,
    }


def encrypt_asset(data: bytes, key: bytes) -> bytes:
    """Encrypts a binary asset with the same key as the page. Output format is
    iv (12 bytes) || ciphertext+tag, written raw -- no base64, no bloat.
    unlock.js slices the iv back off the front after fetch()."""
    iv = os.urandom(IV_LEN)
    ciphertext = AESGCM(key).encrypt(iv, data, None)
    return iv + ciphertext


STAGE_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="robots" content="noindex,nofollow">
<meta name="referrer" content="no-referrer">
<title>Locked</title>
<style>
  body {{ font-family: monospace; max-width: 32em; margin: 4em auto; padding: 0 1em; }}
  #unlock-form {{ display: flex; gap: .5em; }}
  input[type=text] {{ flex: 1; font: inherit; padding: .4em; }}
  #unlock-error {{ color: #b00; min-height: 1.2em; }}
</style>
</head>
<body>
  <div id="lock-screen">
    <p>This stage is locked. Enter the previous answer to continue.</p>
    <form id="unlock-form">
      <input type="text" id="unlock-input" autocomplete="off" autofocus>
      <button type="submit">Unlock</button>
    </form>
    <p id="unlock-error"></p>
  </div>

  <script id="stage-data" type="application/json">{payload_json}</script>
  <script src="{unlock_js_path}" defer></script>
</body>
</html>
"""


# The front page is the entry point: it lives at the site *root* (not a hashed
# folder) and has no "previous answer" -- it's unlocked by a standalone passcode
# you distribute (typed into the form, or auto-applied via a #fragment on the
# shared entry URL). Same crypto as a stage; only the chrome differs.
FRONT_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="robots" content="noindex,nofollow">
<meta name="referrer" content="no-referrer">
<title></title>
<style>
  html, body {{ margin: 0; height: 100%; background: #000; }}
  body {{
    display: flex; align-items: center; justify-content: center;
    font-family: ui-monospace, "SFMono-Regular", Menlo, Consolas, monospace;
    color: #bbb;
  }}
  #lock-screen {{ text-align: center; padding: 1.5em; }}
  #lock-screen p.prompt {{ margin: 0 0 1em; letter-spacing: .18em;
    text-transform: uppercase; font-size: .8rem; color: #777; }}
  #unlock-form {{ display: inline-flex; gap: .5em; }}
  #unlock-input {{
    font: inherit; padding: .55em .7em; width: 12em;
    background: #0d0d0d; border: 1px solid #333; color: #eee; border-radius: 3px;
    outline: none; text-align: center; letter-spacing: .1em;
  }}
  #unlock-input:focus {{ border-color: #666; }}
  #unlock-form button {{
    font: inherit; padding: .55em 1em; cursor: pointer;
    background: #eee; border: none; color: #111; border-radius: 3px;
  }}
  #unlock-error {{ color: #a33; min-height: 1.2em; margin-top: .8em; font-size: .8rem; }}
</style>
</head>
<body>
  <div id="lock-screen">
    <p class="prompt">enter passcode</p>
    <form id="unlock-form">
      <input type="text" id="unlock-input" autocomplete="off" autofocus spellcheck="false">
      <button type="submit">&rarr;</button>
    </form>
    <p id="unlock-error"></p>
  </div>

  <script id="stage-data" type="application/json">{payload_json}</script>
  <script src="{unlock_js_path}" defer></script>
</body>
</html>
"""


# The share page is one fixed URL shared by several passphrases, each gating
# a DIFFERENT file. The page shell itself isn't secret (it's just a prompt +
# download UI), so it ships unencrypted; only the files are gated. Each file
# gets its own random salt/key, so a candidate decrypt only ever succeeds
# against its own matching asset -- AES-GCM's auth tag rejects any other key,
# so a passphrase for file 2 cannot decrypt file 1, 3, or 4.
SHARE_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="robots" content="noindex,nofollow">
<meta name="referrer" content="no-referrer">
<title></title>
<style>
  html, body {{ margin: 0; height: 100%; background: #585858; }}
  body {{
    display: flex; align-items: center; justify-content: center;
    font-family: ui-monospace, "SFMono-Regular", Menlo, Consolas, monospace;
    color: #ddd;
  }}
  #lock-screen {{ text-align: center; padding: 1.5em; max-width: 24em; }}
  #lock-screen p.prompt {{ margin: 0 0 1em; letter-spacing: .18em;
    text-transform: uppercase; font-size: .8rem; color: #bbb; }}
  #unlock-form {{ display: inline-flex; gap: .5em; }}
  #unlock-input {{
    font: inherit; padding: .55em .7em; width: 12em;
    background: #333; border: 1px solid #666; color: #eee; border-radius: 3px;
    outline: none; text-align: center; letter-spacing: .1em;
  }}
  #unlock-input:focus {{ border-color: #999; }}
  #unlock-form button {{
    font: inherit; padding: .55em 1em; cursor: pointer;
    background: #eee; border: none; color: #111; border-radius: 3px;
  }}
  #unlock-error {{ color: #f2a5a5; min-height: 1.2em; margin-top: .8em; font-size: .8rem; }}
  #unlock-status {{ color: #cfe0ea; min-height: 1.2em; margin-bottom: .8em; font-size: .8rem; }}
  #download-link {{
    display: inline-flex; align-items: center; gap: .55em;
    padding: .65em 1.3em; font: inherit; font-size: .9rem;
    background: #eee; color: #111; border-radius: 4px;
    text-decoration: none; cursor: pointer;
  }}
  #download-link:hover {{ background: #fff; }}
  #download-link svg {{ width: 1.1em; height: 1.1em; flex: none; }}
</style>
</head>
<body>
  <div id="lock-screen">
    <div id="entry-section">
      <p class="prompt">enter key</p>
      <form id="unlock-form">
        <input type="text" id="unlock-input" autocomplete="off" autofocus spellcheck="false">
        <button type="submit">&rarr;</button>
      </form>
      <p id="unlock-error"></p>
    </div>
    <div id="result-section" style="display: none;">
      <p id="unlock-status"></p>
      <a id="download-link" download>
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"
             stroke-linecap="round" stroke-linejoin="round">
          <path d="M12 3v12"></path>
          <path d="M7 10l5 5 5-5"></path>
          <path d="M4 19h16"></path>
        </svg>
        <span id="download-label"></span>
      </a>
    </div>
  </div>

  <!-- Loaded blocking (NOT defer) so window.ARGCrypto exists by the time the
       inline script below runs: `defer` is ignored on inline scripts, so an
       inline block always executes during parsing, ahead of any deferred file. -->
  <script src="../unlock.js"></script>
<script>
(function () {{
  const CANDIDATES = {candidates_json};

  // Crypto primitives come from unlock.js (window.ARGCrypto) so normalize(),
  // base64 decoding, key derivation and IV_LEN have exactly one definition.
  // unlock.js is loaded above purely as a library -- its own unlock handler
  // no-ops here because this page has no #stage-data element. Held by
  // reference rather than destructured: if the script failed to load, that is
  // worth reporting, not an uncaught TypeError that leaves the form dead.
  const ARGC = window.ARGCrypto || null;

  // Resolves to the decrypted bytes, or to null when this candidate simply
  // isn't the file the entered passphrase opens. Anything else -- a missing
  // asset, a malformed blob -- throws, because that's a fault in the page
  // rather than a wrong key, and the two must not read the same.
  async function tryCandidate(candidate, password) {{
    const salt = ARGC.b64ToBytes(candidate.salt);
    const key = await ARGC.deriveKey(password, salt, candidate.iterations);
    const res = await fetch(candidate.asset);
    if (!res.ok) throw new Error("fetch " + candidate.asset + " -> HTTP " + res.status);
    const buf = new Uint8Array(await res.arrayBuffer());
    const iv = buf.slice(0, ARGC.IV_LEN);
    const ciphertext = buf.slice(ARGC.IV_LEN);
    try {{
      // Throws (auth tag mismatch) whenever this candidate isn't the right one
      // for the entered passphrase -- that's the whole access-control mechanism.
      return await crypto.subtle.decrypt({{ name: "AES-GCM", iv }}, key, ciphertext);
    }} catch (e) {{
      return null;
    }}
  }}

  async function tryUnlock(rawKey, errorEl, statusEl, linkEl, labelEl, entrySection, resultSection) {{
    if (!ARGC) {{
      console.error("[share] unlock.js did not load");
      errorEl.textContent = "Couldn't load unlock.js -- reload the page.";
      return false;
    }}
    // typeof-guarded: during a Pages deploy a cached older unlock.js can be
    // paired with this page, and an uncaught TypeError here would leave the
    // form silently dead -- the exact failure this whole change exists to kill.
    const blocked = typeof ARGC.cryptoUnavailable === "function" ? ARGC.cryptoUnavailable() : null;
    if (blocked) {{
      console.error("[share] " + blocked + " (crypto.subtle is unavailable)");
      errorEl.textContent = blocked;
      return false;
    }}
    const password = ARGC.normalize(rawKey);
    let faulted = false;
    for (const candidate of CANDIDATES) {{
      let plainBuf;
      try {{
        plainBuf = await tryCandidate(candidate, password);
      }} catch (e) {{
        // A fault on one file must not hide a key that opens a different one:
        // remember it and keep looking, so one broken asset can't lock out
        // every other share key.
        console.error("[share] " + candidate.name + " failed:", e);
        faulted = true;
        continue;
      }}
      if (!plainBuf) continue;   // just the wrong key for this file
      const url = URL.createObjectURL(new Blob([plainBuf], {{ type: "text/plain" }}));
      linkEl.href = url;
      linkEl.download = candidate.name;
      labelEl.textContent = candidate.name;
      statusEl.textContent = "key accepted";
      entrySection.style.display = "none";
      resultSection.style.display = "block";
      return true;
    }}
    // Only say "wrong key" when every candidate cleanly rejected it.
    errorEl.textContent = faulted
      ? "Something went wrong -- see the browser console."
      : "Incorrect key.";
    return false;
  }}

  document.addEventListener("DOMContentLoaded", () => {{
    const form = document.getElementById("unlock-form");
    const input = document.getElementById("unlock-input");
    const errorEl = document.getElementById("unlock-error");
    const statusEl = document.getElementById("unlock-status");
    const linkEl = document.getElementById("download-link");
    const labelEl = document.getElementById("download-label");
    const entrySection = document.getElementById("entry-section");
    const resultSection = document.getElementById("result-section");

    // URL fragment unlock, same convention as every other page here:
    // https://site/share/#<key> -- location.hash is never sent to the server.
    if (location.hash.length > 1) {{
      tryUnlock(decodeURIComponent(location.hash.slice(1)), errorEl, statusEl, linkEl, labelEl, entrySection, resultSection);
    }}

    form.addEventListener("submit", async (e) => {{
      e.preventDefault();
      errorEl.textContent = "";
      await tryUnlock(input.value, errorEl, statusEl, linkEl, labelEl, entrySection, resultSection);
    }});
  }});
}})();
</script>
</body>
</html>
"""


def build_share(entries, output_dir: str = OUTPUT_DIR, folder: str = "share") -> str:
    """Builds one shared unlock page where each of several passphrases gates a
    DIFFERENT file, all served from the same URL. entries is a list of
    (passphrase, filename-in-content) pairs. The page shell ships unencrypted
    (it holds no secret); each file gets its own random salt and its own
    derived key, so a given passphrase can only ever decrypt its own file --
    the others fail AES-GCM authentication and are never exposed. Returns the
    folder name written (always `folder`, unlike build_stage's hash)."""
    share_dir = os.path.join(output_dir, folder)
    os.makedirs(share_dir, exist_ok=True)

    candidates = []
    for passphrase, filename in entries:
        password = normalize(passphrase)
        salt = os.urandom(SALT_LEN)
        key = derive_key(password, salt)

        with open(os.path.join("content", filename), "rb") as f:
            data = f.read()
        asset_name = filename + ".enc"
        with open(os.path.join(share_dir, asset_name), "wb") as f:
            f.write(encrypt_asset(data, key))

        candidates.append({
            "salt": base64.b64encode(salt).decode(),
            "iterations": PBKDF2_ITERATIONS,
            "asset": asset_name,
            "name": filename,
        })

    with open(os.path.join(share_dir, "index.html"), "w", encoding="utf-8") as f:
        f.write(SHARE_TEMPLATE.format(candidates_json=json.dumps(candidates)))

    print(f"[+] share page ({len(entries)} keys)                -> /{folder}/index.html")
    return folder


def render_stage_html(payload: dict, template: str = STAGE_TEMPLATE,
                      unlock_js_path: str = UNLOCK_JS_PATH) -> str:
    return template.format(
        payload_json=json.dumps(payload),
        unlock_js_path=unlock_js_path,
    )


def build_stage(previous_answer: str, folder: str, source_html: str, assets=None,
                output_dir: str = OUTPUT_DIR) -> str:
    """Encrypts source_html (and any binary assets) with key=normalize(previous_answer)
    and writes them to <output_dir>/<folder>/:
        index.html          -- encrypted page (AES-GCM, PBKDF2-derived key)
        <asset>.enc          -- encrypted binary asset, same key, own random iv
    `folder` is an explicit random name from stages_local.py -- see the SECURITY
    note at the top of this file for why it must not be derived from the answer.
    Assets are read from content/<asset>. Returns the folder name written.
    """
    password = normalize(previous_answer)
    salt = os.urandom(SALT_LEN)
    key = derive_key(password, salt)

    stage_dir = os.path.join(output_dir, folder)
    os.makedirs(stage_dir, exist_ok=True)

    payload = encrypt_html(source_html, key, salt)
    with open(os.path.join(stage_dir, "index.html"), "w", encoding="utf-8") as f:
        f.write(render_stage_html(payload))

    for asset in assets or []:
        with open(os.path.join("content", asset), "rb") as f:
            data = f.read()
        encrypted = encrypt_asset(data, key)
        with open(os.path.join(stage_dir, asset + ".enc"), "wb") as f:
            f.write(encrypted)

    return folder


def build_front(passcode: str, source_html: str, assets=None, output_dir: str = OUTPUT_DIR) -> None:
    """Encrypts the front page (source_html + any assets) with key=normalize(passcode)
    and writes them to the site *root*:
        index.html          -- encrypted decryptor shell (unlock.js referenced at root)
        <asset>.enc          -- encrypted binary asset (e.g. qr.png.enc), same key
    Unlike a stage, the front page has no hashed folder -- it *is* the entry URL.
    Assets are read from content/<asset>. Nothing plaintext is written."""
    password = normalize(passcode)
    salt = os.urandom(SALT_LEN)
    key = derive_key(password, salt)

    os.makedirs(output_dir, exist_ok=True)
    payload = encrypt_html(source_html, key, salt)
    with open(os.path.join(output_dir, "index.html"), "w", encoding="utf-8") as f:
        f.write(render_stage_html(payload, template=FRONT_TEMPLATE, unlock_js_path="unlock.js"))

    for asset in assets or []:
        with open(os.path.join("content", asset), "rb") as f:
            data = f.read()
        with open(os.path.join(output_dir, asset + ".enc"), "wb") as f:
            f.write(encrypt_asset(data, key))

    asset_note = f" (+{len(assets)} asset(s))" if assets else ""
    print(f"[+] front page passcode={passcode!r:20} -> /index.html{asset_note}")


def build_all(stages, output_dir: str = OUTPUT_DIR):
    results = []
    seen = set()
    for previous_answer, folder, source_html, assets in stages:
        if folder in seen:
            raise SystemExit(f"duplicate folder name {folder!r} in STAGES -- "
                             "each stage needs its own, or they overwrite each other.")
        seen.add(folder)
        build_stage(previous_answer, folder, source_html, assets, output_dir)
        results.append((previous_answer, folder))
        asset_note = f" (+{len(assets)} asset(s))" if assets else ""
        print(f"[+] answer={previous_answer!r:30} -> /{folder}/index.html{asset_note}")
    return results


def load(name: str) -> str:
    with open(os.path.join("content", name), "r", encoding="utf-8") as f:
        return f.read()


if __name__ == "__main__":
    # STAGES (answers + content) live in stages_local.py, which is gitignored
    # and never committed -- see stages_local.py.example for the format.
    try:
        from stages_local import STAGES, FRONT
    except ImportError:
        raise SystemExit(
            "stages_local.py not found (or missing STAGES/FRONT).\n"
            "Copy stages_local.py.example to stages_local.py and fill in "
            "your real answers/content. That file is gitignored -- keep it "
            "that way, it must never be committed."
        )
    build_front(*FRONT)
    build_all(STAGES)

    try:
        from stages_local import SHARE
    except ImportError:
        SHARE = None
    if SHARE:
        missing = [f for _, f in SHARE if not os.path.exists(os.path.join("content", f))]
        if missing:
            print(f"[!] SKIPPED share page -- missing from content/: {', '.join(missing)}")
            print("[!] The /share/ folder still holds the PREVIOUS build's files.")
        else:
            build_share(SHARE)
