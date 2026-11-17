// MyPass — page logic.
//
// Python (Pyodide, from py/core.py) does the password and data logic.
// JavaScript draws the page and encrypts the vault with Web Crypto.
import { createSession, decryptVault, encryptVault, isEncryptedBlob } from "./vault-crypto.js";

// Where Pyodide (Python for the browser) is loaded from. To update it, change the version here.
const PYODIDE_BASE = "https://cdn.jsdelivr.net/pyodide/v314.0.8/full/";

const STORAGE_KEY = "mypass.vault.v1";
const THEME_KEY = "mypass.theme";
const MIN_MASTER_LENGTH = 8;
const IDLE_LOCK_MS = 5 * 60 * 1000;

const $ = (id) => document.getElementById(id);
const screens = { loading: $("screen-loading"), lock: $("screen-lock"), vault: $("screen-vault") };

// State that only exists while the vault is unlocked.
let py = null;          // the Python module (py/core.py)
let session = null;     // { key, salt, iterations } from vault-crypto.js
let vaultJson = "{}";   // the decrypted vault, as JSON text
let lockMode = "create"; // "create" (first visit) or "unlock"
let idleTimer = null;

// ---------------------------- helpers ----------------------------
function showScreen(name) {
  for (const [key, el] of Object.entries(screens)) el.hidden = key !== name;
}

/** Python errors arrive as a long traceback: keep only the readable last line. */
function errorMessage(err) {
  const text = String(err?.message ?? err).trim();
  const lastLine = text.split("\n").pop();
  return lastLine.replace(/^\w*(Error|Exception):\s*/, "");
}

function readStored() {
  try { return localStorage.getItem(STORAGE_KEY); } catch { return null; }
}

function setStatus(text, kind = "") {
  const el = $("status");
  el.textContent = text;
  el.className = `message ${kind}`.trim();
}

// ---------------------------- theme ----------------------------
$("theme-toggle").addEventListener("click", () => {
  const next = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
  document.documentElement.dataset.theme = next;
  try { localStorage.setItem(THEME_KEY, next); } catch { /* storage blocked: the choice just won't persist */ }
});

// ---------------------------- Python ----------------------------
async function loadPython() {
  const { loadPyodide } = await import(`${PYODIDE_BASE}pyodide.mjs`);
  const pyodide = await loadPyodide({ indexURL: PYODIDE_BASE });

  const response = await fetch("py/core.py");
  if (!response.ok) throw new Error(`Couldn't read py/core.py (HTTP ${response.status}).`);
  pyodide.FS.mkdirTree("/mypass");
  pyodide.FS.writeFile("/mypass/core.py", await response.text());
  pyodide.runPython("import sys; sys.path.insert(0, '/mypass')");
  return pyodide.pyimport("core");
}

async function boot() {
  showScreen("loading");
  $("loading-busy").hidden = false;
  $("loading-failed").hidden = true;
  try {
    py = await loadPython();
  } catch (err) {
    console.error(err);
    $("loading-busy").hidden = true;
    $("loading-failed").hidden = false;
    $("loading-error").textContent = location.protocol === "file:"
      ? "Open the page through a local server (see the README) instead of double-clicking the file."
      : `${errorMessage(err)} Check your internet connection and try again.`;
    return;
  }
  showLockScreen();
}
$("loading-retry").addEventListener("click", boot);

// ---------------------------- master password ----------------------------
function showLockScreen(notice = "") {
  lockMode = readStored() ? "unlock" : "create";
  const creating = lockMode === "create";

  $("lock-title").textContent = creating ? "Create your master password" : "Unlock your vault";
  $("lock-hint").textContent = notice || (creating
    ? `It encrypts everything you save. Use at least ${MIN_MASTER_LENGTH} characters, and don't forget it: there is no way to recover it.`
    : "Type your master password to open your saved passwords.");
  $("lock-submit").textContent = creating ? "Create vault" : "Unlock";
  $("master").autocomplete = creating ? "new-password" : "current-password";
  $("confirm-group").hidden = !creating;
  $("master-confirm").required = creating;
  $("reset-vault").hidden = creating;
  $("lock-error").hidden = true;
  $("master").value = "";
  $("master-confirm").value = "";
  showScreen("lock");
  $("master").focus();
}

function showLockError(text) {
  const el = $("lock-error");
  el.textContent = text;
  el.hidden = false;
}

$("lock-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  $("lock-error").hidden = true;
  const password = $("master").value;
  const button = $("lock-submit");
  const label = button.textContent;
  button.disabled = true;
  button.textContent = "Working…";

  try {
    if (lockMode === "create") {
      if (password.length < MIN_MASTER_LENGTH) throw new Error(`Use at least ${MIN_MASTER_LENGTH} characters.`);
      if (password !== $("master-confirm").value) throw new Error("The two passwords don't match.");
      session = await createSession(password);
      vaultJson = "{}";
      await persist(vaultJson);
    } else {
      let blob;
      try { blob = JSON.parse(readStored()); } catch { blob = null; }
      const opened = await decryptVault(blob, password);
      py.list_websites_json(opened.plaintext); // validates the decrypted data
      session = opened.session;
      vaultJson = opened.plaintext;
    }
    enterVault();
  } catch (err) {
    session = null;
    vaultJson = "{}";
    showLockError(errorMessage(err));
  } finally {
    button.disabled = false;
    button.textContent = label;
  }
});

$("reset-vault").addEventListener("click", () => {
  const ok = confirm("This permanently erases every password saved in this browser. Export a backup first if you might need it. Erase everything?");
  if (!ok) return;
  try { localStorage.removeItem(STORAGE_KEY); } catch { /* nothing to do */ }
  showLockScreen("The vault was erased. Create a new master password.");
});

/** Encrypt the vault and save it in this browser. Throws if the browser refuses. */
async function persist(json) {
  const blob = await encryptVault(json, session);
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(blob));
  } catch (err) {
    throw new Error(`The browser couldn't store the data (${err.name}).`);
  }
}

function enterVault() {
  $("master").value = "";
  $("master-confirm").value = "";
  clearForm();
  setStatus("");
  renderEntries();
  showScreen("vault");
  startIdleTimer();
  $("website").focus();
}

function lock(notice = "") {
  clearTimeout(idleTimer);
  session = null;
  vaultJson = "{}";
  clearForm();
  showLockScreen(notice);
}

function startIdleTimer() {
  clearTimeout(idleTimer);
  idleTimer = setTimeout(() => lock("Locked after 5 minutes without activity."), IDLE_LOCK_MS);
}
for (const type of ["pointerdown", "keydown"]) {
  document.addEventListener(type, () => { if (session) startIdleTimer(); });
}
$("lock-btn").addEventListener("click", () => lock());

// ---------------------------- the form ----------------------------
function clearForm() {
  $("website").value = "";
  $("email").value = "";
  $("password").value = "";
  setPasswordVisible(false);
  updateStrength();
}

function fillForm(entry) {
  $("website").value = entry.website;
  $("email").value = entry.email;
  $("password").value = entry.password;
  updateStrength();
}

function setPasswordVisible(visible) {
  $("password").type = visible ? "text" : "password";
  const toggle = $("toggle-password");
  toggle.setAttribute("aria-pressed", String(visible));
  toggle.setAttribute("aria-label", visible ? "Hide password" : "Show password");
}
$("toggle-password").addEventListener("click", () => {
  setPasswordVisible($("password").type === "password");
});

function updateStrength() {
  const password = $("password").value;
  const meter = $("strength-meter");
  if (!password) {
    meter.dataset.score = "";
    $("strength-label").textContent = "";
    return;
  }
  const { score, label } = JSON.parse(py.strength_json(password));
  meter.dataset.score = String(score);
  $("strength-label").textContent = label;
}
$("password").addEventListener("input", updateStrength);

async function copyToClipboard(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

$("generate-btn").addEventListener("click", async () => {
  $("password").value = py.generate_password();
  setPasswordVisible(true);
  updateStrength();
  const copied = await copyToClipboard($("password").value);
  setStatus(copied ? "Password generated and copied to the clipboard." : "Password generated.", "ok");
});

$("copy-btn").addEventListener("click", async () => {
  if (!$("password").value) return setStatus("There is no password to copy yet.", "error");
  const copied = await copyToClipboard($("password").value);
  setStatus(copied ? "Password copied to the clipboard." : "Couldn't copy automatically. Show the password and copy it by hand.", copied ? "ok" : "error");
});

$("search-btn").addEventListener("click", () => {
  const website = $("website").value.trim();
  if (!website) return setStatus("Type a website to search for.", "error");
  try {
    const entry = JSON.parse(py.find_entry_json(vaultJson, website));
    if (!entry) return setStatus(`No details for ${website} exist.`, "error");
    fillForm(entry);
    setStatus(`Loaded the details for ${entry.website}.`, "ok");
  } catch (err) {
    setStatus(errorMessage(err), "error");
  }
});

$("entry-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    const website = $("website").value.trim();
    const next = py.add_entry_json(vaultJson, website, $("email").value, $("password").value);
    await persist(next);
    vaultJson = next;
    $("website").value = "";
    $("password").value = "";
    setPasswordVisible(false);
    updateStrength();
    renderEntries();
    setStatus(`Saved the details for ${website}.`, "ok");
    $("website").focus();
  } catch (err) {
    setStatus(errorMessage(err), "error");
  }
});

// ---------------------------- saved sites ----------------------------
function renderEntries() {
  const vault = JSON.parse(vaultJson);
  const websites = JSON.parse(py.list_websites_json(vaultJson));
  const list = $("entries");
  list.replaceChildren();

  for (const website of websites) {
    const item = document.createElement("li");

    const open = document.createElement("button");
    open.type = "button";
    open.className = "site";
    const name = document.createElement("span");
    name.className = "site-name";
    name.textContent = website; // textContent, never innerHTML: names come from the user
    const email = document.createElement("span");
    email.className = "site-email";
    email.textContent = vault[website].email || "No email saved";
    open.append(name, email);
    open.addEventListener("click", () => {
      fillForm({ website, ...vault[website] });
      setStatus(`Loaded the details for ${website}.`, "ok");
    });

    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "icon-btn delete-btn";
    remove.setAttribute("aria-label", `Delete ${website}`);
    remove.innerHTML = '<svg class="icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M4 7h16M10 11v6M14 11v6M6 7l1 13h10l1-13M9 7V4h6v3"/></svg>';
    remove.addEventListener("click", () => deleteEntry(website));

    item.append(open, remove);
    list.append(item);
  }

  $("saved-count").textContent = String(websites.length);
  $("entries-empty").hidden = websites.length > 0;
}

async function deleteEntry(website) {
  if (!confirm(`Delete the saved details for ${website}?`)) return;
  try {
    const next = py.remove_entry_json(vaultJson, website);
    await persist(next);
    vaultJson = next;
    renderEntries();
    setStatus(`Deleted ${website}.`, "ok");
  } catch (err) {
    setStatus(errorMessage(err), "error");
  }
}

// ---------------------------- export / import ----------------------------
$("export-btn").addEventListener("click", () => {
  const stored = readStored();
  if (!stored) return setStatus("There is nothing to export yet.", "error");
  const url = URL.createObjectURL(new Blob([stored], { type: "application/json" }));
  const link = document.createElement("a");
  link.href = url;
  link.download = `mypass-backup-${new Date().toISOString().slice(0, 10)}.json`;
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  setStatus("Encrypted backup downloaded. You'll need your master password to open it.", "ok");
});

$("import-btn").addEventListener("click", () => $("import-file").click());

function askBackupPassword() {
  const dialog = $("backup-dialog");
  return new Promise((resolve) => {
    $("backup-password").value = "";
    dialog.returnValue = "";
    dialog.addEventListener(
      "close",
      () => resolve(dialog.returnValue === "ok" ? $("backup-password").value : null),
      { once: true },
    );
    dialog.showModal();
  });
}

$("import-file").addEventListener("change", async (event) => {
  const file = event.target.files[0];
  event.target.value = ""; // lets the same file be picked again later
  if (!file) return;

  try {
    let text = await file.text();

    let parsed = null;
    try { parsed = JSON.parse(text); } catch { /* py.import_json will explain what's wrong */ }

    if (isEncryptedBlob(parsed)) {
      const password = await askBackupPassword();
      if (password === null) return setStatus("Import cancelled.");
      text = (await decryptVault(parsed, password)).plaintext;
    }

    const result = JSON.parse(py.import_json(vaultJson, text));
    const next = JSON.stringify(result.vault);
    await persist(next);
    vaultJson = next;
    renderEntries();
    setStatus(`Imported ${result.imported} ${result.imported === 1 ? "entry" : "entries"}.`, "ok");
  } catch (err) {
    setStatus(errorMessage(err), "error");
  }
});

// ---------------------------- go ----------------------------
boot();
