// Run with: node --test tests/
import assert from "node:assert/strict";
import test from "node:test";

import {
  createSession,
  decryptVault,
  encryptVault,
  isEncryptedBlob,
} from "../js/vault-crypto.js";

const PLAINTEXT = JSON.stringify({ Ebay: { email: "me@example.com", password: "S3cret!" } });

test("encrypts and decrypts with the right master password", async () => {
  const session = await createSession("correct horse battery");
  const blob = await encryptVault(PLAINTEXT, session);
  assert.ok(isEncryptedBlob(blob));

  const result = await decryptVault(blob, "correct horse battery");
  assert.equal(result.plaintext, PLAINTEXT);
});

test("the stored blob does not contain the plaintext", async () => {
  const session = await createSession("correct horse battery");
  const blob = await encryptVault(PLAINTEXT, session);
  const stored = JSON.stringify(blob);
  assert.ok(!stored.includes("S3cret"));
  assert.ok(!stored.includes("me@example.com"));
  assert.ok(!stored.includes("Ebay"));
});

test("a wrong master password is rejected", async () => {
  const session = await createSession("correct horse battery");
  const blob = await encryptVault(PLAINTEXT, session);
  await assert.rejects(() => decryptVault(blob, "wrong password"), /Wrong master password/);
});

test("tampered data is rejected", async () => {
  const session = await createSession("correct horse battery");
  const blob = await encryptVault(PLAINTEXT, session);
  const bytes = Buffer.from(blob.data, "base64");
  bytes[0] ^= 0xff;
  const tampered = { ...blob, data: bytes.toString("base64") };
  await assert.rejects(() => decryptVault(tampered, "correct horse battery"), /Wrong master password|damaged/);
});

test("every save uses a fresh IV, and the session key keeps working", async () => {
  const session = await createSession("correct horse battery");
  const first = await encryptVault(PLAINTEXT, session);
  const second = await encryptVault(PLAINTEXT, session);
  assert.notEqual(first.iv, second.iv);
  assert.notEqual(first.data, second.data);
  const result = await decryptVault(second, "correct horse battery");
  assert.equal(result.plaintext, PLAINTEXT);
});

test("a session returned by decryptVault can save again", async () => {
  const session = await createSession("correct horse battery");
  const blob = await encryptVault(PLAINTEXT, session);
  const opened = await decryptVault(blob, "correct horse battery");
  const newBlob = await encryptVault('{"New":{"email":"e","password":"p"}}', opened.session);
  const again = await decryptVault(newBlob, "correct horse battery");
  assert.equal(again.plaintext, '{"New":{"email":"e","password":"p"}}');
});

test("unsupported iteration counts are refused", async () => {
  const session = await createSession("correct horse battery");
  const blob = await encryptVault(PLAINTEXT, session);
  await assert.rejects(() => decryptVault({ ...blob, iterations: 10 }, "correct horse battery"), /unsupported/);
  await assert.rejects(() => decryptVault({ ...blob, iterations: 900_000_000 }, "correct horse battery"), /unsupported/);
});

test("a plain data.json is not mistaken for an encrypted blob", () => {
  assert.equal(isEncryptedBlob({ Ebay: { email: "a", password: "b" } }), false);
  assert.equal(isEncryptedBlob(null), false);
  assert.equal(isEncryptedBlob([]), false);
});
