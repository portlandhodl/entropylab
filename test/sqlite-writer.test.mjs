// Tests for src/js/sqlite-writer.js using Node's built-in test runner.
// Structural tests load the module in a function scope; database-level tests
// verify the generated files with Python's sqlite3 module (the real SQLite C
// library): PRAGMA integrity_check, schema readback, row dumps, and indexed
// point lookups. Run with `npm run test:sqlite-writer` or `npm test`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const read = (path) => readFileSync(join(root, path), "utf8");
const src = read("src/js/sqlite-writer.js");

const loadModule = () => new Function(`${src}\nreturn hodlSqliteWriter;`)();

const hex = (bytes) => Buffer.from(bytes).toString("hex");
const fromHex = (text) => new Uint8Array(Buffer.from(text, "hex"));

const PYTHON_SQLITE = (() => {
  const probe = spawnSync("python3", ["-c", "import sqlite3"], { stdio: "pipe" });
  return probe.status === 0;
})();

const sqliteVerify = (db, expectations) => {
  const dir = mkdtempSync(join(tmpdir(), "entropylab-sqlite-"));
  const file = join(dir, "test.db");
  writeFileSync(file, db);
  try {
    const out = execFileSync(
      "python3",
      [
        "-c",
        `
import sqlite3, json, sys
con = sqlite3.connect(sys.argv[1])
result = {
  "integrity": con.execute("PRAGMA integrity_check").fetchone()[0],
  "app_id": con.execute("PRAGMA application_id").fetchone()[0] & 0xFFFFFFFF,
  "schema": con.execute("SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY rowid").fetchall(),
  "rows": [[k.hex(), v.hex()] for k, v in con.execute("SELECT key, value FROM main")],
}
con.close()
print(json.dumps(result))
`,
        file,
      ],
      { encoding: "utf8", maxBuffer: 1 << 26 },
    );
    const report = JSON.parse(out);
    assert.equal(report.integrity, "ok", "PRAGMA integrity_check failed");
    if (expectations.appId !== undefined) assert.equal(report.appId ?? report.app_id, expectations.appId);
    if (expectations.rows) assert.deepEqual(report.rows, expectations.rows);
    if (expectations.schema) assert.deepEqual(report.schema, expectations.schema);
    return report;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
};

test("never generates network traffic", () => {
  assert.doesNotMatch(src, /\bfetch\b|XMLHttpRequest|WebSocket|RTCPeerConnection|sendBeacon|WebTransport/);
});

test("varint follows the SQLite 64-bit encoding", () => {
  const { varint } = loadModule();
  assert.equal(hex(varint(0)), "00");
  assert.equal(hex(varint(127)), "7f");
  assert.equal(hex(varint(128)), "8100");
  assert.equal(hex(varint(255)), "817f");
  assert.equal(hex(varint(16383)), "ff7f");
  assert.equal(hex(varint(16384)), "818000");
  assert.equal(hex(varint(0x1fffff)), "ffff7f");
  assert.equal(hex(varint(0xffffffffn)), "8fffffff7f");
  assert.equal(hex(varint(0xffffffffffffffffn)), "ffffffffffffffffff");
  assert.throws(() => varint(0x10000000000000000n), /out of range/);
});

test("record encoding matches SQLite serial types", () => {
  const { encodeRecord } = loadModule();
  // ["version", 280300]: text type 13+2*7=27, smallest int type 3 (i24); header 03 1b 03
  assert.equal(
    hex(encodeRecord(["version", 280300])),
    "031b03" + "76657273696f6e" + "0446ec",
  );
  // [null, 0, 1]: types 0, 8, 9; header 04 00 08 09, no body
  assert.equal(hex(encodeRecord([null, 0, 1])), "04000809");
  // BLOB type 12+2n; a 2-byte blob(0x0102)
  assert.equal(hex(encodeRecord([fromHex("0102")])), "0210" + "0102");
  // long blobs push the serial type varint past one byte
  const big = new Uint8Array(100);
  const encoded = encodeRecord([big]);
  assert.equal(encoded.length, 1 + 2 + 100); // header varint + 2-byte serial varint + body
});

test("bytewiseCompare is SQLite's BINARY collation", () => {
  const { bytewiseCompare } = loadModule();
  assert.ok(bytewiseCompare(fromHex("00"), fromHex("01")) < 0);
  assert.ok(bytewiseCompare(fromHex("ff"), fromHex("00")) > 0);
  assert.ok(bytewiseCompare(fromHex("01"), fromHex("0100")) < 0);
  assert.equal(bytewiseCompare(fromHex("abcd"), fromHex("abcd")), 0);
});

const MAIN_SQL = "CREATE TABLE main(key BLOB PRIMARY KEY NOT NULL, value BLOB NOT NULL)";

test("wallet-shaped database verifies against real SQLite", { skip: !PYTHON_SQLITE }, () => {
  const { createDatabase } = loadModule();
  const rows = [
    [fromHex("0776657273696f6e"), fromHex("ec460400")],
    [fromHex("0a6d696e76657273696f6e"), fromHex("ac970200")],
    [fromHex("05666c616773"), fromHex("0000000007000000")],
  ];
  const db = createDatabase({
    applicationId: 0xf9beb4d9,
    tables: [{ name: "main", sql: MAIN_SQL, primaryKey: 0, rows }],
  });
  assert.equal(db.length % 4096, 0);
  assert.equal(new TextDecoder().decode(db.subarray(0, 15)), "SQLite format 3");
  sqliteVerify(db, {
    appId: 0xf9beb4d9,
    schema: [
      ["table", "main", "main", MAIN_SQL],
      ["index", "sqlite_autoindex_main_1", "main", null],
    ],
    rows: rows.map(([k, v]) => [hex(k), hex(v)]),
  });
});

test("multi-page tables with an index interior pass integrity checks", { skip: !PYTHON_SQLITE }, () => {
  const { createDatabase } = loadModule();
  const rows = [];
  for (let i = 0; i < 400; i++) {
    const key = new Uint8Array(32);
    const value = new Uint8Array(150);
    key[0] = i & 0xff;
    key[31] = (i >> 8) & 0xff;
    value[0] = i & 0xff;
    rows.push([key, value]);
  }
  const db = createDatabase({
    applicationId: 0x0b110907,
    tables: [{ name: "main", sql: MAIN_SQL, primaryKey: 0, rows }],
  });
  const report = sqliteVerify(db, {
    appId: 0x0b110907,
    rows: rows.map(([k, v]) => [hex(k), hex(v)]),
  });
  assert.equal(report.rows.length, 400);
});

test("oversized cells throw instead of writing a corrupt file", () => {
  const { createDatabase } = loadModule();
  assert.throws(
    () =>
      createDatabase({
        tables: [{ name: "main", sql: MAIN_SQL, rows: [[new Uint8Array(1), new Uint8Array(4100)]] }],
      }),
    /overflow|inline limit/,
  );
});

test("empty tables are rejected", () => {
  const { createDatabase } = loadModule();
  assert.throws(() => createDatabase({ tables: [] }), /no tables/);
  assert.throws(() => createDatabase({ tables: [{ name: "main", sql: MAIN_SQL, rows: [] }] }), /no rows/);
});

test("build script and template ship the module", () => {
  const build = read("scripts/build.mjs");
  const template = read("src/index.html");
  assert.match(build, /sqlite-writer\.js/);
  assert.match(build, /JS_SQLITE_WRITER/);
  assert.match(template, /\/\*@@JS_SQLITE_WRITER@@\*\//);
});
