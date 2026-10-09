// The image smoke helpers put container output in their errors, and CI keeps
// only the first 16 KiB of a failure message. Finding 976 misread such a cut log
// as a Doctor stall: the wrapper's stderr and the real failure came after the
// cut. These cases drive the helper against a stand-in docker binary.
import assert from "node:assert/strict";
import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test, { after } from "node:test";

const reporterMessageLimit = 16_384;

const root = await mkdtemp(join(tmpdir(), "oce-runtime-image-failure-output-"));
after(() => rm(root, { recursive: true, force: true }));
const fakeDocker = join(root, "docker");
await writeFile(
  fakeDocker,
  `#!${process.execPath}
const [command] = process.argv.slice(2);
if (command === "inspect") {
  process.stdout.write("false 1\\n");
} else if (command === "logs") {
  process.stdout.write("first doctor line\\n");
  for (let index = 0; index < 400; index += 1) {
    process.stdout.write(\`doctor check \${index}: \${"x".repeat(60)}\\n\`);
  }
  process.stderr.write("Migrating agent databases\\nwrapper failed: final stderr line\\n");
} else if (command === "run") {
  process.stdout.write("fake-container-id\\n");
}
`,
);
await chmod(fakeDocker, 0o700);

// The helper reads both at import.
process.env.OCC_DOCKER_BIN = fakeDocker;
process.env.OCC_TEST_RUNTIME_IMAGE = "localhost/oce/runtime:failure-output-test";
const { outputTail, runGatewaySmoke } = await import("../helpers/runtime-image-startup.mjs");

test("outputTail keeps short output and the end of long output", () => {
  assert.equal(outputTail("short output", 64), "short output");
  const output = `${"a".repeat(100)}${"b".repeat(20)}`;
  assert.equal(outputTail(output, 20), `[... 100 earlier chars omitted ...]\n${"b".repeat(20)}`);
});

test("a Gateway smoke failure with over 16 KiB of logs keeps their final lines within the CI cut", async (t) => {
  const error = await runGatewaySmoke(t, "openclaw").then(
    () => assert.fail("the Gateway smoke should fail when the container exits"),
    (failure) => failure,
  );
  // What the CI reporter keeps of the message.
  const reported = error.message.slice(0, reporterMessageLimit);
  assert.match(reported, /^Gateway container exited before readiness with code 1\.\n/);
  assert.match(reported, /Migrating agent databases\nwrapper failed: final stderr line/);
  assert.match(reported, /doctor check 399: x+\n/);
  assert.match(reported, /\[\.\.\. \d+ earlier chars omitted \.\.\.\]/);
  assert.doesNotMatch(reported, /first doctor line/);
  assert.ok(
    error.message.length <= reporterMessageLimit,
    `message is ${error.message.length} chars`,
  );
});
