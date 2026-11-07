import assert from "node:assert/strict"
import { spawnSync } from "node:child_process"
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { delimiter, join } from "node:path"
import { after, test } from "node:test"

import { installPolkitShims, removePolkitShims } from "../src/shims.ts"

const testRoot = mkdtempSync(join(tmpdir(), "opencode-polkit-test-"))
const runtime = join(testRoot, "runtime")
const stubs = join(testRoot, "stubs")
mkdirSync(runtime)
mkdirSync(stubs)
process.env.XDG_RUNTIME_DIR = runtime
const shimDir = installPolkitShims()

after(() => {
  removePolkitShims(shimDir)
  rmSync(testRoot, { recursive: true, force: true })
})

interface Call {
  cmd: string
  args: string[]
}

interface Run {
  status: number | null
  stdout: string
  stderr: string
  calls: Call[]
}

/** Writes a stand-in that logs its argv and exits with the named variable's status. */
function writeStub(name: string, exitVariable: string, output = ""): void {
  const file = join(stubs, name)
  writeFileSync(
    file,
    `#!/bin/sh
printf 'cmd=%s\\n' '${name}' >> "$PI_TEST_LOG"
for arg in "$@"; do
	printf 'arg=%s\\n' "$arg" >> "$PI_TEST_LOG"
done
printf 'cwd=%s\\n' "$PWD" >> "$PI_TEST_LOG"
${output}
exit "\${${exitVariable}:-0}"
`,
  )
  chmodSync(file, 0o755)
}

writeStub("pkexec", "PI_TEST_PKEXEC_EXIT")
writeStub(
  "pkcheck",
  "PI_TEST_PKCHECK_EXIT",
  `case " $* " in
*" --list-temp "*) printf 'temp-marker\\n' ;;
esac`,
)
writeStub("pkaction", "PI_TEST_PKACTION_EXIT", "printf 'policy-marker\\n'")

function parseCalls(text: string): Call[] {
  const calls: Call[] = []
  for (const line of text.split("\n")) {
    if (line.startsWith("cmd=")) calls.push({ cmd: line.slice(4), args: [] })
    else if (line.startsWith("arg=")) calls.at(-1)?.args.push(line.slice(4))
  }
  return calls
}

function runShim(name: string, args: string[], env: Record<string, string> = {}): Run {
  const runDirectory = mkdtempSync(join(testRoot, "run-"))
  const log = join(runDirectory, "calls")
  writeFileSync(log, "")
  const result = spawnSync(join(shimDir, name), args, {
    encoding: "utf8",
    env: {
      ...process.env,
      PATH: `${stubs}${delimiter}${process.env.PATH ?? ""}`,
      PI_TEST_LOG: log,
      ...env,
    },
  })
  return {
    status: result.status,
    stdout: result.stdout,
    stderr: result.stderr,
    calls: parseCalls(readFileSync(log, "utf8")),
  }
}

function pkexec(run: Run): Call {
  const call = run.calls.find((candidate) => candidate.cmd === "pkexec")
  assert.ok(call, "pkexec was not called")
  return call
}

function pkcheck(run: Run): Call {
  const call = run.calls.find((candidate) => candidate.cmd === "pkcheck")
  assert.ok(call, "pkcheck was not called")
  return call
}

function commands(run: Run): string[] {
  return run.calls.map((call) => call.cmd)
}

test("sudo forwards a plain command to pkexec", () => {
  const run = runShim("sudo", ["id", "-u"])
  assert.equal(run.status, 0)
  assert.deepEqual(commands(run), ["pkexec"])
  assert.deepEqual(pkexec(run).args, ["id", "-u"])
  assert.equal(run.stderr, "")
})

test("sudo passes pkexec's exit status through", () => {
  const run = runShim("sudo", ["false"], { PI_TEST_PKEXEC_EXIT: "7" })
  assert.equal(run.status, 7)
})

test("sudo explains a dismissed pkexec dialog", () => {
  const run = runShim("sudo", ["true"], { PI_TEST_PKEXEC_EXIT: "126" })
  assert.equal(run.status, 126)
  assert.match(run.stderr, /dialog was dismissed/)
})

test("sudo -u USER and --user=USER become pkexec --user", () => {
  const short = runShim("sudo", ["-u", "bob", "id"])
  assert.equal(short.status, 0)
  assert.deepEqual(pkexec(short).args, ["--user", "bob", "id"])

  const attached = runShim("sudo", ["-ubob", "id"])
  assert.equal(attached.status, 0)
  assert.deepEqual(pkexec(attached).args, ["--user", "bob", "id"])

  const long = runShim("sudo", ["--user=alice", "id"])
  assert.equal(long.status, 0)
  assert.deepEqual(pkexec(long).args, ["--user", "alice", "id"])
})

test("bundled sudo options are parsed", () => {
  const run = runShim("sudo", ["-nu", "bob", "id"], { PI_TEST_PKCHECK_EXIT: "0" })
  assert.equal(run.status, 0)
  assert.deepEqual(commands(run), ["pkcheck", "pkexec"])
  assert.ok(!pkcheck(run).args.includes("--allow-user-interaction"))
  assert.deepEqual(pkexec(run).args, ["--user", "bob", "id"])
})

test("-- ends sudo option parsing", () => {
  const run = runShim("sudo", ["-u", "bob", "--", "id"])
  assert.equal(run.status, 0)
  assert.deepEqual(pkexec(run).args, ["--user", "bob", "id"])
})

test("sudo -H is a no-op", () => {
  const run = runShim("sudo", ["-H", "id"])
  assert.equal(run.status, 0)
  assert.deepEqual(pkexec(run).args, ["id"])
})

test("sudo -n reports a required password without running the command", () => {
  const run = runShim("sudo", ["-n", "true"], { PI_TEST_PKCHECK_EXIT: "2" })
  assert.equal(run.status, 1)
  assert.match(run.stderr, /a password is required/)
  assert.deepEqual(commands(run), ["pkcheck"])
  assert.ok(!pkcheck(run).args.includes("--allow-user-interaction"))
})

test("sudo -n runs the command when polkit grants it without asking", () => {
  const run = runShim("sudo", ["-n", "true"], { PI_TEST_PKCHECK_EXIT: "0" })
  assert.equal(run.status, 0)
  assert.deepEqual(commands(run), ["pkcheck", "pkexec"])
  assert.deepEqual(pkexec(run).args, ["true"])
})

test("sudo -n reports policy denial and a failed check", () => {
  const denied = runShim("sudo", ["-n", "true"], { PI_TEST_PKCHECK_EXIT: "1" })
  assert.equal(denied.status, 1)
  assert.match(denied.stderr, /polkit denies org\.freedesktop\.policykit\.exec/)

  const failed = runShim("sudo", ["-n", "true"], { PI_TEST_PKCHECK_EXIT: "127" })
  assert.equal(failed.status, 127)
  assert.match(failed.stderr, /polkit check failed \(status 127\)/)
})

test("sudo -v authenticates through the polkit agent", () => {
  const run = runShim("sudo", ["-v"], { PI_TEST_PKCHECK_EXIT: "0" })
  assert.equal(run.status, 0)
  assert.deepEqual(commands(run), ["pkcheck"])
  assert.ok(pkcheck(run).args.includes("--allow-user-interaction"))
})

test("sudo -v distinguishes denial, dismissal and no agent", () => {
  const denied = runShim("sudo", ["-v"], { PI_TEST_PKCHECK_EXIT: "1" })
  assert.equal(denied.status, 1)
  assert.match(denied.stderr, /did not authorize .*policy denies it, or authentication failed/)

  const dismissed = runShim("sudo", ["-v"], { PI_TEST_PKCHECK_EXIT: "3" })
  assert.equal(dismissed.status, 126)
  assert.match(dismissed.stderr, /dialog was dismissed/)

  const noAgent = runShim("sudo", ["-v"], { PI_TEST_PKCHECK_EXIT: "2" })
  assert.equal(noAgent.status, 1)
  assert.match(noAgent.stderr, /no polkit authentication agent answered/)
})

test("sudo -nv uses the non-interactive check", () => {
  const run = runShim("sudo", ["-nv"], { PI_TEST_PKCHECK_EXIT: "2" })
  assert.equal(run.status, 1)
  assert.match(run.stderr, /a password is required/)
  assert.ok(!pkcheck(run).args.includes("--allow-user-interaction"))
})

test("sudo -l prints the policy and this session's temporary authorizations", () => {
  const run = runShim("sudo", ["-l"])
  assert.equal(run.status, 0)
  assert.match(run.stdout, /policy-marker/)
  assert.match(run.stdout, /temp-marker/)
  assert.deepEqual(commands(run), ["pkaction", "pkcheck"])
  assert.deepEqual(pkcheck(run).args, ["--list-temp"])
})

test("sudo -k revokes polkit authorizations", () => {
  const run = runShim("sudo", ["-k"])
  assert.equal(run.status, 0)
  assert.deepEqual(run.calls, [{ cmd: "pkcheck", args: ["--revoke-temp"] }])
  assert.match(run.stderr, /revoked the temporary polkit authorizations/)
})

test("sudo -k COMMAND revokes and then runs", () => {
  const run = runShim("sudo", ["-k", "true"])
  assert.equal(run.status, 0)
  assert.deepEqual(commands(run), ["pkcheck", "pkexec"])
  assert.deepEqual(pkexec(run).args, ["true"])
})

test("sudo -s wraps the command in a shell", () => {
  const short = runShim("sudo", ["-s", "id", "-u"])
  assert.equal(short.status, 0)
  assert.deepEqual(pkexec(short).args, ["/bin/sh", "-c", "id -u"])

  const long = runShim("sudo", ["--shell", "id", "-u"])
  assert.equal(long.status, 0)
  assert.deepEqual(pkexec(long).args, ["/bin/sh", "-c", "id -u"])
})

test("sudo -E re-exports a named variable through argv", () => {
  const run = runShim("sudo", ["-E", "--preserve-env=FOO", "id", "-u"], { FOO: "a b" })
  assert.equal(run.status, 0)
  assert.deepEqual(pkexec(run).args, [
    "/bin/sh",
    "-c",
    `export 'FOO=a b'; exec "$@"`,
    "sh",
    "id",
    "-u",
  ])
})

test("su -c runs a shell command as the target user", () => {
  const run = runShim("su", ["-c", "id -u", "alice"])
  assert.equal(run.status, 0)
  assert.deepEqual(pkexec(run).args, [
    "--keep-cwd",
    "--user",
    "alice",
    "sh",
    "-c",
    "id -u",
  ])

  const attached = runShim("su", ["-cid -u", "alice"])
  assert.equal(attached.status, 0)
  assert.deepEqual(pkexec(attached).args, [
    "--keep-cwd",
    "--user",
    "alice",
    "sh",
    "-c",
    "id -u",
  ])
})

test("su -c defaults to root", () => {
  const run = runShim("su", ["-c", "id -u"])
  assert.equal(run.status, 0)
  assert.deepEqual(pkexec(run).args, ["--keep-cwd", "--user", "root", "sh", "-c", "id -u"])
})

test("su without -c is refused", () => {
  const run = runShim("su", ["-"])
  assert.equal(run.status, 64)
  assert.match(run.stderr, /login shell/)
  assert.deepEqual(run.calls, [])
})

test("doas forwards its options and command", () => {
  const run = runShim("doas", ["-u", "bob", "id"])
  assert.equal(run.status, 0)
  assert.deepEqual(pkexec(run).args, ["--user", "bob", "id"])

  const attached = runShim("doas", ["-ubob", "id"])
  assert.equal(attached.status, 0)
  assert.deepEqual(pkexec(attached).args, ["--user", "bob", "id"])
})

test("doas -n uses the non-interactive check", () => {
  const run = runShim("doas", ["-n", "true"], { PI_TEST_PKCHECK_EXIT: "2" })
  assert.equal(run.status, 1)
  assert.match(run.stderr, /a password is required/)
  assert.deepEqual(commands(run), ["pkcheck"])
})

test("options without a pkexec equivalent are refused", () => {
  for (const args of [["-i"], ["-S"], ["--askpass"], ["-e"]]) {
    const run = runShim("sudo", args)
    assert.equal(run.status, 64, args.join(" "))
    assert.deepEqual(run.calls, [], args.join(" "))
  }

  for (const name of ["sudoedit", "visudo"]) {
    const run = runShim(name, ["file"])
    assert.equal(run.status, 64, name)
    assert.deepEqual(run.calls, [], name)
  }
})

test("opencode-polkit-env quotes values as shell words", () => {
  const run = (args: string[]) =>
    spawnSync(join(shimDir, "opencode-polkit-env"), args, { encoding: "utf8" }).stdout

  assert.equal(run(["FOO=a b"]), "export 'FOO=a b'; ")
  assert.equal(run(["FOO=it's"]), "export 'FOO=it'\\''s'; ")
  assert.equal(run(["1FOO=bar"]), "")
})

test("opencode-polkit-env drops shim directories from PATH", () => {
  const result = spawnSync(
    join(shimDir, "opencode-polkit-env"),
    ["PATH=/tmp/opencode-polkit-abc:/usr/bin:/bin"],
    { encoding: "utf8" },
  )
  assert.equal(result.stdout, "export 'PATH=/usr/bin:/bin'; ")
})
