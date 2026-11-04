import { chmodSync, existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { isAbsolute, join } from "node:path"

/**
 * Exit status every shim uses for an invocation pkexec cannot express
 * (EX_USAGE). Distinct from pkexec's own 126 (dismissed) and 127 (not
 * authorized or failed) so callers can tell the two apart without reading
 * any output.
 */
export const SHIM_USAGE_EXIT = 64

/**
 * The sudo shim. Lives on PATH ahead of the real sudo, so the shell — not
 * this plugin — decides that `sudo` means this file. It forwards to pkexec
 * and never parses what pkexec prints: the exit status is the whole result.
 *
 * Only options with an exact pkexec equivalent are translated. Everything
 * else is refused with an actionable message rather than forwarded, because
 * pkexec would reject it with a message that does not say what to do instead.
 */
const SUDO_SHIM = `#!/bin/sh
# opencode-polkit: sudo shim. Routes sudo to pkexec so polkit can authorize it.
# Generated at plugin startup; do not edit.

fail() {
	printf 'opencode-polkit: %s\\n' "$1" >&2
	exit ${SHIM_USAGE_EXIT}
}

command -v pkexec >/dev/null 2>&1 || fail 'pkexec is not installed; install polkit'

user=
while [ $# -gt 0 ]; do
	case $1 in
	--)
		shift
		break
		;;
	-u)
		[ $# -ge 2 ] || fail 'sudo -u needs a username: -u USER PROGRAM'
		user=$2
		shift 2
		;;
	--user)
		[ $# -ge 2 ] || fail 'sudo --user needs a username: --user USER PROGRAM'
		user=$2
		shift 2
		;;
	-u?*)
		user=\${1#-u}
		[ -n "$user" ] || fail 'sudo -u needs a username: -u USER PROGRAM'
		shift
		;;
	--user=*)
		user=\${1#--user=}
		[ -n "$user" ] || fail 'sudo --user needs a username: --user USER PROGRAM'
		shift
		;;
	-n | --non-interactive)
		fail 'sudo -n is not supported: pkexec has no non-interactive mode, polkit decides whether authentication is needed. Drop -n.'
		;;
	-v | --validate | -k | --reset-timestamp | -K | --remove-timestamp)
		fail 'sudo credential caching does not exist under polkit; drop -v/-k.'
		;;
	-l | --list)
		fail 'sudo -l is not available under polkit; inspect policy with pkaction --verbose.'
		;;
	-e | --edit)
		fail 'sudoedit is not supported; write a temp file and run pkexec install or pkexec cp on it.'
		;;
	-i | --login | -s | --shell)
		fail 'sudo -i/-s opens a login shell; run pkexec bash instead.'
		;;
	-S | --stdin)
		fail 'sudo -S reads the password from stdin; pkexec authenticates through the polkit agent. Drop -S.'
		;;
	-A | --askpass)
		fail 'SUDO_ASKPASS does not apply to pkexec; drop -A.'
		;;
	-b | --background)
		fail 'sudo -b backgrounds the command; append & instead.'
		;;
	-E | --preserve-env | --preserve-env=* | -H | --set-home | -P | --preserve-groups | -N | --no-update)
		fail 'pkexec deliberately sanitizes the environment; drop -E/-H/-P.'
		;;
	-?*)
		fail "option has no pkexec equivalent: $1 (pkexec accepts --user, --keep-cwd, --disable-internal-agent)"
		;;
	*)
		break
		;;
	esac
done

# pkexec is silent when the dialog is dismissed (status 126), so say what the
# status means. Every other failure path already prints its own reason.
run_pkexec() {
	pkexec "$@"
	status=$?
	if [ $status -eq 126 ]; then
		printf 'opencode-polkit: %s\n' 'the polkit authentication dialog was dismissed' >&2
	fi
	exit $status
}

if [ -n "$user" ]; then
	run_pkexec --user "$user" "$@"
fi
run_pkexec "$@"
`

/** The doas shim: same contract, doas option grammar. */
const DOAS_SHIM = `#!/bin/sh
# opencode-polkit: doas shim. Routes doas to pkexec so polkit can authorize it.
# Generated at plugin startup; do not edit.

fail() {
	printf 'opencode-polkit: %s\\n' "$1" >&2
	exit ${SHIM_USAGE_EXIT}
}

command -v pkexec >/dev/null 2>&1 || fail 'pkexec is not installed; install polkit'

user=
while [ $# -gt 0 ]; do
	case $1 in
	--)
		shift
		break
		;;
	-u)
		[ $# -ge 2 ] || fail 'doas -u needs a username: -u USER PROGRAM'
		user=$2
		shift 2
		;;
	-u?*)
		user=\${1#-u}
		[ -n "$user" ] || fail 'doas -u needs a username: -u USER PROGRAM'
		shift
		;;
	-n)
		fail 'doas -n is not supported: pkexec has no non-interactive mode. Drop -n.'
		;;
	-s)
		fail 'doas -s opens a shell; run pkexec bash instead.'
		;;
	-C | -a | -L)
		fail "option has no pkexec equivalent: $1"
		;;
	-?*)
		fail "unknown doas option: $1"
		;;
	*)
		break
		;;
	esac
done

# pkexec is silent when the dialog is dismissed (status 126), so say what the
# status means. Every other failure path already prints its own reason.
run_pkexec() {
	pkexec "$@"
	status=$?
	if [ $status -eq 126 ]; then
		printf 'opencode-polkit: %s\n' 'the polkit authentication dialog was dismissed' >&2
	fi
	exit $status
}

if [ -n "$user" ]; then
	run_pkexec --user "$user" "$@"
fi
run_pkexec "$@"
`

/**
 * The su shim. `su -c` is the only form pkexec can express exactly: a command
 * run as the target user through a shell, in the current directory. Every
 * other form asks for a login shell, an environment, a shell binary, a group
 * or a terminal, none of which pkexec can honour, so it is refused instead.
 */
const SU_SHIM = `#!/bin/sh
# opencode-polkit: su shim. Routes su -c to pkexec so polkit can authorize it.
# Generated at plugin startup; do not edit.

fail() {
	printf 'opencode-polkit: %s\\n' "$1" >&2
	exit ${SHIM_USAGE_EXIT}
}

command -v pkexec >/dev/null 2>&1 || fail 'pkexec is not installed; install polkit'

user=
cmd=
has_cmd=
while [ $# -gt 0 ]; do
	case $1 in
	--)
		shift
		break
		;;
	-c)
		[ $# -ge 2 ] || fail 'su -c needs a command: su -c COMMAND [USER]'
		cmd=$2
		has_cmd=1
		shift 2
		;;
	-c?*)
		cmd=\${1#-c}
		has_cmd=1
		shift
		;;
	--command)
		[ $# -ge 2 ] || fail 'su --command needs a command: su --command COMMAND [USER]'
		cmd=$2
		has_cmd=1
		shift 2
		;;
	--command=*)
		cmd=\${1#--command=}
		has_cmd=1
		shift
		;;
	- | -l | --login)
		fail 'su starts a login shell; run pkexec bash instead.'
		;;
	-s | --shell | -s?* | --shell=*)
		fail 'su -s picks the shell; name the shell in the command: pkexec sh -c ...'
		;;
	-m | -p | --preserve-environment)
		fail 'pkexec deliberately sanitizes the environment; drop -m/-p.'
		;;
	-g | -G | --group | --supp-group | -g?* | -G?* | --group=* | --supp-group=*)
		fail 'su -g/-G switches groups; pkexec can only switch users.'
		;;
	-w | --whitelist-environment | -w?* | --whitelist-environment=*)
		fail 'su -w whitelists environment variables; pkexec sanitizes the environment.'
		;;
	-P | --pty)
		fail 'su --pty asks for a terminal; the shell tool has none.'
		;;
	-f | --fast)
		fail 'su -f is a shell flag; pass it to the shell in the command instead.'
		;;
	--session-command | --session-command=*)
		fail 'su --session-command keeps the session; pkexec always starts a new process.'
		;;
	-h | --help | -V | --version)
		fail "option has no pkexec equivalent: $1"
		;;
	-?*)
		fail "unknown su option: $1"
		;;
	*)
		[ -z "$user" ] || fail 'su passes arguments after the user name to the shell; use su -c COMMAND USER.'
		user=$1
		shift
		;;
	esac
done

# Operands after -- are the same user-then-nothing sequence.
while [ $# -gt 0 ]; do
	[ -z "$user" ] || fail 'su passes arguments after the user name to the shell; use su -c COMMAND USER.'
	user=$1
	shift
done

[ -n "$user" ] || user=root
[ -n "$has_cmd" ] || fail 'su without -c opens an interactive shell; run pkexec bash instead.'

# su keeps the working directory unless it is a login shell, and --keep-cwd is
# how pkexec does the same. pkexec is silent when the dialog is dismissed
# (status 126), so say what the status means.
pkexec --keep-cwd --user "$user" sh -c "$cmd"
status=$?
if [ $status -eq 126 ]; then
	printf 'opencode-polkit: %s\\n' 'the polkit authentication dialog was dismissed' >&2
fi
exit $status
`

/** sudoedit edits through sudo's own temporary-file flow; polkit has none. */
const SUDOEDIT_SHIM = `#!/bin/sh
printf 'opencode-polkit: sudoedit is not supported; write a temp file and run pkexec install or pkexec cp on it.\\n' >&2
exit ${SHIM_USAGE_EXIT}
`

/** visudo needs an interactive editor on a terminal the shell tool does not have. */
const VISUDO_SHIM = `#!/bin/sh
printf 'opencode-polkit: visudo needs an interactive terminal; validate a candidate file with pkexec visudo -c -f FILE instead.\\n' >&2
exit ${SHIM_USAGE_EXIT}
`

/** File name → script body. Names must match the commands being redirected. */
const POLKIT_SHIM_SCRIPTS: Record<string, string> = {
  sudo: SUDO_SHIM,
  doas: DOAS_SHIM,
  su: SU_SHIM,
  sudoedit: SUDOEDIT_SHIM,
  visudo: VISUDO_SHIM,
}

/**
 * Writes the shim scripts into a fresh private directory and returns it.
 * The caller prepends this directory to PATH; the shell then resolves
 * `sudo`/`doas`/`su` to these files instead of the system ones. The directory
 * is 0700 so no other local user can rewrite the scripts.
 */
export function installPolkitShims(): string {
  const directory = mkdtempSync(join(shimBaseDirectory(), "opencode-polkit-"))
  for (const [name, script] of Object.entries(POLKIT_SHIM_SCRIPTS)) {
    const file = join(directory, name)
    writeFileSync(file, script)
    // writeFileSync's mode is filtered by umask, so set it explicitly.
    chmodSync(file, 0o755)
  }
  return directory
}

/**
 * Where shim directories live. Prefers the login session's runtime directory,
 * which the system clears on logout, over /tmp which keeps leftovers.
 */
function shimBaseDirectory(): string {
  const runtime = process.env.XDG_RUNTIME_DIR
  return runtime && isAbsolute(runtime) && existsSync(runtime) ? runtime : tmpdir()
}

/** Deletes a directory created by installPolkitShims. */
export function removePolkitShims(directory: string): void {
  rmSync(directory, { recursive: true, force: true })
}
