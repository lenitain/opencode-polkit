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

/** The action pkexec checks; the checks below ask polkit about the same one. */
const POLKIT_ACTION = "org.freedesktop.policykit.exec"

/**
 * The part every shim starts with: one refusal helper, and a check that the two
 * polkit tools exist at all.
 */
const SHIM_PRELUDE = `fail() {
	printf 'opencode-polkit: %s\\n' "$1" >&2
	exit ${SHIM_USAGE_EXIT}
}

command -v pkexec >/dev/null 2>&1 || fail 'pkexec is not installed; install polkit'
command -v pkcheck >/dev/null 2>&1 || fail 'pkcheck is not installed; install polkit'
`

/**
 * The checks that answer what sudo's timestamp file used to answer, plus the
 * pkexec wrapper. Only exit statuses are read: pkcheck's messages and its
 * `polkit.result` detail are localised and addressed to humans, so parsing them
 * would break on the next locale or polkit release.
 */
const SHIM_CHECKS = `# The action checked below. pkexec uses it by default; a site can install
# another action selected by org.freedesktop.policykit.exec.path/argv1, whose
# rules these checks do not see.
ACTION=${POLKIT_ACTION}

# pkcheck(1) warns that a bare pid races with pid reuse, so pin the start time.
subject() {
	started=$(awk '{ print $22 }' /proc/$$/stat 2>/dev/null)
	if [ -n "$started" ]; then
		printf '%s,%s,%s' "$$" "$started" "$(id -u)"
	else
		printf '%s' "$$"
	fi
}

# 0 grants the action without asking anyone, 2 requires authentication,
# 1 refuses it. pkcheck's own 126 (usage) and 127 (error) pass through.
check_without_prompt() {
	pkcheck --action-id "$ACTION" --process "$(subject)" >/dev/null 2>&1
}

# The same check with the desktop agent allowed to answer. An agent that still
# holds the password answers without a dialog, which is why a 0 here also means
# the next pkexec runs as root without asking.
check_with_prompt() {
	pkcheck --action-id "$ACTION" --process "$(subject)" --allow-user-interaction >/dev/null 2>&1
}

# -n means "run only if no one has to be asked". polkit cannot say whether the
# agent would answer from its cache, so a 2 is reported as needing a password
# and the command is not run: that is what -n promises, in both directions.
require_without_prompt() {
	if [ -n "$noninteractive" ]; then
		check_without_prompt
		status=$?
		case $status in
		0)
			return 0
			;;
		1)
			printf 'opencode-polkit: %s: polkit denies %s to this process\\n' "$PROG" "$ACTION" >&2
			exit 1
			;;
		2)
			printf '%s: a password is required (polkit requires authentication for %s; drop -n to let the desktop agent answer, which it may do from its cache)\\n' "$PROG" "$ACTION" >&2
			exit 1
			;;
		*)
			printf 'opencode-polkit: %s: polkit check failed (status %s)\\n' "$PROG" "$status" >&2
			exit 127
			;;
		esac
	fi
	return 0
}

# pkexec is silent when the dialog is dismissed (status 126), so say what the
# status means. Every other failure path already prints its own reason.
run_pkexec() {
	pkexec "$@"
	status=$?
	if [ $status -eq 126 ]; then
		printf 'opencode-polkit: %s\\n' 'the polkit authentication dialog was dismissed' >&2
	fi
	exit $status
}
`

/**
 * The sudo shim. Lives on PATH ahead of the real sudo, so the shell — not this
 * plugin — decides that `sudo` means this file. It forwards to pkexec and
 * never parses what pkexec prints: the exit status is the whole result.
 *
 * Options are handled in four ways, and only the last one refuses. Those whose
 * effect pkexec already has (`-H`, `-N`, `-P`) are accepted as no-ops; those
 * polkit answers better than a run (`-n`, `-v`, `-l`, `-k`) become checks; those
 * a wrapper can express (`-s COMMAND`, `-E`, `-b`) are translated; the rest,
 * which need a terminal or a password channel polkit does not have, are refused
 * with one line naming the alternative.
 */
const SUDO_SHIM = `#!/bin/sh
# opencode-polkit: sudo shim. Routes sudo to pkexec so polkit can authorize it.
# Generated at plugin startup; do not edit.

${SHIM_PRELUDE}
${SHIM_CHECKS}
PROG=sudo
user=
noninteractive=
preserve=
preserve_names=
background=
mode=

while [ $# -gt 0 ]; do
	case $1 in
	--)
		shift
		break
		;;
	--user)
		[ $# -ge 2 ] || fail 'sudo --user needs a username: --user USER PROGRAM'
		user=$2
		shift 2
		;;
	--user=*)
		user=\${1#--user=}
		shift
		;;
	--non-interactive)
		noninteractive=1
		shift
		;;
	--preserve-env)
		preserve=1
		shift
		;;
	--preserve-env=*)
		preserve=1
		preserve_names=\${1#--preserve-env=}
		shift
		;;
	--set-home | --no-update | --preserve-groups)
		shift
		;;
	--list)
		mode=list
		shift
		;;
	--validate)
		mode=validate
		shift
		;;
	--reset-timestamp | --remove-timestamp)
		mode=revoke
		shift
		;;
	--background)
		background=1
		shift
		;;
	--help)
		mode=help
		shift
		;;
	--version)
		mode=version
		shift
		;;
	--stdin | --askpass | --edit | --login)
		case $1 in
		--edit)
			fail 'sudoedit is not supported; write a temp file and run pkexec install or pkexec cp on it.'
			;;
		--stdin)
			fail 'sudo -S reads the password from stdin; pkexec authenticates through the polkit agent. Drop -S.'
			;;
		--askpass)
			fail 'SUDO_ASKPASS does not apply to pkexec; drop -A.'
			;;
		*)
			fail 'sudo -i opens a login shell; run pkexec bash instead.'
			;;
		esac
		;;
	--shell)
		mode=shell
		shift
		;;
	--*)
		fail "option has no pkexec equivalent: $1 (pkexec accepts --user, --keep-cwd, --disable-internal-agent)"
		;;
	-?*)
		rest=\${1#-}
		shift
		while [ -n "$rest" ]; do
			letter=\${rest%"\${rest#?}"}
			rest=\${rest#?}
			case $letter in
			u)
				if [ -n "$rest" ]; then
					user=$rest
					rest=
				else
					[ $# -ge 1 ] || fail 'sudo -u needs a username: -u USER PROGRAM'
					user=$1
					shift
				fi
				;;
			n)
				noninteractive=1
				;;
			E)
				preserve=1
				;;
			H | N | P)
				# pkexec already sets HOME, keeps no timestamp and leaves groups alone.
				;;
			b)
				background=1
				;;
			l)
				mode=list
				;;
			v)
				mode=validate
				;;
			k | K)
				mode=revoke
				;;
			s)
				mode=shell
				;;
			h)
				mode=help
				;;
			V)
				mode=version
				;;
			i)
				fail 'sudo -i opens a login shell; run pkexec bash instead.'
				;;
			e)
				fail 'sudoedit is not supported; write a temp file and run pkexec install or pkexec cp on it.'
				;;
			S)
				fail 'sudo -S reads the password from stdin; pkexec authenticates through the polkit agent. Drop -S.'
				;;
			A)
				fail 'SUDO_ASKPASS does not apply to pkexec; drop -A.'
				;;
			*)
				fail "option has no pkexec equivalent: -$letter (pkexec accepts --user, --keep-cwd, --disable-internal-agent)"
				;;
			esac
		done
		;;
	*)
		break
		;;
	esac
done

# --help and --version describe the binary, not the authorisation, so nothing is
# elevated: answering them exactly keeps scripts that probe sudo working.
if [ "$mode" = help ] || [ "$mode" = version ]; then
	for candidate in /usr/bin/sudo /bin/sudo /usr/local/bin/sudo; do
		[ -x "$candidate" ] || continue
		if [ "$mode" = help ]; then
			exec "$candidate" --help
		fi
		exec "$candidate" --version
	done
	fail 'the real sudo is not installed, so --help and --version cannot be answered'
fi

# -l reports the policy polkit will apply and the authorizations this session
# already holds. Both halves are local and never prompt.
if [ "$mode" = list ]; then
	pkaction --action-id "$ACTION" --verbose || exit 127
	printf '\\nopencode-polkit: temporary authorizations in this session\\n'
	pkcheck --list-temp || exit 127
	exit 0
fi

# -v asks the same question sudo -v asks: can authentication succeed right now?
if [ "$mode" = validate ]; then
	if [ -n "$noninteractive" ]; then
		check_without_prompt
	else
		check_with_prompt
	fi
	status=$?
	case $status in
	0)
		exit 0
		;;
	1)
		printf 'opencode-polkit: sudo: polkit did not authorize %s (the policy denies it, or authentication failed)\\n' "$ACTION" >&2
		exit 1
		;;
	2)
		if [ -n "$noninteractive" ]; then
			printf 'sudo: a password is required (polkit requires authentication for %s)\\n' "$ACTION" >&2
		else
			printf 'opencode-polkit: sudo: no polkit authentication agent answered\\n' >&2
		fi
		exit 1
		;;
	3)
		printf 'opencode-polkit: %s\\n' 'the polkit authentication dialog was dismissed' >&2
		exit 126
		;;
	*)
		printf 'opencode-polkit: sudo: polkit check failed (status %s)\\n' "$status" >&2
		exit 127
		;;
	esac
fi

# -k drops what polkit itself recorded. The password a desktop agent keeps is
# the agent's, not polkit's, so say that it stays.
if [ "$mode" = revoke ]; then
	pkcheck --revoke-temp || exit 127
	if [ $# -eq 0 ]; then
		printf 'opencode-polkit: %s\\n' 'revoked the temporary polkit authorizations; a desktop agent that caches the password keeps its own copy, so the next command may still not ask' >&2
		exit 0
	fi
fi

# -E: pkexec strips the environment, so name the variables again inside the shell
# that runs the command. Entries reach the helper as arguments, so spaces, quotes
# and newlines survive exactly; the helper also drops every shim directory from
# PATH, so an elevated command cannot resolve sudo back to a shim.
shim_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd 2>/dev/null)
env_helper=$shim_dir/opencode-polkit-env
[ -x "$env_helper" ] || fail "the opencode-polkit environment helper is missing: $env_helper"

# Runs in the caller's shell, never in a command substitution: an exit there
# would only end the subshell, and a name reaches eval below, so it must be a
# name before that happens.
check_preserve() {
	if [ -z "$preserve_names" ]; then
		command -v xargs >/dev/null 2>&1 || fail '-E needs xargs to forward the environment; name the variables instead: --preserve-env=NAME[,NAME...]'
		return 0
	fi
	old_ifs=$IFS
	IFS=,
	for name in $preserve_names; do
		case $name in
		'' | [0-9]* | *[!A-Za-z0-9_]*)
			IFS=$old_ifs
			fail "not a variable name: $name"
			;;
		esac
	done
	IFS=$old_ifs
}

export_prefix() {
	if [ -n "$preserve_names" ]; then
		set --
		old_ifs=$IFS
		IFS=,
		for name in $preserve_names; do
			is_set=
			eval "is_set=\\\${$name+yes}"
			[ -n "$is_set" ] || continue
			eval "value=\\\${$name}"
			set -- "$@" "$name=$value"
		done
		IFS=$old_ifs
		"$env_helper" "$@"
		return
	fi
	env -0 | xargs -0 -n 64 "$env_helper"
}

require_without_prompt

[ $# -gt 0 ] || fail 'sudo needs a command: sudo [OPTIONS] COMMAND (an interactive shell needs a terminal)'

# -s runs the command through a shell, which pkexec expresses exactly.
if [ "$mode" = shell ]; then
	set -- /bin/sh -c "$*"
fi

# The preserved environment is exported by a shell prologue, so the command keeps
# its own argv rather than being flattened into one string.
if [ -n "$preserve" ]; then
	check_preserve
	prefix=$(export_prefix)
	set -- /bin/sh -c "\${prefix}exec \\"\\$@\\"" sh "$@"
fi

if [ -n "$user" ]; then
	set -- --user "$user" "$@"
fi

# -b returns as soon as the command is started, as sudo -b does.
if [ -n "$background" ]; then
	pkexec "$@" &
	exit 0
fi

run_pkexec "$@"
`

/** The doas shim: same contract, doas option grammar. */
const DOAS_SHIM = `#!/bin/sh
# opencode-polkit: doas shim. Routes doas to pkexec so polkit can authorize it.
# Generated at plugin startup; do not edit.

${SHIM_PRELUDE}
${SHIM_CHECKS}
PROG=doas
user=
noninteractive=
mode=

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
		shift
		;;
	-n)
		noninteractive=1
		shift
		;;
	-s)
		mode=shell
		shift
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

require_without_prompt

[ $# -gt 0 ] || fail 'doas needs a command: doas [OPTIONS] COMMAND (an interactive shell needs a terminal)'

if [ "$mode" = shell ]; then
	set -- /bin/sh -c "$*"
fi

if [ -n "$user" ]; then
	set -- --user "$user" "$@"
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

${SHIM_PRELUDE}
${SHIM_CHECKS}
PROG=su
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
		fail 'su --pty asks for a terminal; the bash tool has none.'
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
# how pkexec does the same.
run_pkexec --keep-cwd --user "$user" sh -c "$cmd"
`

/**
 * The environment helper: turns `NAME=VALUE` arguments into an export statement
 * each, so `-E` can rebuild the environment pkexec stripped. Values arrive as
 * arguments rather than text, so spaces, quotes and newlines need no escaping on
 * the way in. PATH keeps every entry except the shim directories.
 */
const POLKIT_ENV_HELPER = `#!/bin/sh
# opencode-polkit: rebuilds a stripped environment. Generated at plugin startup;
# do not edit.

for entry in "$@"; do
	name=\${entry%%=*}
	value=\${entry#*=}
	case $name in
	'' | [0-9]* | *[!A-Za-z0-9_]*)
		continue
		;;
	PATH)
		filtered=
		old_ifs=$IFS
		IFS=:
		for dir in $value; do
			case \${dir##*/} in
			opencode-polkit-*)
				continue
				;;
			esac
			filtered=$filtered\${filtered:+:}$dir
		done
		IFS=$old_ifs
		value=$filtered
		;;
	esac
	quote="'"
	quoted=
	while :; do
		case $value in
		*"$quote"*)
			quoted=$quoted\${value%%"$quote"*}"'\\\\''"
			value=\${value#*"$quote"}
			;;
		*)
			quoted=$quoted$value
			break
			;;
		esac
	done
	printf "export '%s=%s'; " "$name" "$quoted"
done
`


/** sudoedit edits through sudo's own temporary-file flow; polkit has none. */
const SUDOEDIT_SHIM = `#!/bin/sh
${SHIM_PRELUDE}
fail 'sudoedit is not supported; write a temp file and run pkexec install or pkexec cp on it.'
`

/** visudo needs an interactive editor on a terminal the shell tool does not have. */
const VISUDO_SHIM = `#!/bin/sh
${SHIM_PRELUDE}
fail 'visudo needs an interactive terminal; validate a candidate file with pkexec visudo -c -f FILE instead.'
`

/** File name → script body. Names must match the commands being redirected. */
const POLKIT_SHIM_SCRIPTS: Record<string, string> = {
  sudo: SUDO_SHIM,
  doas: DOAS_SHIM,
  su: SU_SHIM,
  sudoedit: SUDOEDIT_SHIM,
  visudo: VISUDO_SHIM,
  "opencode-polkit-env": POLKIT_ENV_HELPER,
}

/**
 * Writes the shim scripts into a fresh private directory and returns it.
 * The caller prepends this directory to PATH; the shell then resolves
 * `sudo`/`doas`/`su` to these files instead of the system ones. The directory
 * is 0700 so no other local user can rewrite the scripts, and it holds
 * `opencode-polkit-env`, the helper `sudo -E` uses to re-export an environment
 * pkexec stripped.
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
