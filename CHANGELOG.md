# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `test/shims.test.ts`: behaviour tests for the generated shims. They stub
  `pkexec`, `pkcheck` and `pkaction` on `PATH`, so they need neither polkit, a
  desktop agent nor root; `npm test` runs them with Node's test runner.
- README: account-lockout section. Where the `polkit-1` PAM service includes
  `pam_faillock`, a wrong or empty password submitted in the dialog adds a
  record shared with terminal sudo and login; dismissing the dialog adds none,
  an agent may allow several attempts in one dialog (each retry starts a new PAM
  helper), and a locked account rejects even the correct password for
  `unlock_time`. Documents how to inspect and reset the tally, and why retrying
  does not help.
- README limitation: `-n`, `-v` and `-l` check
  `org.freedesktop.policykit.exec` itself, while pkexec may select another
  action installed with `org.freedesktop.policykit.exec.path`/`argv1`
  annotations.

### Changed

- The shell tool's description now asks the model to consult the user before
  retrying a dismissed or failed dialog, because failed or empty password
  submissions count toward a system-wide `pam_faillock` lockout while a dismissal
  does not.
- README: `sudoers` and the `sudo` PAM stack are not consulted; polkit policy and
  the `polkit-1` PAM service decide, so sudo-only modules such as a fingerprint
  reader or a second factor do not run in OpenCode.
- README now describes agent caching and retry behaviour generically instead of
  attributing it to one desktop agent.
- `sudo -v` reports an interactive failure as "polkit did not authorize" instead
  of "polkit denies", since the check can fail after the password is rejected.
- The shim's action comment now records that pkexec may select a custom action by
  annotation, which the checks do not see.
- `npm run check` now also type-checks `test/`, and CI runs check, test and
  build.

## [0.4.0] - 2026-11-05

### Added

- `sudo -n`, `doas -n`: a non-interactive `pkcheck` on
  `org.freedesktop.policykit.exec` decides whether the command runs. polkit grants
  it without asking, or the shim exits `1` with `sudo: a password is required` and
  the reason that dropping `-n` lets the agent answer. Measured: a successful
  `pkexec` leaves no temporary authorization behind (`pkcheck --list-temp` stays
  empty), so the silent second run is the agent's own password cache and no
  non-interactive query can predict it; `-n` therefore reports policy, not a
  guess.
- `sudo -v` performs the authentication (`pkcheck --allow-user-interaction`) and
  exits `0`, `1`, `126` when the dialog is dismissed, or `127`; `sudo -nv` uses
  the non-interactive check.
- `sudo -l` prints `pkaction --verbose` for the action and this session's
  temporary authorizations.
- `sudo -k`/`-K` revoke polkit's temporary authorizations and say that an agent's
  own password cache cannot be cleared from here.
- `sudo -H`, `-N`, `-P` are accepted as no-ops: pkexec already sets `HOME`, keeps
  no timestamp and leaves groups alone.
- `sudo -s COMMAND` and `--shell` run the command through a shell, `sudo -b`
  starts it in the background and returns, and `sudo -E`/
  `--preserve-env[=LIST]` re-export the environment inside the command.
- `sudo --help` and `sudo -V` are answered by the real binary, so scripts that
  probe sudo keep working.
- Short options bundle (`sudo -nu bob`), and unknown long options report their own
  name instead of `--`.
- `opencode-polkit-env`: helper that turns `NAME=VALUE` arguments into export
  statements. `-E` passes entries through argv (`env -0` into `xargs -0`), so
  spaces, quotes and newlines survive, and it drops every shim directory from
  `PATH` so an elevated command cannot resolve sudo back to a shim.
- `src/index.ts`: the shell tool's description gains one sentence naming the
  redirect and what `-n`, `-v` and `-l` answer, so the model plans privilege with
  the real contract instead of learning it from a failed call.

### Changed

- The shims share one prologue: `fail`, the polkit subject (pinned with
  `pid,start-time,uid` as `pkcheck(1)` requires), the two checks and the `pkexec`
  wrapper.
- `-n` failures exit `1` like sudo, not `64`: `64` now means only that the
  invocation cannot be expressed. README documents the four-way handling
  (translated, no-op, checked, refused) and polkit's missing temp authorization.
- `sudo -i`, `-S`, `-A`, `sudoedit` and `visudo` still refuse, now from the shared
  prelude.

## [0.3.1] - 2026-11-04

### Added

- `src/shims.ts`: `su` stand-in. `su -c COMMAND [USER]` (also `-cCOMMAND`,
  `--command COMMAND`, `--command=COMMAND`) becomes
  `pkexec --keep-cwd --user USER sh -c COMMAND`, because a non-login `su` keeps
  the working directory and runs its command through a shell. Every other form
  is refused with status `64` and one line naming the alternative: `su`,
  `su -`, `su -l` (login shell → `pkexec bash`), `-m`/`-p`/`-w` (pkexec
  sanitizes the environment), `-s` (name the shell in the command), `-g`/`-G`
  (pkexec cannot switch groups), `--pty` (no terminal), `-f` and
  `--session-command`.
- README scope statement: the plugin covers elevation → polkit only; ssh,
  gpg/pinentry, keyrings, database clients, `kinit` and disk encryption are
  explicitly out of scope and need an askpass helper or a PTY.

### Changed

- README authorisation note: a desktop agent may reuse the password it already
  holds, so a second command can run without a dialog; that cache belongs to
  the agent and must not be relied on. `su -c … USER` authenticates an
  administrator rather than `USER`, and runs the command with `sh -c`.

## [0.3.0] - 2026-11-01

0.3.0 replaces how the plugin decides anything. It used to parse the command
string to find `sudo`, then parse the output to guess whether authentication
failed; both are gone. The plugin now only prepends a directory of shims to
`PATH`, letting the shell's own name resolution pick them, and reads the
outcome from exit status alone. Everything that existed to support guessing —
the lexical scanner, the output matchers, the denial cache, the translations —
is deleted with it. The plugin no longer changes the command the agent wrote.

### Added

- `src/shims.ts`: `sudo`, `doas`, `sudoedit` and `visudo` scripts written to a
  private `0700` temporary directory at setup and removed when the plugin is
  disposed. `sudo` and `doas` forward to `pkexec`; `sudoedit` and `visudo`
  refuse, because polkit has no equivalent flow.
- Deterministic option contract in the shims: `-u USER`, `-uUSER`, `--user USER`
  and `--user=USER` become `pkexec --user USER`, `--` ends option parsing, and
  every other option is refused with exit status `64` and a message naming the
  alternative (`-n` → polkit decides, `-i`/`-s` → `pkexec bash`, `-E`/`-H`/`-P`
  → pkexec sanitizes the environment, `-b` → append `&`). `pkexec` would
  otherwise reject them with `Cannot run program`, which says nothing about what
  to do next.
- A one-line explanation on exit status `126`: it is the only pkexec failure
  path that prints nothing of its own, so the shim says the dialog was
  dismissed. Every `127` path already prints its reason.
- `SHIM_USAGE_EXIT` (64) documents that the refusal status is the shim's own and
  cannot be confused with pkexec's `126`/`127`.

### Changed

- **Breaking:** commands are no longer rewritten. The `shell` tool's
  `execute.before`/`execute.after` hooks are replaced by a single
  `shell.create.before` hook that only sets `event.env.PATH`, so the agent's
  command reaches the shell exactly as written, and `sudo` inside quotes,
  comments or heredocs needs no special case.
- **Breaking:** authentication failures are reported from exit status
  (`126` dismissed, `127` not authorized, `64` refused invocation), never from
  output. The locale-dependent matchers for `Not authorized`,
  `Error executing command as another user` and
  `Error creating textual authentication agent` are gone.
- **Breaking:** messages are English only. The `Messages` table, the ten
  translations and `detectLocale` are removed; the consumer is the coding agent.
- **Breaking:** a refused command is no longer remembered. Retrying after a
  dismissed dialog prompts again instead of being rejected by the plugin.
- PATH interception is idempotent: prepending happens once, so stacked hooks do
  not grow `PATH`.

### Removed

- `scanPrivileged` (the quote-, escape- and heredoc-aware lexical scanner) and
  `findBadOption`.
- The `deniedCommands` and `originalCommands` maps, along with the
  `execute.after` result rewriting they supported.
- The `translations` table for en, zh, ja, ko, de, fr, es, pt, ru, tr and uk.
- The i18n section of the README, which now documents the exit-status contract
  and the PATH shim's limits instead.
