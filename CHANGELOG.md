# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
