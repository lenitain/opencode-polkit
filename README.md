# opencode-polkit

Redirect `sudo`/`doas` to `pkexec` in [OpenCode](https://opencode.ai).
Triggers the system's native polkit authentication dialog (KDE, GNOME, etc.)
instead of requiring a terminal for password input.

Like CachyOS Hello, the plugin does not check for a polkit agent up front:
`sudo` is always redirected to `pkexec` at execution time, and polkitd routes
the request to whatever agent is currently registered. Without an agent,
`pkexec` fails fast with `Error creating textual authentication agent`
(no TTY); the plugin reports that as a clear denial. With an agent whose
registration is inconsistent (a known wayland/systemd-user-session
issue), polkitd waits for it and `pkexec` would hang forever — a leading
`timeout 120` guard bounds that to a visible failure.

## Install

```sh
opencode plugin opencode-polkit
```

Or add to `opencode.json` / `~/.config/opencode/opencode.jsonc`:

```json
{
  "plugin": ["opencode-polkit"]
}
```

For local development, point opencode at the project directory instead:

```json
{
  "plugin": ["/path/to/opencode-polkit"]
}
```

## Behavior

| Command               | result                                                |
|-----------------------|-------------------------------------------------------|
| `sudo xxx`            | redirects to `timeout 120 pkexec xxx`                 |
| `doas xxx`            | redirects to `timeout 120 pkexec xxx`                 |
| `cat x \| sudo tee y` | redirects to `cat x \| pkexec tee y` (mid-command)    |
| `pkexec xxx`          | passes through                                        |
| `sudoedit` / `visudo` | blocked                                               |

### Detection

Privilege keywords are found by a **lexical scanner**, not a regex: it
tracks quote state, backslash escapes and heredocs, so `sudo` inside
string literals, comments or heredoc bodies is ignored, while `sudo` in
any executable position (leading, after `&&`/`||`/`|`, in `$(...)` or
subshells) is rewritten or reported. `sudo a && sudo b` rewrites both.

When authentication is denied (`Not authorized`, `Error executing
command as another user`, `Error creating textual authentication
agent`), a clear error message is shown and the command is remembered
so a retry is rejected without prompting again.

## i18n

Messages adapt to `$LC_MESSAGES` / `$LANG`. Currently supports:
en, zh, ja, ko, de, fr, es, pt, ru, tr, uk.

PRs welcome for additional translations.

## License

MIT
