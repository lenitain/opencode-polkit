# opencode-polkit

Redirect `sudo`/`doas` to `pkexec` in [OpenCode](https://opencode.ai).
Triggers the system's native polkit authentication dialog (KDE, GNOME, etc.)
instead of requiring a terminal for password input.

Like CachyOS Hello, the plugin does not check for a polkit agent up front:
`sudo` is always redirected to `pkexec` at execution time, and polkitd routes
the request to whatever agent is currently registered. If no agent is
available, `pkexec` fails with its own clear error message.

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

| Command         | result                                     |
|-----------------|--------------------------------------------|
| `sudo xxx`      | redirects to `pkexec xxx`                  |
| `doas xxx`      | redirects to `pkexec xxx`                  |
| `pkexec xxx`    | passes through                             |
| `sudoedit`      | blocked                                    |
| `visudo`        | blocked                                    |

When a user denies the polkit authentication dialog, a clear error message is shown.

## i18n

Messages adapt to `$LC_MESSAGES` / `$LANG`. Currently supports:
en, zh, ja, ko, de, fr, es, pt, ru, tr, uk.

PRs welcome for additional translations.

## License

MIT
