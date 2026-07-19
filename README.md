# opencode-polkit

Redirect `sudo`/`doas` to `pkexec` in [OpenCode](https://opencode.ai).
Triggers the system's native polkit authentication dialog (KDE, GNOME, etc.)
instead of requiring a terminal for password input.

When polkit is unavailable, privilege escalation commands are blocked with a
clear error message.

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

## Behavior

| Command         | polkit available               | polkit unavailable   |
|-----------------|--------------------------------|----------------------|
| `sudo xxx`      | redirects to `pkexec xxx`      | blocked with error   |
| `doas xxx`      | redirects to `pkexec xxx`      | blocked with error   |
| `pkexec xxx`    | passes through                 | blocked with error   |
| `sudoedit`      | blocked                        | blocked              |
| `visudo`        | blocked                        | blocked              |

## i18n

Messages adapt to `$LC_MESSAGES` / `$LANG`. Currently supports:
en, zh, ja, ko, de, fr, es, pt, ru, tr, uk.

PRs welcome for additional translations.

## License

MIT
