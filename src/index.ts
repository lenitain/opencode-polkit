import type { Plugin, PluginInput } from "@opencode-ai/plugin"

type Kw = "sudo" | "doas" | "sudoedit" | "visudo" | "pkexec"

type Hit = { index: number; kw: Kw }

/**
 * Lexical scan for privilege-escalation keywords OUTSIDE quotes.
 *
 * Shell commands may contain `sudo` anywhere a command starts (pipes,
 * `&&`/`||`, subshells, command substitution), and string literals /
 * comments may contain the same words spuriously. A plain regex cannot
 * tell those apart; this scanner tracks quote state (' " and backslash
 * escapes) and only reports keywords in executable position.
 *
 * - `node -e "…sudo…"`        → no hit (inside quotes)
 * - `cat x | sudo tee y`       → hit at index 8 (command boundary)
 * - `cd /tmp && sudo ./x`      → hit (after `&&`)
 */
function scanPrivileged(command: string): Hit[] {
  const hits: Hit[] = []
  let inSingle = false
  let inDouble = false
  let escaped = false
  // Heredoc delimiters waiting to close (stack; multiple << are legal).
  const heredocs: string[] = []
  for (let i = 0; i < command.length; i++) {
    const ch = command[i]

    // Inside a heredoc body: only a line consisting of the delimiter ends
    // it. Content there is a string literal, never a command.
    if (heredocs.length > 0) {
      const lineEnd = command.indexOf("\n", i)
      const line = lineEnd === -1 ? command.slice(i) : command.slice(i, lineEnd)
      if (heredocs.some((d) => line === d)) {
        heredocs.pop()
      }
      i = lineEnd === -1 ? command.length : lineEnd
      continue
    }

    if (escaped) {
      escaped = false
      continue
    }
    if (ch === "\\" && !inSingle) {
      escaped = true
      continue
    }
    if (ch === "'" && !inDouble) {
      inSingle = !inSingle
      continue
    }
    if (ch === '"' && !inSingle) {
      inDouble = !inDouble
      continue
    }
    if (inSingle || inDouble) continue

    // Heredoc start: `<<[-]DELIM` (delim may be quoted or unquoted).
    if (ch === "<" && command[i + 1] === "<") {
      let j = i + 2
      if (command[j] === "-") j++
      while (j < command.length && /\s/.test(command[j])) j++
      if (j < command.length && (command[j] === "'" || command[j] === '"')) {
        const q = command[j]
        const end = command.indexOf(q, j + 1)
        if (end !== -1) {
          heredocs.push(command.slice(j + 1, end))
          i = end
          continue
        }
      } else {
        const m = /^[^\s|;&<>()]+/.exec(command.slice(j))
        if (m) {
          heredocs.push(m[0])
          i = j + m[0].length - 1
          continue
        }
      }
    }

    const prev = i > 0 ? command[i - 1] : ""
    if (/[-\/.\w]/.test(prev)) continue
    for (const kw of ["sudoedit", "visudo", "sudo", "doas", "pkexec"] as const) {
      if (command.startsWith(kw, i)) {
        const next = command[i + kw.length] ?? ""
        if (!/[-\/.\w]/.test(next)) {
          hits.push({ index: i, kw })
          i += kw.length - 1
          break
        }
      }
    }
  }
  return hits
}

type Messages = {
  blocked: string
  polkitDenied: string
}

const translations: Record<string, Messages> = {
  en: {
    blocked: "Privilege escalation command blocked by plugin",
    polkitDenied: "Polkit authentication denied by user",
  },
  zh: {
    blocked: "权限提升命令已被插件拦截",
    polkitDenied: "Polkit 认证已被用户拒绝",
  },
  ja: {
    blocked: "特権昇格コマンドはプラグインによりブロックされました",
    polkitDenied: "Polkit 認証がユーザーによって拒否されました",
  },
  ko: {
    blocked: "권한 상승 명령이 플러그인에 의해 차단되었습니다",
    polkitDenied: "Polkit 인증이 사용자에 의해 거부되었습니다",
  },
  de: {
    blocked: "Berechtigungseskalation vom Plugin blockiert",
    polkitDenied: "Polkit-Authentifizierung vom Benutzer abgelehnt",
  },
  fr: {
    blocked: "Commande d'élévation de privilèges bloquée par le plugin",
    polkitDenied: "Authentification polkit refusée par l'utilisateur",
  },
  es: {
    blocked: "Comando de elevación de privilegios bloqueado por el plugin",
    polkitDenied: "Autenticación polkit denegada por el usuario",
  },
  pt: {
    blocked: "Comando de elevação de privilégios bloqueado pelo plugin",
    polkitDenied: "Autenticação polkit negada pelo usuário",
  },
  ru: {
    blocked: "Команда повышения привилегий заблокирована плагином",
    polkitDenied: "Аутентификация polkit отклонена пользователем",
  },
  tr: {
    blocked: "Yetki yükseltme komutu eklenti tarafından engellendi",
    polkitDenied: "Polkit kimlik doğrulaması kullanıcı tarafından reddedildi",
  },
  uk: {
    blocked: "Команду підвищення привілеїв заблоковано плагіном",
    polkitDenied: "Автентифікацію polkit відхилено користувачем",
  },
}

function detectLocale(): string {
  const raw = process.env.LC_MESSAGES || process.env.LANG || "en"
  const tag = raw.split(".")[0].replace(/_/g, "-").toLowerCase()
  for (const prefix of ["zh", "ja", "ko", "de", "fr", "es", "pt", "ru", "tr", "uk"]) {
    if (tag.startsWith(prefix)) return prefix
  }
  return "en"
}

const MSG: Messages = translations[detectLocale()] ?? translations.en

/** Wrap a leading pkexec with a timeout so a stuck polkit authentication
 * (agent registered but unroutable — the "dialog never appears" case)
 * fails after `seconds` instead of hanging the bash tool forever. 30s is
 * enough for a visible dialog to be confirmed and short enough that a
 * silent hang is noticed quickly. */
const AUTH_TIMEOUT_SECS = 30

export const PolkitPlugin: Plugin = async (_input: PluginInput) => {
  const deniedCommands = new Set<string>()

  return {
    "tool.execute.before": async (hookInput, hookOutput) => {
      if (hookInput.tool !== "bash") return
      const command: string = hookOutput?.args?.command ?? ""
      const hits = scanPrivileged(command)
      if (hits.length === 0) return

      if (deniedCommands.has(command)) {
        throw new Error(MSG.polkitDenied)
      }

      if (hits.some((h) => h.kw === "sudoedit" || h.kw === "visudo")) {
        throw new Error(MSG.blocked)
      }

      // Already pkexec (leading or mid-command): pass through untouched.
      if (hits.every((h) => h.kw === "pkexec")) return

      // Rewrite every in-command sudo/doas to pkexec (back to front so
      // indices stay valid). Mid-command occurrences keep their position:
      // `cat x | sudo tee y` -> `cat x | pkexec tee y`.
      let rewritten = command
      for (const h of [...hits].reverse()) {
        if (h.kw === "sudo" || h.kw === "doas") {
          rewritten =
            rewritten.slice(0, h.index) + "pkexec" + rewritten.slice(h.index + h.kw.length)
        }
      }

      // Leading command gets a timeout guard: a hung polkit dialog (no
      // matching agent) previously hung the bash tool forever. Only simple
      // commands are wrapped (no command separators after pkexec) so
      // compound commands and user redirections are never restructured.
      // Only exit code 124 (timeout's own code) prints the auth-specific
      // message; a command that merely fails keeps its real exit code and
      // no misleading message.
      const lead = /^\s*/.exec(rewritten)![0]
      const rest = rewritten.slice(lead.length)
      if (
        /^pkexec\b/.test(rest) &&
        !/^timeout\s+\d+\s+/.test(rest) &&
        !/[;&|()]|\s&&|\s\|\|/.test(rest.slice("pkexec".length))
      ) {
        rewritten =
          lead +
          `timeout ${AUTH_TIMEOUT_SECS} ` +
          rest +
          `; code=$?; if [ $code -eq 124 ]; then echo "[opencode-polkit] polkit authentication not completed within ${AUTH_TIMEOUT_SECS}s (dialog may not have appeared)"; fi; exit $code`
      }

      hookOutput.args.command = rewritten
    },
    "tool.execute.after": async (hookInput, hookOutput) => {
      if (hookInput.tool !== "bash") return
      const command: string = hookInput.args?.command ?? ""
      const hits = scanPrivileged(command)
      if (hits.length === 0) return

      // Reconstruct the user's original command for the deny list: strip
      // the timeout guard and map pkexec back to sudo.
      let original = command.replace(/^(\s*)timeout\s+\d+\s+/, "$1")
      for (const h of [...scanPrivileged(original)].reverse()) {
        if (h.kw === "pkexec") {
          original = original.slice(0, h.index) + "sudo" + original.slice(h.index + 6)
        }
      }

      if (
        /\bNot authorized\b/.test(hookOutput.output) ||
        /\bError executing command as another user\b/.test(hookOutput.output) ||
        /\bError creating textual authentication agent\b/.test(hookOutput.output)
      ) {
        deniedCommands.add(original)
        throw new Error(MSG.polkitDenied)
      }
    },
  }
}
