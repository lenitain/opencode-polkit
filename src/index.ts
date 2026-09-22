import type { Plugin } from "@opencode/plugin"

type Kw = "sudo" | "doas" | "sudoedit" | "visudo" | "pkexec"

type Hit = { index: number; kw: Kw }

/** Long options pkexec accepts (all of them; pkexec has no short options). */
const PKEXEC_OPTIONS = new Set([
  "--version",
  "--help",
  "--disable-internal-agent",
  "--keep-cwd",
  "--user",
])

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
 * - `--name sudo bash`         → no hit (argument position)
 * - `echo x; # sudo y`         → no hit (comment)
 */
function scanPrivileged(command: string): Hit[] {
  const hits: Hit[] = []
  let inSingle = false
  let inDouble = false
  let escaped = false
  // True right after a command boundary (`;`, `&&`, `||`, `|`, `(`, start).
  let atCommandStart = true
  // Heredoc delimiters waiting to close (stack; multiple << are legal).
  const heredocs: string[] = []
  for (let i = 0; i < command.length; i++) {
    const ch = command[i]

    // Inside a heredoc body: only a line consisting of the delimiter ends
    // it. Content there is a string literal, never a command. Pop the
    // matching delimiter (nested heredocs close in any order).
    if (heredocs.length > 0) {
      const lineEnd = command.indexOf("\n", i)
      const line = lineEnd === -1 ? command.slice(i) : command.slice(i, lineEnd)
      const idx = heredocs.lastIndexOf(line)
      if (idx !== -1) {
        heredocs.splice(idx)
        // The line after the delimiter starts a new command position.
        atCommandStart = true
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
    if (ch === '"' && !inDouble) {
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

    // Command boundaries open a new executable position.
    if (ch === ";" || ch === "|" || ch === "&" || ch === "(" || ch === "\n") {
      atCommandStart = true
      continue
    }

    // `#` at a word start begins a comment that runs to end of line.
    if (ch === "#") {
      const prev = command[i - 1] ?? ""
      if (i === 0 || /\s/.test(prev) || /[;|&(]/.test(prev)) {
        const nl = command.indexOf("\n", i)
        i = nl === -1 ? command.length : nl
        continue
      }
    }

    if (/\s/.test(ch)) continue

    // An env assignment (`FOO=1 sudo x`) still starts a command; any other
    // word in argument position (`--name sudo`) does not.
    let isCommandPos = atCommandStart
    if (!isCommandPos) {
      let j = i - 1
      while (j >= 0 && /\s/.test(command[j])) j--
      while (j >= 0 && !/[\s;|&()]/.test(command[j])) j--
      const token = command.slice(j + 1, i)
      if (token.includes("=")) isCommandPos = true
    }
    atCommandStart = false

    if (!isCommandPos) continue

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

/**
 * First option token after a privilege keyword that pkexec does not
 * accept, or null when the command's options are pkexec-compatible.
 * Scanning stops at the program name (`--` also terminates options, as
 * in sudo); tokens after it belong to the program, not to pkexec.
 *
 * - `sudo -n true`             → `-n` (pkexec has no short options)
 * - `sudo --non-interactive x` → `--non-interactive`
 * - `sudo --user root x`       → null (compatible)
 * - `sudo -- x -n`             → null (`--` ends sudo options)
 */
function findBadOption(command: string, hit: Hit): string | null {
  let i = hit.index + hit.kw.length
  while (i < command.length && /\s/.test(command[i])) i++
  while (i < command.length && command[i] === "-") {
    let end = i + 1
    while (end < command.length && !/\s/.test(command[end]) && !/[;|&()]/.test(command[end])) end++
    const token = command.slice(i, end)
    if (token === "--") break
    if (!token.startsWith("--")) return token
    if (!PKEXEC_OPTIONS.has(token.split("=")[0])) return token
    i = end
    while (i < command.length && /\s/.test(command[i])) i++
  }
  return null
}

type Messages = {
  blocked: string
  polkitDenied: string
  badOption: string
}

const translations: Record<string, Messages> = {
  en: {
    blocked: "Privilege escalation command blocked by plugin",
    polkitDenied: "Polkit authentication denied by user",
    badOption:
      'Option "{opt}" is not supported by pkexec. Remove it or use a pkexec-compatible one (--user, --keep-cwd, --disable-internal-agent).',
  },
  zh: {
    blocked: "权限提升命令已被插件拦截",
    polkitDenied: "Polkit 认证已被用户拒绝",
    badOption:
      '选项 "{opt}" 不被 pkexec 支持,请移除或改用 pkexec 兼容选项(--user、--keep-cwd、--disable-internal-agent)。',
  },
  ja: {
    blocked: "特権昇格コマンドはプラグインによりブロックされました",
    polkitDenied: "Polkit 認証がユーザーによって拒否されました",
    badOption:
      'オプション "{opt}" は pkexec ではサポートされていません。削除するか、pkexec 互換オプション(--user、--keep-cwd、--disable-internal-agent)を使用してください。',
  },
  ko: {
    blocked: "권한 상승 명령이 플러그인에 의해 차단되었습니다",
    polkitDenied: "Polkit 인증이 사용자에 의해 거부되었습니다",
    badOption:
      '옵션 "{opt}"은(는) pkexec에서 지원되지 않습니다. 제거하거나 pkexec 호환 옵션(--user, --keep-cwd, --disable-internal-agent)을 사용하세요.',
  },
  de: {
    blocked: "Berechtigungseskalation vom Plugin blockiert",
    polkitDenied: "Polkit-Authentifizierung vom Benutzer abgelehnt",
    badOption:
      'Option "{opt}" wird von pkexec nicht unterstützt. Entfernen Sie sie oder verwenden Sie eine pkexec-kompatible Option (--user, --keep-cwd, --disable-internal-agent).',
  },
  fr: {
    blocked: "Commande d'élévation de privilèges bloquée par le plugin",
    polkitDenied: "Authentification polkit refusée par l'utilisateur",
    badOption:
      'Option "{opt}" non prise en charge par pkexec. Supprimez-la ou utilisez une option compatible pkexec (--user, --keep-cwd, --disable-internal-agent).',
  },
  es: {
    blocked: "Comando de elevación de privilegios bloqueado por el plugin",
    polkitDenied: "Autenticación polkit denegada por el usuario",
    badOption:
      'Opción "{opt}" no admitida por pkexec. Elimínela o use una opción compatible con pkexec (--user, --keep-cwd, --disable-internal-agent).',
  },
  pt: {
    blocked: "Comando de elevação de privilégios bloqueado pelo plugin",
    polkitDenied: "Autenticação polkit negada pelo usuário",
    badOption:
      'Opção "{opt}" não suportada pelo pkexec. Remova-a ou use uma opção compatível com pkexec (--user, --keep-cwd, --disable-internal-agent).',
  },
  ru: {
    blocked: "Команда повышения привилегий заблокирована плагином",
    polkitDenied: "Аутентификация polkit отклонена пользователем",
    badOption:
      'Параметр "{opt}" не поддерживается pkexec. Удалите его или используйте совместимый параметр (--user, --keep-cwd, --disable-internal-agent).',
  },
  tr: {
    blocked: "Yetki yükseltme komutu eklenti tarafından engellendi",
    polkitDenied: "Polkit kimlik doğrulaması kullanıcı tarafından reddedildi",
    badOption:
      '"{opt}" seçeneği pkexec tarafından desteklenmiyor. Kaldırın veya pkexec uyumlu bir seçenek kullanın (--user, --keep-cwd, --disable-internal-agent).',
  },
  uk: {
    blocked: "Команду підвищення привілеїв заблоковано плагіном",
    polkitDenied: "Автентифікацію polkit відхилено користувачем",
    badOption:
      'Параметр "{opt}" не підтримується pkexec. Видаліть його або використайте сумісний параметр (--user, --keep-cwd, --disable-internal-agent).',
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

/** The `shell` tool's input (OpenCode 2.0 renamed `bash` to `shell`). */
type ShellInput = { readonly command?: unknown }

/** The command string of a shell tool call, or "" for anything else. */
function shellCommand(input: unknown): string {
  if (typeof input !== "object" || input === null) return ""
  const command = (input as ShellInput).command
  return typeof command === "string" ? command : ""
}

/** Plain text of a tool result, whether content is a string or Content[]. */
function resultText(result: { readonly content?: unknown }): string {
  const content = result.content
  if (typeof content === "string") return content
  if (!Array.isArray(content)) return ""
  return content
    .map((part) =>
      typeof part === "object" && part !== null && "type" in part && part.type === "text" && "text" in part
        ? String(part.text)
        : "",
    )
    .join("\n")
}

const setup = async (ctx: Plugin.Context): Promise<void> => {
  const deniedCommands = new Set<string>()

  await ctx.tool.hook("execute.before", (event) => {
    if (event.tool !== "shell") return
    // Mutating the input object in place rewrites the executed command;
    // core uses `event.input` after every hook has run.
    const args = event.input
    const command = shellCommand(args)
    const hits = scanPrivileged(command)
    if (hits.length === 0) return

    if (deniedCommands.has(command)) {
      throw new Error(MSG.polkitDenied)
    }

    if (hits.some((h) => h.kw === "sudoedit" || h.kw === "visudo")) {
      throw new Error(MSG.blocked)
    }

    // Rewrite would produce `pkexec <bad option>`: fail with a clear
    // message instead of a confusing `Cannot run program` error.
    for (const h of hits) {
      if (h.kw === "sudo" || h.kw === "doas" || h.kw === "pkexec") {
        const bad = findBadOption(command, h)
        if (bad) throw new Error(MSG.badOption.replace("{opt}", bad))
      }
    }

    // Already pkexec (leading or mid-command): pass through untouched.
    if (hits.every((h) => h.kw === "pkexec")) return

    // Rewrite every in-command sudo/doas to pkexec (back to front so
    // indices stay valid): `cat x | sudo tee y` -> `cat x | pkexec tee y`.
    // No other rewriting: the command keeps its exact shape so the agent
    // sees only the minimal change (sudo -> pkexec).
    let rewritten = command
    for (const h of [...hits].reverse()) {
      if (h.kw === "sudo" || h.kw === "doas") {
        rewritten = rewritten.slice(0, h.index) + "pkexec" + rewritten.slice(h.index + h.kw.length)
      }
    }

    ;(args as { command?: string }).command = rewritten
  })

  await ctx.tool.hook("execute.after", (event) => {
    if (event.tool !== "shell") return
    // `event.input` is the (possibly rewritten) command the shell ran:
    // map pkexec back to sudo to reconstruct the original for the deny list.
    const command = shellCommand(event.input)
    const hits = scanPrivileged(command)
    if (hits.length === 0) return

    let original = command
    for (const h of [...hits].reverse()) {
      if (h.kw === "pkexec") {
        original = original.slice(0, h.index) + "sudo" + original.slice(h.index + 6)
      }
    }

    const text =
      event.status === "completed" ? resultText(event.result) : event.status === "error" ? event.error.message : ""

    // Only unambiguous authentication failures are reported and deny
    // listed. A hang (dialog never appears) is bounded by the shell tool's
    // own timeout (default 2 min) and is NOT translated here: it cannot
    // be told apart from a long-running command.
    if (
      /\bNot authorized\b/.test(text) ||
      /\bError executing command as another user\b/.test(text) ||
      /\bError creating textual authentication agent\b/.test(text)
    ) {
      deniedCommands.add(original)
      throw new Error(MSG.polkitDenied)
    }
  })
}

/**
 * OpenCode 2.0 requires a default export shaped `{ id, setup }` (the loader
 * rejects anything else). Deliberately a plain object with type-only imports:
 * the built plugin has zero runtime dependencies.
 */
export default { id: "opencode-polkit", setup } satisfies Plugin.Plugin
