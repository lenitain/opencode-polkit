import type { Plugin, PluginInput } from "@opencode-ai/plugin"

const MATCH = /(?<![-\/.\w])(sudo|pkexec|doas|sudoedit|visudo)(?![-\/.\w])/i

const POLKIT_AGENTS = [
  "polkit-kde-authentication-agent-1",
  "polkit-gnome-authentication-agent-1",
  "lxqt-policykit-agent",
  "mate-polkit",
  "xfce-polkit",
  "dde-polkit-agent",
]

type Messages = {
  blocked: string
  noPolkit: string
  noPolkitPkexec: string
  polkitDenied: string
}

const translations: Record<string, Messages> = {
  en: {
    blocked: "Privilege escalation command blocked by plugin",
    noPolkit: "sudo/doas blocked: no polkit agent detected, cannot escalate safely",
    noPolkitPkexec: "pkexec unavailable: no polkit agent detected",
    polkitDenied: "Polkit authentication denied by user",
  },
  zh: {
    blocked: "权限提升命令已被插件拦截",
    noPolkit: "sudo/doas 已被拦截：未检测到 polkit agent，无法安全提权",
    noPolkitPkexec: "pkexec 不可用：未检测到 polkit agent",
    polkitDenied: "Polkit 认证已被用户拒绝",
  },
  ja: {
    blocked: "特権昇格コマンドはプラグインによりブロックされました",
    noPolkit: "sudo/doas がブロックされました：polkit エージェントが見つからないため、安全に昇格できません",
    noPolkitPkexec: "pkexec は利用できません：polkit エージェントが見つかりません",
    polkitDenied: "Polkit 認証がユーザーによって拒否されました",
  },
  ko: {
    blocked: "권한 상승 명령이 플러그인에 의해 차단되었습니다",
    noPolkit: "sudo/doas 차단됨: polkit 에이전트가 감지되지 않아 안전하게 권한 상승할 수 없습니다",
    noPolkitPkexec: "pkexec 사용 불가: polkit 에이전트가 감지되지 않았습니다",
    polkitDenied: "Polkit 인증이 사용자에 의해 거부되었습니다",
  },
  de: {
    blocked: "Berechtigungseskalation vom Plugin blockiert",
    noPolkit: "sudo/doas blockiert: kein polkit-Agent erkannt, sichere Eskalation nicht möglich",
    noPolkitPkexec: "pkexec nicht verfügbar: kein polkit-Agent erkannt",
    polkitDenied: "Polkit-Authentifizierung vom Benutzer abgelehnt",
  },
  fr: {
    blocked: "Commande d'élévation de privilèges bloquée par le plugin",
    noPolkit: "sudo/doas bloqué : aucun agent polkit détecté, élévation impossible",
    noPolkitPkexec: "pkexec indisponible : aucun agent polkit détecté",
    polkitDenied: "Authentification polkit refusée par l'utilisateur",
  },
  es: {
    blocked: "Comando de elevación de privilegios bloqueado por el plugin",
    noPolkit: "sudo/doas bloqueado: no se detectó agente polkit, no se puede elevar de forma segura",
    noPolkitPkexec: "pkexec no disponible: no se detectó agente polkit",
    polkitDenied: "Autenticación polkit denegada por el usuario",
  },
  pt: {
    blocked: "Comando de elevação de privilégios bloqueado pelo plugin",
    noPolkit: "sudo/doas bloqueado: nenhum agente polkit detectado, não é possível elevar com segurança",
    noPolkitPkexec: "pkexec indisponível: nenhum agente polkit detectado",
    polkitDenied: "Autenticação polkit negada pelo usuário",
  },
  ru: {
    blocked: "Команда повышения привилегий заблокирована плагином",
    noPolkit: "sudo/doas заблокирован: не обнаружен polkit-агент, невозможно безопасно повысить привилегии",
    noPolkitPkexec: "pkexec недоступен: не обнаружен polkit-агент",
    polkitDenied: "Аутентификация polkit отклонена пользователем",
  },
  tr: {
    blocked: "Yetki yükseltme komutu eklenti tarafından engellendi",
    noPolkit: "sudo/doas engellendi: polkit aracısı algılanmadı, güvenli şekilde yetki yükseltilemez",
    noPolkitPkexec: "pkexec kullanılamıyor: polkit aracısı algılanmadı",
    polkitDenied: "Polkit kimlik doğrulaması kullanıcı tarafından reddedildi",
  },
  uk: {
    blocked: "Команду підвищення привілеїв заблоковано плагіном",
    noPolkit: "sudo/doas заблоковано: не виявлено агента polkit, неможливо безпечно підвищити привілеї",
    noPolkitPkexec: "pkexec недоступний: не виявлено агента polkit",
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

function polkitAvailable(): boolean {
  try {
    if (process.env.DBUS_SESSION_BUS_ADDRESS) {
      const proc = Bun.spawnSync(["busctl", "--user", "list"], {
        stdio: ["ignore", "pipe", "pipe"],
      })
      if (proc.exitCode === 0 && /\bpolkit\b/i.test(new TextDecoder().decode(proc.stdout))) {
        return true
      }
    }
  } catch { /* fall through */ }
  try {
    const proc = Bun.spawnSync(["pgrep", "-x", ...POLKIT_AGENTS], {
      stdio: ["ignore", "pipe", "pipe"],
    })
    return proc.exitCode === 0
  } catch {
    return false
  }
}

const hasPolkit = polkitAvailable()

export const PolkitPlugin: Plugin = async (_input: PluginInput) => {
  return {
    "tool.execute.before": async (hookInput, hookOutput) => {
      if (hookInput.tool !== "bash") return
      const command: string = hookOutput?.args?.command ?? ""
      if (!MATCH.test(command)) return

      if (/^pkexec(?![-\/.\w])/.test(command.trim())) {
        if (!hasPolkit) throw new Error(MSG.noPolkitPkexec)
        return
      }

      if (/(?<![-\/.\w])(sudoedit|visudo)(?![-\/.\w])/.test(command)) {
        throw new Error(MSG.blocked)
      }

      if (!hasPolkit) {
        throw new Error(MSG.noPolkit)
      }

      hookOutput.args.command = command.replace(
        /(?<![-\/.\w])(sudo|doas)(?![-\/.\w])/,
        "pkexec",
      )
    },
    "tool.execute.after": async (hookInput, hookOutput) => {
      if (hookInput.tool !== "bash") return
      const command: string = hookInput.args?.command ?? ""
      if (!MATCH.test(command)) return

      if (/\bNot authorized\b/.test(hookOutput.output) ||
          /\bError executing command as another user\b/.test(hookOutput.output)) {
        throw new Error(MSG.polkitDenied)
      }
    },
  }
}
