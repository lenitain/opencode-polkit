import type { Plugin, PluginInput } from "@opencode-ai/plugin"

const MATCH = /(?<![-\/.\w])(sudo|pkexec|doas|sudoedit|visudo)(?![-\/.\w])/i

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

export const PolkitPlugin: Plugin = async (_input: PluginInput) => {
  const deniedCommands = new Set<string>()

  return {
    "tool.execute.before": async (hookInput, hookOutput) => {
      if (hookInput.tool !== "bash") return
      const command: string = hookOutput?.args?.command ?? ""
      if (!MATCH.test(command)) return

      if (deniedCommands.has(command)) {
        throw new Error(MSG.polkitDenied)
      }

      if (/^pkexec(?![-\/.\w])/.test(command.trim())) {
        return
      }

      if (/(?<![-\/.\w])(sudoedit|visudo)(?![-\/.\w])/.test(command)) {
        throw new Error(MSG.blocked)
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

      const originalCommand = command.replace(
        /(?<![-\/.\w])pkexec(?![-\/.\w])/,
        "sudo",
      )

      if (/\bNot authorized\b/.test(hookOutput.output) ||
          /\bError executing command as another user\b/.test(hookOutput.output)) {
        deniedCommands.add(originalCommand)
        throw new Error(MSG.polkitDenied)
      }
    },
  }
}
