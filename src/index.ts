import type { Plugin } from "@opencode/plugin"
import { installPolkitShims, removePolkitShims } from "./shims.js"

/**
 * PATH used when the shell tool supplies none, mirroring a normal Linux host.
 * Only the prepend matters; the rest is a last-resort fallback.
 */
const FALLBACK_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

/** Tool names whose description should name how elevation works here. */
const SHELL_TOOLS = ["bash", "shell"]

/** Opening words of the appended description; also the guard against appending twice. */
const CONTRACT_MARKER = "polkit redirect:"

/**
 * Appended to the shell tool's description. The model plans privilege with what
 * it knows about sudo, so the difference is stated where it reads the tool,
 * instead of being learned from a failed call.
 */
const SHELL_TOOL_CONTRACT = `${CONTRACT_MARKER} \`sudo\`, \`doas\` and \`su -c\` run through pkexec, so a desktop polkit dialog authorises them instead of a terminal password prompt. \`sudo -n\` runs the command only if polkit would authorise it without asking, \`sudo -v\` performs a real authentication, and \`sudo -l\` prints the polkit policy that decides. Ask the user before retrying a dismissed or failed dialog instead of looping: on systems with pam_faillock, failed or empty password submissions count toward a system-wide lockout shared with login, while dismissing the dialog does not.`

/**
 * Redirects sudo/doas/su -c to pkexec without touching the command text.
 *
 * The shell tool spawns `$SHELL -c 'command'` with the environment built here,
 * so putting the shims first on PATH lets the shell's own name resolution pick
 * them up — `sudo`, `$(sudo …)`, `xargs sudo`, `FOO=1 sudo`, nested scripts.
 * Nothing parses the command string, and nothing parses pkexec's output: the
 * shims hand pkexec's exit status (126 dismissed, 127 not authorized) back to
 * the caller unchanged.
 *
 * The shell is non-interactive and non-login, so no profile rewrites PATH and
 * no alias can shadow the shims.
 */
const setup = async (ctx: Plugin.Context): Promise<Plugin.Cleanup> => {
  const shimDir = installPolkitShims()
  const prefix = `${shimDir}:`

  // Hooks stack across plugin loads; prepending once keeps PATH duplicate-free.
  await ctx.shell.hook("create.before", (event) => {
    const path = event.env.PATH || FALLBACK_PATH
    if (!path.startsWith(prefix)) event.env.PATH = prefix + path
  })

  // The shell tool is the host's, so its description is extended rather than
  // replaced. Every reload runs this transform again, so a description that
  // already carries the line is left alone.
  await ctx.tool.transform((tools) => {
    for (const tool of tools.list()) {
      if (!SHELL_TOOLS.includes(tool.id) && !SHELL_TOOLS.includes(tool.name)) continue
      tools.update(tool.id, (entry) => {
        if (entry.description.includes(CONTRACT_MARKER)) return
        entry.description = `${entry.description}\n\n${SHELL_TOOL_CONTRACT}`
      })
    }
  })

  return () => removePolkitShims(shimDir)
}

/**
 * OpenCode 2.0 requires a default export shaped `{ id, setup }`. Type-only
 * imports keep the built plugin free of runtime dependencies.
 */
export default { id: "opencode-polkit", setup } satisfies Plugin.Plugin
