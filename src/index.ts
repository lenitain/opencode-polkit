import type { Plugin } from "@opencode/plugin"
import { installPolkitShims, removePolkitShims } from "./shims.js"

/**
 * PATH used when the shell tool supplies none, mirroring a normal Linux host.
 * Only the prepend matters; the rest is a last-resort fallback.
 */
const FALLBACK_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

/**
 * Redirects sudo/doas to pkexec without touching the command text.
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

  return () => removePolkitShims(shimDir)
}

/**
 * OpenCode 2.0 requires a default export shaped `{ id, setup }`. Type-only
 * imports keep the built plugin free of runtime dependencies.
 */
export default { id: "opencode-polkit", setup } satisfies Plugin.Plugin
