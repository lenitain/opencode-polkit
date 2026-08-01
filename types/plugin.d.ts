export type PluginInput = Record<string, never>

export type Hooks = {
  "tool.execute.before"?: (
    input: { tool: string },
    output: { args: { command?: string } },
  ) => Promise<void>
  "tool.execute.after"?: (
    input: { tool: string; args: { command?: string } },
    output: { output: string },
  ) => Promise<void>
}

export type Plugin = (input: PluginInput) => Promise<Hooks>
