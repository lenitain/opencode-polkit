import * as ts from "npm:typescript@^5.5.0"

const source = await Deno.readTextFile("src/index.ts")
const { outputText } = ts.transpileModule(source, {
  compilerOptions: {
    target: ts.ScriptTarget.ES2022,
    module: ts.ModuleKind.ESNext,
  },
})
await Deno.writeTextFile("dist/index.js", outputText)
console.log("built dist/index.js")
