// Local-directory entrypoint for OpenCode: OpenCode 2.2 also resolves a
// directory through a named package.json and its "exports", but older 2.0
// releases only look for `server`/`index` at the root. npm installs reach the
// real build through package.json "exports"; this shim keeps
// `"plugins": ["/path/to/opencode-polkit"]` working on both.
export { default } from "./dist/index.js"
