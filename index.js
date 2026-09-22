// Local-directory entrypoint for OpenCode 2.0: the loader resolves a plugin
// directory by looking for `server`/`index` at its root (package.json "main"
// and "exports" are only consulted for npm package names). npm installs reach
// the real build through package.json "exports"; this shim covers
// `"plugins": ["/path/to/opencode-polkit"]`.
export { default } from "./dist/index.js"
