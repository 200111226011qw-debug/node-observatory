import fs from "node:fs/promises";
import path from "node:path";
import { minify } from "terser";

const input = new URL("../src/index.js", import.meta.url);
const output = new URL("../dist/worker.obfuscated.js", import.meta.url);
const source = await fs.readFile(input, "utf8");
const result = await minify(source, {
  module: true,
  compress: { passes: 2 },
  mangle: true,
  format: { comments: false, beautify: false },
  sourceMap: false
});
if (!result.code) throw new Error("Terser produced no output");
await fs.mkdir(path.dirname(output.pathname), { recursive: true });
await fs.writeFile(output, result.code + "\n", "utf8");
console.log("Built dist/worker.obfuscated.js (no source map)");
