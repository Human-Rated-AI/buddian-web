import { copyFile, cp, mkdir, rm } from "node:fs/promises";
import { resolve } from "node:path";
import esbuild from "esbuild";

const root = resolve(import.meta.dirname, "..");
const src = resolve(root, "src");
const dist = resolve(root, "dist");

await rm(dist, { recursive: true, force: true });
await mkdir(dist, { recursive: true });

await Promise.all([
  copyFile(resolve(src, "index.html"), resolve(dist, "index.html")),
  copyFile(resolve(src, "styles.css"), resolve(dist, "styles.css")),
  cp(resolve(src, "assets"), resolve(dist, "assets"), { recursive: true, force: true }).catch((error) => {
    if (error.code !== "ENOENT") throw error;
  }),
]);

await esbuild.build({
  entryPoints: [resolve(src, "app.js")],
  bundle: true,
  outfile: resolve(dist, "app.js"),
  format: "esm",
  target: ["es2022"],
  legalComments: "eof",
  sourcemap: false,
  minify: false,
  treeShaking: true,
});
