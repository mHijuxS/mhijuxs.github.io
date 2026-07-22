#!/usr/bin/env node
/**
 * Render an .excalidraw scene to PNG (and optionally SVG) using a real
 * headless Chromium and the @excalidraw/excalidraw export utilities.
 *
 * Usage:
 *   node render.mjs <input.excalidraw> [--out <out.png>] [--svg] [--scale N]
 *                                      [--dark] [--width N] [--height N]
 *
 * Defaults:
 *   - output PNG goes next to the input with the same basename
 *   - SVG is also written when --svg is given
 *   - scale = 2  (retina-ish)
 *   - background = white (use --dark for Excalidraw's dark mode export)
 */

import { chromium } from "playwright";
import { fileURLToPath } from "url";
import path from "path";
import fs from "fs";

const argv = process.argv.slice(2);
if (argv.length === 0 || argv.includes("-h") || argv.includes("--help")) {
  console.error(
    "Usage: render.mjs <input.excalidraw> [--out <out.png>] [--svg] " +
      "[--scale N] [--dark] [--width N] [--height N]"
  );
  process.exit(argv.length === 0 ? 2 : 0);
}

function takeFlag(name) {
  const idx = argv.indexOf(name);
  if (idx === -1) return undefined;
  argv.splice(idx, 1);
  return true;
}

function takeOpt(name) {
  const idx = argv.indexOf(name);
  if (idx === -1) return undefined;
  const v = argv[idx + 1];
  argv.splice(idx, 2);
  return v;
}

const writeSvg = takeFlag("--svg");
const dark = takeFlag("--dark");
const scale = parseFloat(takeOpt("--scale") ?? "2");
const widthOverride = takeOpt("--width");
const heightOverride = takeOpt("--height");
const outOverride = takeOpt("--out");

const inputPath = argv[0];
if (!inputPath || !fs.existsSync(inputPath)) {
  console.error(`[!] input not found: ${inputPath}`);
  process.exit(2);
}

const scene = JSON.parse(fs.readFileSync(inputPath, "utf8"));
if (scene.type !== "excalidraw") {
  console.error(`[!] not an excalidraw scene (type=${scene.type})`);
  process.exit(2);
}

const inputAbs = path.resolve(inputPath);
const inputDir = path.dirname(inputAbs);
const inputBase = path.basename(inputAbs, path.extname(inputAbs));
const outPng = outOverride
  ? path.resolve(outOverride)
  : path.join(inputDir, inputBase + ".png");
const outSvg = path.join(
  path.dirname(outPng),
  path.basename(outPng, path.extname(outPng)) + ".svg"
);

const here = path.dirname(fileURLToPath(import.meta.url));
const harnessUrl =
  "file://" + path.join(here, "public", "index.html");

console.log(`[*] input : ${inputAbs}`);
console.log(`[*] output: ${outPng}${writeSvg ? " (+ .svg)" : ""}`);
console.log(`[*] harness: ${harnessUrl}`);

const browser = await chromium.launch({
  args: ["--font-render-hinting=none"],
});
const page = await browser.newPage({
  viewport: { width: 2400, height: 1600 },
  deviceScaleFactor: 2,
});

page.on("console", (msg) => {
  const t = msg.type();
  if (t === "error" || t === "warning") {
    console.log(`[browser:${t}] ${msg.text()}`);
  }
});
page.on("pageerror", (e) => console.log(`[browser:pageerror] ${e.message}`));

await page.goto(harnessUrl);
await page.waitForFunction(() => window.__excalidraw_ready__ === true, {
  timeout: 15000,
});

// Make sure web fonts are loaded before exporting
await page.evaluate(async () => {
  if (document.fonts && document.fonts.ready) {
    await document.fonts.ready;
  }
});

const result = await page.evaluate(
  async ({ scene, scale, dark, widthOverride, heightOverride, writeSvg }) => {
    const elements = scene.elements || [];
    const files = scene.files || {};
    const baseAppState = scene.appState || {};

    const exportAppState = {
      ...baseAppState,
      exportBackground: true,
      exportWithDarkMode: !!dark,
      exportScale: scale,
      viewBackgroundColor: dark
        ? baseAppState.viewBackgroundColor || "#121212"
        : "#ffffff",
      // hide grid in export
      gridSize: null,
    };

    const blobOpts = {
      elements,
      appState: exportAppState,
      files,
      mimeType: "image/png",
      quality: 1,
      exportPadding: 24,
    };
    if (widthOverride && heightOverride) {
      const w = parseInt(widthOverride, 10);
      const h = parseInt(heightOverride, 10);
      blobOpts.getDimensions = () => ({ width: w, height: h, scale });
    }

    const pngBlob = await window.exportToBlob(blobOpts);
    const pngBuf = new Uint8Array(await pngBlob.arrayBuffer());

    let svgText = null;
    if (writeSvg) {
      const svgEl = await window.exportToSvg({
        elements,
        appState: exportAppState,
        files,
        exportPadding: 24,
      });
      svgText = new XMLSerializer().serializeToString(svgEl);
    }

    return {
      png: Array.from(pngBuf),
      svg: svgText,
    };
  },
  { scene, scale, dark, widthOverride, heightOverride, writeSvg }
);

fs.writeFileSync(outPng, Buffer.from(result.png));
console.log(`[+] wrote ${outPng}  (${result.png.length} bytes)`);

if (writeSvg && result.svg) {
  fs.writeFileSync(outSvg, result.svg);
  console.log(`[+] wrote ${outSvg}  (${result.svg.length} chars)`);
}

await browser.close();
