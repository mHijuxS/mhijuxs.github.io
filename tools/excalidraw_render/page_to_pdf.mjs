#!/usr/bin/env node
/**
 * Render a Jekyll-built page to PDF using the same headless Chromium that
 * the excalidraw renderer uses. Spins up a tiny in-process static file
 * server rooted at /data/_site so the page resolves all of its CSS / JS /
 * images / fonts exactly the way it does on the live site.
 *
 * Usage (inside the container):
 *   node page_to_pdf.mjs <url-path-under-_site> <output.pdf> [--dark]
 *
 * Example:
 *   node page_to_pdf.mjs /posts/hackthebox-garfield/ \
 *        /data/images/hackthebox_garfield/garfield_post.pdf
 */

import { chromium } from "playwright";
import http from "http";
import fs from "fs";
import path from "path";

const SITE_ROOT = "/data/_site";
const argv = process.argv.slice(2);

function takeFlag(name) {
  const i = argv.indexOf(name);
  if (i === -1) return false;
  argv.splice(i, 1);
  return true;
}

// dark mode is the default, --light opts back to a white-background render
const lightFlag = takeFlag("--light");
const darkFlag  = takeFlag("--dark"); // accepted for backwards-compat but is the default
const dark = !lightFlag;
void darkFlag;

const urlPath = argv[0];
const outPdf = argv[1];

if (!urlPath || !outPdf) {
  console.error(
    "Usage: page_to_pdf.mjs <url-path-under-_site> <output.pdf> [--light]"
  );
  process.exit(2);
}

if (!fs.existsSync(SITE_ROOT)) {
  console.error(`[!] ${SITE_ROOT} does not exist - run 'bundle exec jekyll build' first`);
  process.exit(2);
}

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".css":  "text/css; charset=utf-8",
  ".js":   "application/javascript; charset=utf-8",
  ".mjs":  "application/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg":  "image/svg+xml",
  ".png":  "image/png",
  ".jpg":  "image/jpeg",
  ".jpeg": "image/jpeg",
  ".gif":  "image/gif",
  ".webp": "image/webp",
  ".woff":  "font/woff",
  ".woff2": "font/woff2",
  ".ttf":   "font/ttf",
  ".otf":   "font/otf",
  ".ico":   "image/x-icon",
  ".map":   "application/json; charset=utf-8",
  ".txt":   "text/plain; charset=utf-8",
  ".xml":   "application/xml; charset=utf-8",
};

function serveFile(res, filePath) {
  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404, { "Content-Type": "text/plain" });
      res.end("Not found");
      return;
    }
    const ext = path.extname(filePath).toLowerCase();
    res.writeHead(200, { "Content-Type": MIME[ext] || "application/octet-stream" });
    res.end(data);
  });
}

const server = http.createServer((req, res) => {
  let urlClean = decodeURIComponent(req.url.split("?")[0]);
  if (urlClean.endsWith("/")) urlClean += "index.html";

  // Resolve under _site, prevent path traversal
  const resolved = path.normalize(path.join(SITE_ROOT, urlClean));
  if (!resolved.startsWith(SITE_ROOT)) {
    res.writeHead(403); res.end("forbidden"); return;
  }

  fs.stat(resolved, (err, st) => {
    if (err) {
      // try .html fallback
      const alt = resolved.replace(/\/?$/, "") + "/index.html";
      if (fs.existsSync(alt)) return serveFile(res, alt);
      res.writeHead(404, { "Content-Type": "text/plain" });
      res.end("Not found: " + urlClean);
      return;
    }
    if (st.isDirectory()) {
      return serveFile(res, path.join(resolved, "index.html"));
    }
    return serveFile(res, resolved);
  });
});

await new Promise((r) => server.listen(0, "127.0.0.1", r));
const port = server.address().port;
const fullUrl = `http://127.0.0.1:${port}${urlPath}`;
console.log(`[*] serving ${SITE_ROOT} on ${fullUrl}`);

const browser = await chromium.launch({ args: ["--font-render-hinting=none"] });
const ctx = await browser.newContext({
  viewport: { width: 1280, height: 1800 },
  deviceScaleFactor: 2,
  colorScheme: dark ? "dark" : "light",
});
const page = await ctx.newPage();

page.on("pageerror", (e) => console.log(`[browser:pageerror] ${e.message}`));
page.on("console", (m) => {
  const t = m.type();
  if (t === "error" || t === "warning") console.log(`[browser:${t}] ${m.text()}`);
});

console.log(`[*] navigating to ${fullUrl}`);
await page.goto(fullUrl, { waitUntil: "networkidle", timeout: 120000 });

// Force the requested colour mode via Chirpy's mode toggle
await page.evaluate((isDark) => {
  document.documentElement.setAttribute("data-mode", isDark ? "dark" : "light");
  try { localStorage.setItem("mode", isDark ? "dark" : "light"); } catch (_) {}
}, dark);
await page.waitForTimeout(300);

// Expand any <details> elements so collapsed content actually appears in the PDF
await page.evaluate(() => {
  document.querySelectorAll("details").forEach((d) => (d.open = true));
});

// --- Force ALL images to load eagerly. Chirpy stamps loading="lazy" on every
// image in a post and uses lozad/IntersectionObserver to swap them in when
// they scroll into view, headless Chromium during a `page.pdf` render never
// scrolls, so without this every screenshot below the fold stays as a blank
// placeholder in the PDF.
await page.evaluate(() => {
  document.querySelectorAll("img").forEach((img) => {
    img.loading = "eager";
    img.decoding = "sync";
    // lozad / lazyload variants
    if (img.dataset.src) {
      img.src = img.dataset.src;
      delete img.dataset.src;
    }
    if (img.dataset.srcset) {
      img.srcset = img.dataset.srcset;
      delete img.dataset.srcset;
    }
    img.classList.remove("lazyload", "lazyloaded", "lozad", "shimmer");
  });
});

// Slow-scroll the entire page top → bottom in steps so any IntersectionObserver
// based loaders (lozad, lazyload) fire on every image even if the eager swap
// above missed something theme-specific.
await page.evaluate(async () => {
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const step = window.innerHeight * 0.8;
  for (let y = 0; y < document.body.scrollHeight; y += step) {
    window.scrollTo(0, y);
    await sleep(80);
  }
  window.scrollTo(0, document.body.scrollHeight);
  await sleep(200);
  window.scrollTo(0, 0);
});

// Now wait until every image is actually decoded (or fails). 60s budget per image.
const imgStats = await page.evaluate(async () => {
  const imgs = Array.from(document.images);
  const results = await Promise.all(
    imgs.map(
      (img) =>
        new Promise((resolve) => {
          if (img.complete && img.naturalWidth > 0) {
            return resolve({ src: img.src, ok: true, w: img.naturalWidth });
          }
          let done = false;
          const finish = (ok) => {
            if (done) return;
            done = true;
            resolve({ src: img.src, ok, w: img.naturalWidth });
          };
          img.addEventListener("load", () => finish(true), { once: true });
          img.addEventListener("error", () => finish(false), { once: true });
          // hard cap so a single broken image cannot stall the whole render
          setTimeout(() => finish(img.complete && img.naturalWidth > 0), 60000);
        })
    )
  );
  return {
    total: results.length,
    loaded: results.filter((r) => r.ok).length,
    failed: results.filter((r) => !r.ok).map((r) => r.src),
  };
});
console.log(
  `[*] images: ${imgStats.loaded}/${imgStats.total} loaded` +
    (imgStats.failed.length ? `, failed: ${imgStats.failed.join(", ")}` : "")
);

// One more font check after the scroll triggered any newly-injected images
await page.evaluate(async () => {
  if (document.fonts && document.fonts.ready) await document.fonts.ready;
});

// Inject print-friendly CSS so layout reflows for paper instead of clipping
// the Chirpy sidebar / TOC.
await page.addStyleTag({
  content: `
    @page { size: A4; margin: 18mm 14mm; }
    /* hide the chirpy sidebar / topbar / panel / search / TOC for printing */
    #sidebar, #topbar-wrapper, #panel-wrapper, #search-result-wrapper,
    #search-results, #search, #toc-wrapper, .toc, .access-tags,
    .post-navigation, #disqus_thread, .related-posts, footer { display: none !important; }
    /* let the post column take the full width */
    main, #main, #core-wrapper, .col-11, .col-lg-11, .col-md-12 {
      max-width: 100% !important;
      flex: 0 0 100% !important;
      width: 100% !important;
      margin-left: 0 !important;
    }
    /* never break inside code blocks or images */
    pre, table, img { break-inside: avoid; page-break-inside: avoid; }
    /* slightly tighter line height for paper */
    body { font-size: 11pt; line-height: 1.45; }
    pre, code { font-size: 9pt; }
    /* keep images contained inside the printable column */
    img { max-width: 100% !important; height: auto !important; }
  `,
});

// Tell Chromium to render with @media print so any other print rules kick in
await page.emulateMedia({ media: "print" });

console.log(`[*] writing ${outPdf}`);
await page.pdf({
  path: outPdf,
  format: "A4",
  printBackground: true,
  margin: { top: "18mm", bottom: "18mm", left: "14mm", right: "14mm" },
  preferCSSPageSize: true,
});

await browser.close();
server.close();

console.log(`[+] wrote ${outPdf}`);
