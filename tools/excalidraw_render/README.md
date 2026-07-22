# excalidraw-render

Headless renderer for `.excalidraw` scenes used in HTB / CTF writeups.

This folder ships:

- a small **Dockerfile** based on the official Playwright image,
- an **esbuild bundle** of `@excalidraw/excalidraw@0.18.0` exposing
  `exportToBlob` / `exportToSvg` / `exportToCanvas` on `window`,
- a **`render.mjs`** Node driver that opens a tiny static HTML harness in
  headless Chromium and runs the export utilities against any scene file,
- a **`render.sh`** host wrapper that builds the image on first use and runs
  it with the repo root mounted at `/data`.

The version of `@excalidraw/excalidraw` is pinned (0.18.0) so the schema
matches what `images/hackthebox_garfield/build_attack_chain.py` and any
future scene generators emit.

## Quick start

From the repo root:

```bash
# 1. (one-off) build the image
docker build -t excalidraw-render:latest tools/excalidraw_render

# 2. render a scene to PNG (and SVG)
tools/excalidraw_render/render.sh \
  images/hackthebox_garfield/garfield_attack_chain.excalidraw --svg
```

The PNG (and `.svg`, when `--svg` is passed) lands next to the input file.

## Scene generator workflow

The intended workflow for a new writeup:

```
images/<post_slug>/
├── build_attack_chain.py        # Python generator that emits the scene JSON
├── attack_chain.excalidraw      # generated scene (commit this)
├── attack_chain.png             # exported PNG (referenced from the post)
└── attack_chain.svg             # optional SVG version
```

Loop:

```bash
# 1. tweak / extend the scene generator
$EDITOR images/<slug>/build_attack_chain.py
python3 images/<slug>/build_attack_chain.py

# 2. re-render to PNG
tools/excalidraw_render/render.sh images/<slug>/attack_chain.excalidraw --svg

# 3. reference it from the post:
#    ![Attack chain](attack_chain.png)
```

## Render options

`render.sh` forwards every flag past the input path to `render.mjs`:

| Flag                 | Meaning                                                  |
|----------------------|----------------------------------------------------------|
| `--svg`              | also write a `.svg` next to the `.png`                   |
| `--scale N`          | export pixel scale (default 2 — retina-ish)              |
| `--dark`             | export with Excalidraw dark mode                         |
| `--out PATH`         | override the PNG path (must live under the repo root)    |
| `--width N --height N` | pin the export dimensions                              |

Environment:

| Var                       | Default                       | Meaning                          |
|---------------------------|-------------------------------|----------------------------------|
| `EXCALIDRAW_RENDER_IMAGE` | `excalidraw-render:latest`    | Docker tag to use                |
| `REBUILD=1`               | unset                         | force a rebuild before rendering |

## How it works

1. The Dockerfile starts from `mcr.microsoft.com/playwright:v1.48.0-jammy`
   which already has Chromium + every shared lib it needs.
2. `npm install` pulls in `@excalidraw/excalidraw`, `react`, `react-dom` and
   `playwright`.
3. `esbuild entry.js --bundle` produces `public/bundle.js`, an IIFE that
   exposes `window.exportToBlob`, `window.exportToSvg`, etc.
4. `render.mjs`:
   - launches headless Chromium via Playwright,
   - opens `public/index.html`, which loads `bundle.js`,
   - waits for `window.__excalidraw_ready__`,
   - reads the input `.excalidraw` JSON, evaluates `exportToBlob` /
     `exportToSvg` inside the page with the scene's `elements` / `appState`,
   - writes the resulting PNG (and optional SVG) to disk.
5. `render.sh` mounts the repo root at `/data`, computes the relative path
   of the input file inside the repo and feeds the container an absolute
   path under `/data` so all outputs land where you expect them on the host.

## Notes

- The scene's `appState.viewBackgroundColor` is forced to `#ffffff` for the
  light export and `#121212` for `--dark`. Override with `--width / --height`
  if a scene clips at the default 24px export padding.
- Excalidraw's hand-drawn rendering is deterministic per `seed` field on
  each element, which is why the Python generator seeds `random.seed(1337)`.
  Re-running the generator and the renderer reproduces the exact same image.
