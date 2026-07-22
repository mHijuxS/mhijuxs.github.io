# Headless Excalidraw render container.
#
# Build:   docker build -t excalidraw-render:latest tools/excalidraw_render
# Render:  docker run --rm -v "$PWD:/data" excalidraw-render:latest \
#              /data/path/to/scene.excalidraw [--svg] [--scale 2] [--dark]
#
# The Playwright base image already ships with a known-good Chromium and
# all of the OS-level libs needed by it (libnss3, libatk, fonts, ...).

FROM mcr.microsoft.com/playwright:v1.48.0-jammy

ENV NODE_ENV=production \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    NPM_CONFIG_FUND=false \
    NPM_CONFIG_AUDIT=false \
    NPM_CONFIG_UPDATE_NOTIFIER=false

WORKDIR /app

# 1. install deps (cached layer)
COPY package.json ./
RUN npm install

# 2. copy sources and bundle the in-page Excalidraw harness with esbuild
COPY entry.js ./
COPY public/ ./public/
RUN npx esbuild entry.js \
        --bundle \
        --format=iife \
        --outfile=public/bundle.js \
        --define:process.env.NODE_ENV=\"production\" \
        --loader:.woff2=dataurl \
        --loader:.woff=dataurl \
        --loader:.ttf=dataurl \
        --loader:.css=text \
        --log-level=warning \
    && ls -lh public/bundle.js

# 3. copy the render drivers
COPY render.mjs page_to_pdf.mjs ./

# Default command: print usage. Override with arguments to render a file.
ENTRYPOINT ["node", "/app/render.mjs"]
CMD ["--help"]
