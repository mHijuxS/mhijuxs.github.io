#!/usr/bin/env bash
#
# Host wrapper around the excalidraw-render Docker image.
#
# Examples:
#   tools/excalidraw_render/render.sh images/hackthebox_garfield/garfield_attack_chain.excalidraw
#   tools/excalidraw_render/render.sh path/to/scene.excalidraw --svg --scale 3
#
# The first argument is the .excalidraw file (relative or absolute). All other
# args are forwarded to render.mjs (--svg, --scale N, --dark, --out FILE, ...).
#
# The output PNG (and optional SVG) lands next to the input by default.

set -euo pipefail

if [[ $# -lt 1 || "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  cat <<'EOF'
Usage: render.sh <input.excalidraw> [render.mjs flags...]

Common flags forwarded to render.mjs:
  --svg                also write a .svg next to the .png
  --scale N            export pixel scale (default 2)
  --dark               render with Excalidraw dark mode
  --out path/file.png  override output PNG path (must be inside repo)
  --width N --height N pin output dimensions

Environment:
  EXCALIDRAW_RENDER_IMAGE  override docker image tag (default excalidraw-render:latest)
  REBUILD=1                force rebuild of the docker image before rendering
EOF
  exit "$([[ "${1:-}" == "-h" || "${1:-}" == "--help" ]] && echo 0 || echo 2)"
fi

INPUT="$1"; shift
if [[ ! -f "$INPUT" ]]; then
  echo "[!] input not found: $INPUT" >&2
  exit 2
fi

INPUT_ABS="$(realpath "$INPUT")"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Make sure the input is somewhere under the repo so we can mount the repo
# root and have stable paths inside the container.
case "$INPUT_ABS" in
  "$REPO_ROOT"/*) ;;
  *)
    echo "[!] input must live under the repo root ($REPO_ROOT)" >&2
    exit 2;;
esac

REL="${INPUT_ABS#"$REPO_ROOT/"}"

IMAGE="${EXCALIDRAW_RENDER_IMAGE:-excalidraw-render:latest}"

if [[ "${REBUILD:-0}" == "1" ]] || ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "[*] building $IMAGE from $SCRIPT_DIR ..."
  docker build -t "$IMAGE" "$SCRIPT_DIR"
fi

echo "[*] rendering $REL ..."
exec docker run --rm \
  --user "$(id -u):$(id -g)" \
  -v "$REPO_ROOT:/data:rw" \
  -e HOME=/tmp \
  -e XDG_CACHE_HOME=/tmp \
  "$IMAGE" "/data/$REL" "$@"
