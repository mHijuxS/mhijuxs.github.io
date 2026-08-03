#!/usr/bin/env python3
"""
Generate an Excalidraw scene for the HacksmarterLabs Second attack chain.

Outputs:  second_attack_chain.excalidraw  (renders via tools/excalidraw_render/render.sh)

Vertical layout: time flows top-to-bottom in a single main column. Each
credential hop is a user/role node; the AWS service that leaked it sits
between them. One dead-end side branch (the Lambda deployment package) is
parked on the left, close to its origin.

Design conventions match images/hackthebox_garfield/build_attack_chain.py and
images/hacksmarter_nova-forge/build_attack_chain.py so every diagram in the
repo reads as the same visual system.
"""

import json
import random
import time

random.seed(1337)

def rid():
    return "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=16))

def now_ms():
    return int(time.time() * 1000)

# ---------- palette (dark canvas + light pastel "sticky note" nodes) --------

BG_COLOR      = "#1e1e1e"
USER_FILL,    USER_STROKE     = "#fff3bf", "#f08c00"   # warm yellow / orange
COMP_FILL,    COMP_STROKE     = "#a5d8ff", "#1864ab"   # cool blue
GROUP_FILL,   GROUP_STROKE    = "#d0bfff", "#5f3dc4"   # violet
ARTIFACT_FILL,ARTIFACT_STROKE = "#ffd8a8", "#d9480f"   # peach
LABEL_FILL,   LABEL_STROKE    = "#2b2b2b", "#5a5a5a"   # dark badge, subtle border
NODE_TEXT     = "#1e1e1e"                              # dark text on pastel node
LABEL_TEXT    = "#e9ecef"                              # light text on dark badge
TITLE_COLOR   = "#adb5bd"                              # neutral light grey

PHASE_COLORS = {
    "enum":   "#51cf66",   # green      - starter key + control-plane enumeration
    "lambda": "#69db7c",   # lt green   - Lambda environment variables
    "s3":     "#4dabf7",   # blue       - S3 script bucket
    "recon":  "#b197fc",   # violet     - EC2 describe -> public WordPress host
    "rce":    "#ff922b",   # orange     - wp2shell pre-auth RCE
    "imds":   "#ff6b6b",   # pink       - instance metadata credential theft
    "loot":   "#ff5252",   # bright red - Secrets Manager
}

FONT_FAMILY = 1
LINE_HEIGHT = 1.25

# ---------- element factories ----------------------------------------------

def base(kind, x, y, w, h, stroke, fill, *, fill_style="solid",
         stroke_style="solid", stroke_width=2, roundness_type=None):
    return {
        "id": rid(),
        "type": kind,
        "x": x, "y": y, "width": w, "height": h, "angle": 0,
        "strokeColor": stroke,
        "backgroundColor": fill,
        "fillStyle": fill_style,
        "strokeWidth": stroke_width,
        "strokeStyle": stroke_style,
        "roughness": 1,
        "opacity": 100,
        "groupIds": [], "frameId": None, "index": None,
        "roundness": {"type": roundness_type} if roundness_type else None,
        "seed": random.randint(1, 2**31 - 1),
        "version": 1,
        "versionNonce": random.randint(1, 2**31 - 1),
        "isDeleted": False,
        "boundElements": [],
        "updated": now_ms(),
        "link": None,
        "locked": False,
    }

def text_elem(x, y, w, h, text, *, color=NODE_TEXT,
              container_id=None, size=18, align="center"):
    return {
        **base("text", x, y, w, h, color, "transparent"),
        "fontSize": size,
        "fontFamily": FONT_FAMILY,
        "text": text,
        "textAlign": align,
        "verticalAlign": "middle",
        "containerId": container_id,
        "originalText": text,
        "autoResize": True,
        "lineHeight": LINE_HEIGHT,
    }

def shape_with_label(kind, stroke, fill, x, y, w, h, label,
                     *, roundness=3, font_size=18, stroke_style="solid"):
    shape = base(kind, x, y, w, h, stroke, fill,
                 stroke_style=stroke_style, roundness_type=roundness)
    if kind == "ellipse":
        pad_x, pad_y = 26, 12
    elif kind == "diamond":
        pad_x, pad_y = 44, 30
    else:
        pad_x, pad_y = 12, 10
    txt = text_elem(x + pad_x, y + pad_y, w - 2 * pad_x, h - 2 * pad_y, label,
                    container_id=shape["id"], size=font_size)
    shape["boundElements"] = [{"id": txt["id"], "type": "text"}]
    return shape, txt

def user_node(cx, cy, label, w=300, h=96):
    return shape_with_label("ellipse", USER_STROKE, USER_FILL,
                            cx - w/2, cy - h/2, w, h, label, font_size=16)

def computer_node(cx, cy, label, w=320, h=100):
    return shape_with_label("rectangle", COMP_STROKE, COMP_FILL,
                            cx - w/2, cy - h/2, w, h, label, font_size=16)

def artifact_node(cx, cy, label, w=360, h=100):
    return shape_with_label("rectangle", ARTIFACT_STROKE, ARTIFACT_FILL,
                            cx - w/2, cy - h/2, w, h, label,
                            font_size=14, stroke_style="dashed")

def edge_label(cx, cy, text, *, max_chars=None):
    lines = text.split("\n")
    line_w = max(len(l) for l in lines)
    if max_chars:
        line_w = min(line_w, max_chars)
    char_w, line_h = 7.2, 17
    w = max(140, int(line_w * char_w) + 22)
    h = max(28, len(lines) * line_h + 14)
    rect = base("rectangle", cx - w/2, cy - h/2, w, h,
                LABEL_STROKE, LABEL_FILL,
                stroke_width=1, roundness_type=3)
    txt = text_elem(cx - w/2 + 6, cy - h/2 + 6, w - 12, h - 12,
                    text, container_id=rect["id"], size=13,
                    color=LABEL_TEXT)
    rect["boundElements"] = [{"id": txt["id"], "type": "text"}]
    return [rect, txt], (w, h)

def _shape_edge_point(shape, tx, ty, gap=6):
    """
    Return the point on the shape's boundary where the line from the shape's
    centre toward (tx, ty) exits, plus a small outward `gap` so the arrowhead
    sits cleanly off the border. Handles rectangle / ellipse / diamond.
    """
    cx = shape["x"] + shape["width"] / 2
    cy = shape["y"] + shape["height"] / 2
    dx, dy = tx - cx, ty - cy
    if dx == 0 and dy == 0:
        return cx, cy

    kind = shape["type"]
    w, h = shape["width"], shape["height"]

    if kind == "ellipse":
        a, b = w / 2, h / 2
        t = 1.0 / ((dx / a) ** 2 + (dy / b) ** 2) ** 0.5
    elif kind == "diamond":
        t = 1.0 / (abs(dx) / (w / 2) + abs(dy) / (h / 2))
    else:  # rectangle
        hx, hy = w / 2, h / 2
        tx_edge = float("inf") if dx == 0 else hx / abs(dx)
        ty_edge = float("inf") if dy == 0 else hy / abs(dy)
        t = min(tx_edge, ty_edge)

    ex, ey = cx + t * dx, cy + t * dy
    d = (dx * dx + dy * dy) ** 0.5
    return ex + gap * dx / d, ey + gap * dy / d


def arrow(src, dst, *, color, label=None, label_side=1, label_dist=32,
          stroke_width=2.6):
    src_cx = src["x"] + src["width"] / 2
    src_cy = src["y"] + src["height"] / 2
    dst_cx = dst["x"] + dst["width"] / 2
    dst_cy = dst["y"] + dst["height"] / 2

    sx, sy = _shape_edge_point(src, dst_cx, dst_cy, gap=6)
    dx, dy = _shape_edge_point(dst, src_cx, src_cy, gap=6)

    arr = {
        **base("arrow", sx, sy, dx - sx, dy - sy, color, "transparent",
               stroke_width=stroke_width),
        "points": [[0, 0], [dx - sx, dy - sy]],
        "lastCommittedPoint": None,
        "startBinding": {"elementId": src["id"], "focus": 0, "gap": 0},
        "endBinding":   {"elementId": dst["id"], "focus": 0, "gap": 0},
        "startArrowhead": None,
        "endArrowhead": "arrow",
        "elbowed": False,
    }
    src["boundElements"] = (src.get("boundElements") or []) + [
        {"id": arr["id"], "type": "arrow"}]
    dst["boundElements"] = (dst.get("boundElements") or []) + [
        {"id": arr["id"], "type": "arrow"}]

    out = [arr]
    if label:
        mx = (sx + dx) / 2
        my = (sy + dy) / 2
        ax, ay = dx - sx, dy - sy
        L = (ax * ax + ay * ay) ** 0.5 or 1.0
        nx, ny = -ay / L * label_side, ax / L * label_side
        lx = mx + nx * label_dist
        ly = my + ny * label_dist
        label_elems, _ = edge_label(lx, ly, label)
        out += label_elems
    return out

# ---------- scene layout ----------------------------------------------------

MAIN_X = 900
LEFT_X = 320

Y = {
    "pentest":   250,
    "lambdafn":  470,
    # LEFT lane, dead-end deployment package. Offset upward from the Lambda
    # node so the branch arrow runs diagonally and its label has clear space
    # instead of landing on top of the artifact box.
    "pkg":       285,
    "envvars":   690,
    "lambdamgr": 910,
    "bucket":   1130,
    "script":   1350,
    "deploy":   1570,
    "ec2":      1810,
    "shell":    2040,
    "imds":     2270,
    "role":     2500,
    "secret":   2720,
}

elements = []

pentest, pentest_t = user_node(
    MAIN_X, Y["pentest"],
    "cg-pentest-lab\nlong-term key AKIA...IDUW3", w=380)

lambdafn, lambdafn_t = computer_node(
    MAIN_X, Y["lambdafn"],
    "Lambda cg-log-processor-lab\nrole cg-lambda-role-lab", w=380)

pkg, pkg_t = artifact_node(
    LEFT_X, Y["pkg"],
    "get-function Code.Location\n-> cg-log-processor.zip\nlambda.py is a stub (dead end)", w=360)

envvars, envvars_t = artifact_node(
    MAIN_X, Y["envvars"],
    "Environment.Variables\nLAMBDA_MANAGER_AK / _SK\nplaintext in the API response", w=400)

lambdamgr, lambdamgr_t = user_node(
    MAIN_X, Y["lambdamgr"],
    "cg-lambda-manager-lab\ns3:ListAllMyBuckets + read", w=400, h=100)

bucket, bucket_t = computer_node(
    MAIN_X, Y["bucket"],
    "S3 cg-engineering-scripts-lab\n-067103977971", w=380)

script, script_t = artifact_node(
    MAIN_X, Y["script"],
    "deployment-script.sh\nexport AWS_ACCESS_KEY_ID=AKIA...WVGI\nhardcoded in a backup job", w=440)

deploy, deploy_t = user_node(
    MAIN_X, Y["deploy"],
    "deployment identity\nec2:Describe*", w=340)

ec2, ec2_t = computer_node(
    MAIN_X, Y["ec2"],
    "EC2 cg-marketing-wp-lab\n98.92.131.16  WordPress 6.9\nIMDSv1 allowed, profile attached", w=460, h=110)

shell, shell_t = artifact_node(
    MAIN_X, Y["shell"],
    "wp2shell plugin webshell\nuid=33(www-data)", w=380)

imds, imds_t = computer_node(
    MAIN_X, Y["imds"],
    "IMDS 169.254.169.254\n/latest/meta-data/iam/\nsecurity-credentials/", w=400, h=110)

role, role_t = user_node(
    MAIN_X, Y["role"],
    "assumed-role/cg-ec2-role-lab\nASIA... + session token", w=440, h=100)

secret, secret_t = computer_node(
    MAIN_X, Y["secret"],
    "Secrets Manager\ncg-final-flag-lab", w=340)

elements += [
    pentest, pentest_t, lambdafn, lambdafn_t, pkg, pkg_t,
    envvars, envvars_t, lambdamgr, lambdamgr_t,
    bucket, bucket_t, script, script_t, deploy, deploy_t,
    ec2, ec2_t, shell, shell_t, imds, imds_t, role, role_t,
    secret, secret_t,
]

edges = [
    (pentest,   lambdafn,  "enum",   -1, 30, "aws lambda list-functions"),
    (lambdafn,  pkg,       "lambda", +1, 44, "presigned S3 URL\n(no s3: permission needed)"),
    (lambdafn,  envvars,   "lambda", -1, 26, "ListFunctions returns the full\nFunctionConfiguration"),
    (envvars,   lambdamgr, "lambda", -1, 26, "load AK/SK as a new profile\nsts get-caller-identity"),
    (lambdamgr, bucket,    "s3",     -1, 26, "aws s3 ls"),
    (bucket,    script,    "s3",     -1, 26, "aws s3 cp s3://.../deployment-script.sh"),
    (script,    deploy,    "s3",     -1, 26, "third long-term key,\nthird identity"),
    (deploy,    ec2,       "recon",  -1, 26, "aws ec2 describe-instances\n-> public IP + MetadataOptions"),
    (ec2,       shell,     "rce",    -1, 26, "wp2shell shell --interactive\nbatch route confusion -> SQLi\n-> pre-auth admin -> plugin upload"),
    (shell,     imds,      "imds",   -1, 26, "curl from inside the instance\n(HttpTokens: optional)"),
    (imds,      role,      "imds",   -1, 26, "role name is not the profile name,\nlist the directory first"),
    (role,      secret,    "loot",   -1, 26, "list-secrets + get-secret-value"),
]

for src, dst, phase, side, dist, lbl in edges:
    elements += arrow(src, dst, color=PHASE_COLORS[phase],
                      label=lbl, label_side=side, label_dist=dist)

# ---------- title + subtitle -----------------------------------------------

elements.append(text_elem(60, 40, 1800, 48,
    "HacksmarterLabs - Second - Attack Chain",
    color=TITLE_COLOR, size=30, align="left"))
elements.append(text_elem(60, 92, 1800, 28,
    "Reads top-to-bottom. Four distinct AWS identities, each one handed over by the previous one. The only non-AWS step is the WordPress RCE that puts us inside the instance's network namespace.",
    color=TITLE_COLOR, size=14, align="left"))

# ---------- legend ----------------------------------------------------------

ly0 = Y["secret"] + 220
legend_shapes = [
    ("ellipse",   USER_STROKE,     USER_FILL,     "solid",  "IAM identity (user / assumed role)"),
    ("rectangle", COMP_STROKE,     COMP_FILL,     "solid",  "AWS service or host"),
    ("rectangle", ARTIFACT_STROKE, ARTIFACT_FILL, "dashed", "artifact (credential / file / shell)"),
]
for i, (shape, stroke, fill, sty, label) in enumerate(legend_shapes):
    sx = 60
    sy = ly0 + i * 60
    swatch = base(shape, sx, sy, 60, 36, stroke, fill,
                  stroke_style=sty, roundness_type=3)
    elements.append(swatch)
    elements.append(text_elem(sx + 76, sy + 4, 800, 28, label,
                              color=TITLE_COLOR, size=15, align="left"))

ly1 = ly0 + 210
elements.append(text_elem(60, ly1, 800, 28,
    "Arrow colours (attack phase):",
    color=TITLE_COLOR, size=16, align="left"))

phase_legend = [
    ("enum",   "control-plane enumeration with the starter key"),
    ("lambda", "Lambda environment variables leak a second key"),
    ("s3",     "S3 script bucket leaks a third key"),
    ("recon",  "EC2 describe finds the public WordPress host"),
    ("rce",    "wp2shell pre-auth route confusion to plugin webshell"),
    ("imds",   "instance metadata service hands over the role"),
    ("loot",   "Secrets Manager holds the final secret"),
]
for i, (phase, label) in enumerate(phase_legend):
    sx = 60
    sy = ly1 + 40 + i * 36
    swatch = base("rectangle", sx, sy + 10, 60, 6, PHASE_COLORS[phase],
                  PHASE_COLORS[phase], stroke_width=1, roundness_type=3)
    elements.append(swatch)
    elements.append(text_elem(sx + 76, sy, 800, 28, label,
                              color=TITLE_COLOR, size=14, align="left"))

# ---------- serialise --------------------------------------------------------

scene = {
    "type": "excalidraw",
    "version": 2,
    "source": "https://writeups.mhsferreira.com",
    "elements": elements,
    "appState": {
        "gridSize": 20,
        "gridStep": 5,
        "gridModeEnabled": False,
        "viewBackgroundColor": BG_COLOR,
    },
    "files": {},
}

OUT = "second_attack_chain.excalidraw"
with open(OUT, "w") as f:
    json.dump(scene, f, indent=2)
print(f"[+] wrote {OUT}  ({len(elements)} elements)")
