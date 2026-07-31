#!/usr/bin/env python3
"""
Generate an Excalidraw scene for the HacksmarterLabs Nova Forge attack chain.

Outputs:  nova_forge_attack_chain.excalidraw  (renders via tools/excalidraw_render/render.sh)

Vertical layout: time flows top-to-bottom in a single main column, with short
side branches placed close to their origin/target so no arrow ever crosses a
node it doesn't belong to.

Design conventions match images/hackthebox_garfield/build_attack_chain.py so
both diagrams read as the same visual system across the repo.
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
# Dark viewBackground; nodes keep the original saturated pastels so their
# text stays dark-on-light (max contrast). Arrows and labels use lighter
# accents so they read against the dark bg.

BG_COLOR      = "#1e1e1e"
USER_FILL,    USER_STROKE     = "#fff3bf", "#f08c00"   # warm yellow / orange
COMP_FILL,    COMP_STROKE     = "#a5d8ff", "#1864ab"   # cool blue
GROUP_FILL,   GROUP_STROKE    = "#d0bfff", "#5f3dc4"   # violet
ARTIFACT_FILL,ARTIFACT_STROKE = "#ffd8a8", "#d9480f"   # peach
LABEL_FILL,   LABEL_STROKE    = "#2b2b2b", "#5a5a5a"   # dark badge, subtle border
NODE_TEXT     = "#1e1e1e"                              # dark text on pastel node
LABEL_TEXT    = "#e9ecef"                              # light text on dark badge
TITLE_COLOR   = "#adb5bd"                              # neutral light grey

# Brighter, higher-saturation strokes so arrows pop against dark bg
PHASE_COLORS = {
    "phish":      "#51cf66",   # green    - SMTP flat-OPC -> john.doe hash
    "kerberoast": "#69db7c",   # lt green - AD Recycle Bin + targeted kerberoast
    "acl":        "#4dabf7",   # blue     - ACL chain m.lee -> daniel.brooks
    "loot":       "#b197fc",   # violet   - Opera DPAPI + storage portal
    "coerce":     "#ff922b",   # orange   - CVE-2025-33073 CMTI + PetitPotam
    "lsa":        "#ff6b6b",   # pink     - LSA secrets + password spray
    "delegate":   "#ffa94d",   # amber    - Protected Users escape + delegation
    "da":         "#ff5252",   # bright red - WriteSPN sname rewrite -> DA
}

FONT_FAMILY = 1
LINE_HEIGHT = 1.25

# ---------- element factories (same as Garfield) ----------------------------

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
    # available. Ellipses' inscribed rectangle is ~70% of the box, so text
    # centered in the full box overflows the ellipse near the sides.
    # Diamonds are the worst offender: width at top/bottom vertices is zero,
    # so anything that isn't a short single line needs to be pushed further
    # inward so Excalidraw wraps it inside the visible interior.
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
    # Direction from source centre to destination centre picks which edge
    # each endpoint clips against.
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
        # gap:0 because we already clipped the line to the shape edge above;
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
# Side branches sit at LEFT_X / RIGHT_X, always close to their origin so
# arrows never cross an unrelated node.

MAIN_X   = 900
LEFT_X   = 340
RIGHT_X  = 1500

# Y band for each step (top-to-bottom). Spacing is tuned so 100px-tall nodes
# never touch their neighbour and short-branch arrows have room for a label.
Y = {
    "attacker":   240,
    "smtp":       420,
    "johndoe":    600,
    "mlee":       800,
    "stevew":    1000,
    "itsu":      1200,
    "noah":      1420,
    "stevm":     1620,
    "tier1":     1820,
    "daniel":    2040,

    # daniel.brooks fans out into two side branches at the coerce y-band:
    # LEFT_X: DC WinRM chain (Opera / chuck / portal)
    # MAIN_X: continues into DNS / coerce / relay chain
    # WriteSPN sits far down on the right, close to where its ticket is used.
    "dc":        2240,   # LEFT lane, WinRM foothold
    "opera":     2440,   # LEFT lane
    "chuck":     2640,   # LEFT lane
    "portal":    2840,   # LEFT lane, "disable SMB signing"
    "dns":       2240,   # MAIN lane, DNS write with CMTI
    "cmti":      2440,   # MAIN lane, PetitPotam coerce
    "sam":       2640,   # MAIN lane, STORAGE\Administrator NTLM
    "lsa":       2840,   # MAIN lane, LSA DefaultPassword

    "cokx":      2840,   # right-side branch aligned with LSA (short arrows)
    "frank":     3060,   # main chain: 1hatefrank spray
    "svcit":     3300,   # main chain: convergence (frank FCP + cokx remove PU)
    "writespn":  3320,   # RIGHT lane, next to s4u so its arrow is short
    "s4u":       3540,   # main chain: getST + altservice
    "admin":     3760,   # main chain: DA
}

elements = []

# --- Row 1: phish / initial NetNTLMv2 -----------------------------------

attacker, attacker_t = user_node(LEFT_X, Y["attacker"], "attacker\n(unauth)", w=220)
smtp,     smtp_t     = computer_node(MAIN_X, Y["smtp"],
                                     "DC :25 hMailServer\n(rescan -p 25 finds it)")
johndoe,  johndoe_t  = artifact_node(MAIN_X, Y["johndoe"],
                                     "john.doe NetNTLMv2\n-> hashcat 5600 -> johndoe1369")

# --- Row 2: AD Recycle Bin + targeted Kerberoast ------------------------

mlee, mlee_t = user_node(MAIN_X, Y["mlee"], "m.lee\n(restored from Recycle Bin)", w=340, h=100)

# --- Row 3: ACL chain (7 nodes stacked vertically) ----------------------

stevew, stevew_t = user_node(MAIN_X,  Y["stevew"], "steve.wills")
itsu,   itsu_t   = group_node(MAIN_X, Y["itsu"],   "IT Support\nUsers", w=340, h=170)
noah,   noah_t   = user_node(MAIN_X,  Y["noah"],   "noah.sanders")
stevm,  stevm_t  = user_node(MAIN_X,  Y["stevm"],  "steve.miller")
tier1,  tier1_t  = group_node(MAIN_X, Y["tier1"],  "OU=\nTier1-Support",  w=340, h=170)
daniel, daniel_t = user_node(MAIN_X,  Y["daniel"], "daniel.brooks", w=280)

# --- Row 4: daniel.brooks fans out into three side branches -------------

# LEFT lane: DC WinRM foothold -> Opera -> chuck -> Storage Portal (signing off)
dc,     dc_t     = computer_node(LEFT_X, Y["dc"],
                                 "DC  10.0.0.100\n(WinRM as daniel.brooks)")
opera,  opera_t  = artifact_node(LEFT_X, Y["opera"],
                                 "DumpBrowserSecrets\n-> V10 key + 3 logins")
chuck,  chuck_t  = user_node(LEFT_X, Y["chuck"],
                             "chuck.harrys\n:666chucky", w=250)
portal, portal_t = computer_node(LEFT_X, Y["portal"],
                                 "STORAGE :5000  Flask\n[Disable SMB Signing]")

# RIGHT lane: WriteSPN on DC$ (artifact; its arrow will reach getST much later)
writespn, writespn_t = artifact_node(RIGHT_X, Y["writespn"],
                                     "WriteSPN on DC$\naddspn CIFS/STORAGE.novaforge.local")

# MAIN lane continues DOWN through DNS injection -> coerce -> SAM -> LSA
dns,  dns_t  = artifact_node(MAIN_X, Y["dns"],
                             "DNS record injection\n<host><CredMarshalTargetInfo blob>\n(CVE-2025-33073)")
cmti, cmti_t = artifact_node(MAIN_X, Y["cmti"],
                             "PetitPotam -> STORAGE$\nntlmrelayx -t smb://STORAGE\n(SMB-to-self, signing off)")
sam,  sam_t  = artifact_node(MAIN_X, Y["sam"],
                             "STORAGE\\Administrator\nlocal NTLM d5cad8a978...")
lsa,  lsa_t  = artifact_node(MAIN_X, Y["lsa"],
                             "PtH admin -> mimikatz lsadump::secrets\nDefaultPassword = 1hatefrank")

# --- Row 5: spray + PS-history discovery --------------------------------

frank, frank_t = user_node(MAIN_X,  Y["frank"], "frank.white\n:1hatefrank")
cokx,  cokx_t  = user_node(RIGHT_X, Y["cokx"],
                           "david.cokx\n(PS history:\nnet user david.cokx)", w=290, h=110)

# --- Row 6: convergence on svc_it_admin ---------------------------------

svcit, svcit_t = user_node(MAIN_X, Y["svcit"],
                           "svc_it_admin\n(FCP reset,\nremoved from Protected Users)",
                           w=460, h=140)

# --- Row 7: S4U with sname rewrite --------------------------------------

s4u, s4u_t = artifact_node(MAIN_X, Y["s4u"],
                           "getST -impersonate administrator\n-altservice cifs/DC.novaforge.local\n(TGS encrypted with DC$ key)",
                           w=440, h=110)

# --- Row 8: Domain Admin ------------------------------------------------

admin, admin_t = user_node(MAIN_X, Y["admin"],
                           "Administrator\n-> secretsdump / DCSync", w=340)

elements += [
    attacker, attacker_t, smtp, smtp_t, johndoe, johndoe_t, mlee, mlee_t,
    stevew, stevew_t, itsu, itsu_t, noah, noah_t, stevm, stevm_t, tier1, tier1_t,
    daniel, daniel_t,
    dc, dc_t, opera, opera_t, chuck, chuck_t, portal, portal_t,
    writespn, writespn_t,
    dns, dns_t, cmti, cmti_t, sam, sam_t, lsa, lsa_t,
    frank, frank_t, cokx, cokx_t,
    svcit, svcit_t, s4u, s4u_t, admin, admin_t,
]

# ---------- edges (colour-coded by phase) -----------------------------------

edges = [
    # phase: phish -----------------------------------------------------------
    (attacker, smtp,    "phish", +1, 40,
     "swaks --attach cv.xml\n(Word flat-OPC .xml, UNC image)"),
    (smtp,     johndoe, "phish", -1, 30,
     "Outlook fetches\n\\\\atk\\bad.jpg\n(SMB NTLMv2)"),

    # phase: kerberoast (LDAP + Recycle Bin + targeted roast) ----------------
    (johndoe, mlee, "kerberoast", -1, 40,
     "LDAP w/ john.doe\n-> WRITE on tombstoned m.lee\n-> bad set restore m.lee\n-> targetedKerberoast (etype 18)\n-> 0816mypassword"),

    # phase: ACL chain (single vertical column) ------------------------------
    (mlee,   stevew, "acl", -1, 26,
     "GenericAll\n(dacledit + FCP reset)"),
    (stevew, itsu,   "acl", -1, 26,
     "Owns\n(bad set owner + dacledit + add self)"),
    (itsu,   noah,   "acl", -1, 26, "ForceChangePassword"),
    (noah,   stevm,  "acl", -1, 26, "GenericAll (FCP)"),
    (stevm,  tier1,  "acl", -1, 26, "GenericAll on OU"),
    (tier1,  daniel, "acl", -1, 26,
     "dacledit -inheritance\n-> reset daniel.brooks + ryan.collins"),

    # phase: loot on DC (LEFT lane) ------------------------------------------
    (daniel, dc,     "loot", -1, 30,
     "Remote Management Users\n-> evil-winrm to DC"),
    (dc,     opera,  "loot", -1, 26, "inject DumpBrowserSecrets\ninto opera.exe"),
    (opera,  chuck,  "loot", -1, 26, "V10 decrypt logins JSON"),
    (chuck,  portal, "loot", -1, 26,
     "chisel R:127.0.0.1:5000\n-> log in as Storage Portal Admin"),

    # phase: coerce + relay (MAIN lane) --------------------------------------
    (daniel, dns,   "coerce", +1, 30,
     "NovaForge DNS Operations\nbloodyAD add dnsRecord"),
    (portal, cmti,  "coerce", +1, 34,
     "signing:False\nenables SMB-to-self"),
    (dns,    cmti,  "coerce", -1, 26, "SSPI parses CMTI as loopback"),
    (cmti,   sam,   "coerce", -1, 26,
     "relay STORAGE$ back into\nits own SMB service"),

    # phase: LSA + spray (MAIN lane) -----------------------------------------
    (sam,    lsa,   "lsa", -1, 26,
     "evil-winrm -H <hash> Administrator\n-> mimikatz lsadump::secrets"),
    (lsa,    frank, "lsa", -1, 26,
     "nxc ldap -u users -p 1hatefrank\n-> frank.white:1hatefrank"),
    (lsa,    cokx,  "lsa", +1, 30,
     "type PSReadLine\\Con*\nnet user david.cokx \"pa$$word12\""),

    # phase: Protected Users escape ------------------------------------------
    (frank,  svcit, "delegate", -1, 26,
     "ForceChangePassword svc_it_admin\n-> P@$$word123!"),
    (cokx,   svcit, "delegate", +1, 30,
     "AddMember on Protected Users\n-> remove svc_it_admin"),

    # phase: WriteSPN + sname rewrite (RIGHT lane -> converges on s4u) -------
    (svcit, writespn, "da", +1, 30,
     "svc_it_admin has WriteSPN on DC$"),
    (svcit,  s4u,      "da", -1, 26,
     "S4U2Self + S4U2Proxy\n(CD w/ Protocol Transition)"),
    (writespn, s4u,    "da", +1, 40,
     "TGS encrypted with DC$ key\n(because DC$ now owns the SPN)"),
    (s4u,    admin,    "da", -1, 26,
     "sname rewritten to cifs/DC\n-> secretsdump -just-dc"),
]

for src, dst, phase, side, dist, lbl in edges:
    elements += arrow(src, dst, color=PHASE_COLORS[phase],
                      label=lbl, label_side=side, label_dist=dist)

# ---------- title + subtitle -----------------------------------------------

elements.append(text_elem(60, 40, 1800, 48,
    "HacksmarterLabs - Nova Forge - Attack Chain",
    color=TITLE_COLOR, size=30, align="left"))
elements.append(text_elem(60, 92, 1800, 28,
    "Reads top-to-bottom.  Main chain runs down the centre; side branches sit to the left (DC loot) and right (WriteSPN / david.cokx) close to where they originate.",
    color=TITLE_COLOR, size=14, align="left"))

# ---------- legend (shapes + phase colours) at the bottom -------------------

ly0 = Y["admin"] + 260
legend_shapes = [
    ("ellipse",   USER_STROKE,     USER_FILL,     "solid",  "user / principal"),
    ("rectangle", COMP_STROKE,     COMP_FILL,     "solid",  "computer / service"),
    ("diamond",   GROUP_STROKE,    GROUP_FILL,    "solid",  "AD group / OU"),
    ("rectangle", ARTIFACT_STROKE, ARTIFACT_FILL, "dashed", "artifact (hash / ticket / DNS record)"),
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
    ("phish",      "SMTP + Word flat-OPC UNC leak"),
    ("kerberoast", "AD Recycle Bin + targeted Kerberoast"),
    ("acl",        "ACL chain (owner / FCP / GenericAll / OU DACL)"),
    ("loot",       "WinRM foothold + browser DPAPI secrets"),
    ("coerce",     "DNS write + CMTI (CVE-2025-33073) + PetitPotam relay"),
    ("lsa",        "mimikatz LSA secrets + credential spray"),
    ("delegate",   "Protected Users escape + delegation setup"),
    ("da",         "WriteSPN sname rewrite -> DCSync"),
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

OUT = "nova_forge_attack_chain.excalidraw"
with open(OUT, "w") as f:
    json.dump(scene, f, indent=2)
print(f"[+] wrote {OUT}  ({len(elements)} elements)")
