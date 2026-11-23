#!/usr/bin/env python3
"""Genera los custom agents de Kiro (.kiro/agents/*.json) desde los SOP del framework.

Cada SOP markdown (agents/orquestador|fases|roles/*.md) se registra como un custom
agent de Kiro: su archivo se carga como `resources` (contexto obligatorio) y el
`prompt` indica al agente operar segun ese SOP.

DETECCION AUTOMATICA DE LAYOUT
------------------------------
Funciona tanto si el framework esta en la RAIZ del workspace (agents/ en la raiz)
como si esta bajo un subdirectorio (p. ej. agent_ethack_dfir/). Localiza la raiz
del workspace como el ancestro mas cercano que contiene `.kiro/`, y calcula el
prefijo relativo (PREFIX) que anteponen los `file://` de los resources.
"""
import json, os, re, glob

# Raiz del framework = dos niveles arriba de este script (scripts/ -> framework/)
FRAMEWORK = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def find_workspace_root(start: str) -> str:
    """Ancestro mas cercano (incluyendo start) que contiene `.kiro/`."""
    d = start
    for _ in range(6):
        if os.path.isdir(os.path.join(d, ".kiro")):
            return d
        parent = os.path.dirname(d)
        if parent == d:
            break
        d = parent
    return None


WS = find_workspace_root(FRAMEWORK) or os.path.dirname(FRAMEWORK)
REL = os.path.relpath(FRAMEWORK, WS)          # "." si el framework ES la raiz
PREFIX = "" if REL in (".", "") else REL.replace(os.sep, "/") + "/"
OUT = os.path.join(WS, ".kiro", "agents")
os.makedirs(OUT, exist_ok=True)

print(f">> framework : {FRAMEWORK}")
print(f">> workspace : {WS}")
print(f">> layout    : {'raiz' if PREFIX=='' else 'subdir ('+PREFIX.rstrip('/')+')'}  -> PREFIX='{PREFIX}'")
print(f">> salida     : {OUT}")

# (nombre_kiro, sop_rel, powers_esperados)
AGENTS = [
    ("ethack-orquestador",         "agents/orquestador/orquestador.md",   []),
    ("ethack-reconnaissance",      "agents/fases/reconnaissance.md",      ["footprinting-enumeration", "osint-passive-recon"]),
    ("ethack-scanning",            "agents/fases/scanning.md",            ["footprinting-enumeration", "vulnerability-assessment"]),
    ("ethack-gaining-access",      "agents/fases/gaining-access.md",      ["vulnerability-assessment", "exploitation-metasploit"]),
    ("ethack-maintaining-access",  "agents/fases/maintaining-access.md",  ["exploitation-metasploit"]),
    ("ethack-covering-tracks",     "agents/fases/covering-tracks.md",     []),
    ("ethack-red-team",            "agents/roles/red-team.md",            []),
    ("ethack-blue-team",           "agents/roles/blue-team.md",           []),
    ("ethack-digital-forensics",   "agents/roles/digital-forensics.md",   ["dfir-linux", "network-forensics", "docker-forensics"]),
    ("ethack-incident-responder",  "agents/roles/incident-responder.md",  ["incident-handling-nist", "incident-response-lab"]),
    ("ethack-grc",                 "agents/roles/grc.md",                 ["grc-nist-csf"]),
]


def front_matter_name(path: str):
    m = re.search(r"^name:\s*(.+)$", open(path, encoding="utf-8").read(), re.M)
    return m.group(1).strip() if m else None


ENG = f"file://{PREFIX}engagements/dvwa-lab-ulsa"
created = []
for kname, sop_rel, powers in AGENTS:
    sop_abs = os.path.join(FRAMEWORK, sop_rel)
    if not os.path.exists(sop_abs):
        print("  (falta SOP, omito):", sop_rel)
        continue
    sop_name = front_matter_name(sop_abs) or kname
    resources = [
        f"file://{PREFIX}{sop_rel}",
        f"{ENG}/scope.yaml",
        f"{ENG}/state.json",
        f"file://{PREFIX}README-kiro-setup.md",
    ]
    if kname == "ethack-orquestador":
        resources.insert(1, f"file://{PREFIX}agents/orquestador/phase_sequence.py")
    powers_txt = (" Powers esperados (instalar/activar aparte): " + ", ".join(powers) + ".") if powers else " Sin Power base (hueco a cubrir por el alumno)."
    agent = {
        "name": kname,
        "description": f"[ULSA EH+DFIR] SOP '{sop_name}'. Opera segun el archivo de SOP cargado en resources." + powers_txt,
        "prompt": (
            f"Eres el agente '{sop_name}' del sistema Ethical Hacking + DFIR de ULSA. "
            f"Tu SOP operativo esta en el resource file://{PREFIX}{sop_rel}: siguelo al pie de la letra. "
            f"Respeta la Allowlist_Objetivos (scope.yaml) y los Principios_Eticos como restricciones duras: "
            f"solo objetivos autorizados, contenedor y no host, nunca produccion, explotacion limitada a PoC. "
            f"El estado del engagement vive en {PREFIX}engagements/dvwa-lab-ulsa/state.json."
        ),
        "tools": ["@builtin"],
        "allowedTools": ["fs_read"],
        "resources": resources,
        "mcpServers": {},
        "useLegacyMcpJson": False,
        "welcomeMessage": f"Usando {kname} (ULSA EH+DFIR). SOP: {sop_rel}.{powers_txt}",
    }
    dest = os.path.join(OUT, kname + ".json")
    json.dump(agent, open(dest, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    open(dest, "a").write("\n")
    created.append(kname)
    print("  generado:", os.path.relpath(dest, WS))

print(f"\nTotal: {len(created)} custom agents en {os.path.relpath(OUT, WS)}/")
