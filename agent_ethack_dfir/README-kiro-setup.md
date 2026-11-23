# Configurar los agentes Ethical Hacking + DFIR en Kiro

Este framework define **11 agentes** como SOP en markdown (`agents/orquestador`,
`agents/fases`, `agents/roles`). Para **usarlos en Kiro** hay que registrarlos como
**custom agents** (archivos JSON que Kiro lee de `.kiro/agents/`). Esta guía explica cómo.

> **IMPORTANTE — abre la RAÍZ del repo como workspace de Kiro.** Los `resources` de los
> agentes usan rutas **relativas al workspace** (`file://agent_ethack_dfir/...`). Para que
> resuelvan, tras `git clone` abre **la carpeta raíz del repo clonado** como workspace en Kiro
> (no una subcarpeta). El generador `gen_kiro_agents.py` detecta automáticamente el layout
> (framework en la raíz o bajo `agent_ethack_dfir/`) y escribe los `.kiro/agents/*.json` con el
> prefijo de ruta correcto; si mueves el framework, **vuelve a ejecutarlo**.

## 1. Qué se registra

| Agente Kiro | SOP | Tipo | Powers esperados |
|---|---|---|---|
| `ethack-orquestador` | agents/orquestador/orquestador.md | orquestador | (coordina; usa los de las fases) |
| `ethack-reconnaissance` | agents/fases/reconnaissance.md | fase | footprinting-enumeration, osint-passive-recon |
| `ethack-scanning` | agents/fases/scanning.md | fase | footprinting-enumeration, vulnerability-assessment |
| `ethack-gaining-access` | agents/fases/gaining-access.md | fase | vulnerability-assessment, exploitation-metasploit |
| `ethack-maintaining-access` | agents/fases/maintaining-access.md | fase | exploitation-metasploit |
| `ethack-covering-tracks` | agents/fases/covering-tracks.md | fase | **gap** (lo cubre el alumno) |
| `ethack-red-team` | agents/roles/red-team.md | rol | — |
| `ethack-blue-team` | agents/roles/blue-team.md | rol | **gap** (lo cubre el alumno) |
| `ethack-digital-forensics` | agents/roles/digital-forensics.md | rol | dfir-linux, network-forensics |
| `ethack-incident-responder` | agents/roles/incident-responder.md | rol | incident-handling-nist, incident-response-lab |
| `ethack-grc` | agents/roles/grc.md | rol | grc-nist-csf |

## 2. Instalación (dos vías)

### Vía A — usar los JSON ya generados (recomendado)
Los configs ya están creados en **`<workspace>/.kiro/agents/ethack-*.json`** por el generador:

```bash
python3 agent_ethack_dfir/scripts/gen_kiro_agents.py
```

- **Ámbito proyecto** (lo anterior): viven en `<workspace>/.kiro/agents/` y solo aplican a este
  workspace. Es lo deseable para el curso (van versionados con el repo del engagement).
- **Ámbito usuario** (opcional, para todos tus proyectos): copia los JSON a `~/.kiro/agents/`.
  ```bash
  cp .kiro/agents/ethack-*.json ~/.kiro/agents/
  ```

Reinicia/recarga Kiro para que detecte los nuevos agentes.

### Vía B — manual desde Kiro
- **Kiro IDE:** panel de agentes → *Create Agent* → rellena `name`, `description`, `prompt`,
  y en *resources* apunta al SOP (`file://agent_ethack_dfir/agents/.../<sop>.md`).
- **Kiro CLI:** `kiro-cli agent create` (o edita directamente un JSON en `.kiro/agents/`).

## 3. Esquema del custom agent (campos usados)

```jsonc
{
  "name": "ethack-scanning",              // identificador único del agente
  "description": "…",                     // aparece en el selector de agentes
  "prompt": "Eres el agente … sigue tu SOP…",  // system prompt (apunta al SOP)
  "tools": ["@builtin"],                  // toolset disponible (bash, fs, buscar, web…)
  "allowedTools": ["fs_read"],            // auto-aprobados; el resto pide confirmación
  "resources": [                          // contexto que el agente carga SIEMPRE
    "file://agent_ethack_dfir/agents/fases/scanning.md",   // el SOP operativo
    "file://agent_ethack_dfir/engagements/dvwa-lab-ulsa/scope.yaml",
    "file://agent_ethack_dfir/engagements/dvwa-lab-ulsa/state.json"
  ],
  "mcpServers": {}                        // MCP extra si algún Power lo requiere
}
```

> **Clave:** el SOP markdown se carga como **resource** y el `prompt` ordena seguirlo. Así el
> comportamiento del agente = su SOP, sin reescribirlo.

## 4. Seleccionar / cambiar de agente

- **Kiro IDE:** selector de agente (arriba del chat) → elige `ethack-orquestador`, etc.
- **Kiro CLI:** `/agent` para listar/cambiar en la sesión, o fija el default:
  ```bash
  kiro-cli settings chat.defaultAgent ethack-orquestador
  ```

## 5. Prerrequisito: Powers

Cada agente de fase/rol **espera ciertos Kiro Powers instalados y activados** (columna de la
tabla §1). Sin el Power, el agente puede seguir su SOP pero no tendrá la Herramienta_Real
(nmap, Nessus, Metasploit, Volatility…). Instálalos/actívalos antes de ejecutar la fase.
Los **gaps** (`covering-tracks`, `blue-team`) **no tienen Power base**: son el trabajo del
alumno (crear ≥2 Powers con herramienta real).

## 6. Modelo de operación (importante)

Los custom agents de Kiro **no se invocan entre sí automáticamente**. El `ethack-orquestador`
**describe** la delegación y mantiene el orden/estado (`phase_sequence.py`, `state.json`), pero
en la práctica **tú cambias de agente** para ejecutar cada fase/rol, o el orquestador usa
workflows. Flujo típico de clase:

1. Selecciona **`ethack-orquestador`** → te dice la fase que toca (lee `state.json`) y la guardia.
2. Cambia al subagente de esa fase (p. ej. **`ethack-scanning`**) → ejecuta y entrega el resultado.
3. Vuelve al **orquestador** para consolidar (`consolidate_phase`) y avanzar `state.json`.
4. Para el pivote defensivo, usa **`ethack-digital-forensics`** e **`ethack-incident-responder`**.

## 7. Seguridad (por defecto)

- `allowedTools` se dejó mínimo (`fs_read`). **`execute_bash` y `fs_write` piden aprobación
  explícita** en cada uso: apropiado para una herramienta ofensiva.
- Los agentes cargan `scope.yaml` como resource y su SOP exige validar el objetivo con
  `scripts/validate_target.py` antes de cualquier Herramienta_Real (Allowlist, contenedor-no-host,
  nunca producción).

## 8. Regenerar los configs

Si editas los SOP o cambia el engagement:
```bash
python3 agent_ethack_dfir/scripts/gen_kiro_agents.py   # reescribe .kiro/agents/ethack-*.json
```
