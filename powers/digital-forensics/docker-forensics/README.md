# docker-forensics — Forense de contenedores Docker comprometidos

Power del equipo **Digital Forensics** (ULSA). Guía a Kiro durante **toda** la
investigación forense de un **contenedor Docker comprometido** del
Entorno_Laboratorio —por ejemplo el **DVWA** que atacó el Red Team— siguiendo el
Flujo_Investigacion **Detect → Isolate → Collect → Preserve → Analyze → Report**,
en **Orden_Volatilidad** (RFC 3227) y con **Cadena_Custodia** encadenada por hash.

> **Encuadre.** Material didáctico para un **laboratorio autorizado**. El Power no
> concede autorización por sí mismo: el contenedor objetivo debe estar en
> `engagements/${ENGAGEMENT_ID}/scope.yaml#assets`. No hay servidor MCP; solo
> **guías y comandos** sobre herramientas reales (`docker`, `sha256sum`, `tar`,
> `grep`).

> **Formato del Power (instalable en Kiro).** Igual que el cimiento `dfir-linux`:
> un `POWER.md` en la raíz (con el frontmatter y el bloque `x-ethack`) y las guías
> de conocimiento en `steering/` (una por archivo, cargadas bajo demanda). Así se
> instala con **Add Custom Power → Local Directory**. La variante original con
> `plugin.json` + `skills/` **no** la reconocía ese instalador; `make validate` lee
> el mismo contrato `x-ethack` del frontmatter y sigue en verde.

## Ubicación en el ciclo

- `kind: forensics` · `forensicsStage: Collect` · `ecCouncilPhase: null`
- Equipo `digital-forensics` · responsable **Aristide Cordonnier**
- Deriva del cimiento `dfir-linux` (forense de host): cuando el contenedor se
  exporta y se monta, el análisis del sistema de archivos reutiliza la misma
  disciplina de host, pero **sobre la copia**, nunca sobre el contenedor vivo.

## Las dos reglas que nunca se rompen

1. **Nada de `docker exec` ni de escribir dentro del contenedor víctima.** Entrar o
   escribir altera la evidencia (mtimes, logs, memoria) y contamina la escena.
   Todo se observa desde fuera con comandos de solo lectura del demonio Docker.
2. **Siempre sobre la copia que entrega el profesor**, jamás sobre el contenedor de
   producción ni sobre el host EC2 anfitrión (`host_is_target: false` en
   `scope.yaml`). El análisis se hace sobre el `.tar` exportado, montado en **solo
   lectura**.

## Flujo_Investigacion (Detect → … → Report)

| Etapa | Qué pasa | Dónde |
|---|---|---|
| **Detect** | Señal de compromiso (alerta Blue Team, log DVWA, hallazgo Red Team). | Fuera del Power |
| **Isolate** | Cortar daño sin perder estado: `docker pause` **por defecto**; `docker network disconnect` solo si lo pide el Incident Manager. | `docker-evidence-collection` |
| **Collect** | Orden_Volatilidad: `docker top` → `docker inspect` → `docker diff` → `docker logs --timestamps` → `docker export`. | `docker-evidence-collection` |
| **Preserve** | `sha256sum` por evidencia + `sha256sum -c` antes y después; Cadena_Custodia `.jsonl` encadenada. | `docker-evidence-collection` |
| **Analyze** | `.tar` extraído en solo lectura: `docker diff` (A/C/D) → logs Apache → artefactos de usuario → anti-forense. Cada hallazgo con evidencia y técnica MITRE ATT&CK. | `docker-evidence-analysis` |
| **Report** | Cronología, IoC, mapeo ATT&CK, Cadena_Custodia y remediación. | `docker-forensics-report` |

## Guías de conocimiento (`steering/`)

Las guías se leen **bajo demanda** (divulgación progresiva); carga solo la del paso
en que estés. Son las tres antiguas skills, ahora como archivos de `steering/`.

| Guía | Cubre | Contenido |
|---|---|---|
| [`docker-evidence-collection`](steering/docker-evidence-collection.md) | Isolate · **Collect** · Preserve | Aislamiento sin pérdida de estado, recolección en Orden_Volatilidad, hashing y Cadena_Custodia encadenada. |
| [`docker-evidence-analysis`](steering/docker-evidence-analysis.md) | Analyze | Análisis del `.tar` en solo lectura: `docker diff`, logs Apache, artefactos de usuario y detección de borrado de huellas, con evidencia + MITRE ATT&CK por hallazgo. |
| [`docker-forensics-report`](steering/docker-forensics-report.md) | Report | Modelo de reporte técnico: cronología, IoC, mapeo ATT&CK, Cadena_Custodia y remediación. |

## Modos de ejecución (`Modo_Ejecucion`)

Tres perfiles que cambian cuánto hace Kiro por ti y cuánto te hace razonar; **no**
cambian las herramientas, la metodología ni la frontera de autorización.

| Modo | Perfil | Qué hace Kiro |
|---|---|---|
| `script-kiddie` *(default)* | Entrada | Da el comando listo y el hallazgo, con explicación mínima. |
| `green-hat` | Aprendiz | Explica cada comando y el porqué del orden antes de ejecutarlo, y te pide interpretar la salida. |
| `pro` | Profesional | No da el comando hecho: te guía a construirlo, discute límites forenses y exige justificación ética/legal escrita. |

Si el humano no indica el perfil, Kiro **pregunta** antes de recolectar o analizar;
si no se define, usa `script-kiddie`. Subir la exigencia lo pide cualquiera; bajarla
solo el instructor. El perfil usado se anota en la Cadena_Custodia y en el reporte.

## Entregables

- `agent_ethack_dfir/engagements/${ENGAGEMENT_ID}/evidence/` — evidencias (`docker top`,
  `inspect`, `diff`, `logs`, `export.tar`), su `SHA256SUMS` y la Cadena_Custodia
  `chain_of_custody.jsonl`. **Rutas derivadas de `ENGAGEMENT_ID`** (camino completo,
  donde vive el `scope.yaml` real), nada en duro; el contenedor objetivo se lee del
  `scope.yaml` del engagement.
- Reporte técnico (guía `docker-forensics-report`) trazable a cada evidencia por su
  `sha256`.

> **Evidencia pesada fuera del repo.** El `.tar` del export y el `rootfs` extraído no
> se versionan (`.gitignore`: `engagements/*/evidence/*` y `engagements/*/analysis/`);
> lo único que queda en `evidence/` es `chain_of_custody.jsonl`. Para probar sobre un
> contenedor propio, usa un **engagement de prueba local** (`engagements/*-selftest/`,
> ignorado por git) como explica `steering/docker-evidence-collection.md`.

## Configuración

**No requiere configuración.** No tiene `mcp.json` ni claves de API: es un Power de
guías y comandos sobre herramientas ya instaladas en la Kali del laboratorio.
