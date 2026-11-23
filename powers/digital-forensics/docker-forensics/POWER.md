---
name: "docker-forensics"
displayName: "Docker Forensics"
description: "Power de Digital Forensics que guía a Kiro durante el análisis forense de un contenedor Docker comprometido del Entorno_Laboratorio (p. ej. el DVWA atacado por el Red Team). Recorre el Flujo_Investigacion Detect → Isolate → Collect → Preserve → Analyze → Report en Orden_Volatilidad (RFC 3227), con Cadena_Custodia encadenada por sha256. Envuelve herramientas reales (docker, sha256sum, tar, grep); no incluye servidor MCP: solo guías y comandos. Trabaja SIEMPRE sobre la copia verificada del contenedor, nunca sobre producción ni sobre el host EC2 anfitrión."
keywords: ["digital-forensics", "dfir", "docker", "container-forensics", "chain-of-custody", "rfc3227", "mitre-attack", "dvwa"]
author: "Aristide Cordonnier"
x-ethack:
  kind: "forensics"
  ecCouncilPhase: null
  forensicsStage: "Collect"
  team: "digital-forensics"
  owner: "Aristide Cordonnier"
  tools:
    - name: "docker"
      binary: "docker"
      category: "forensics"
    - name: "sha256sum"
      binary: "sha256sum"
      category: "forensics"
    - name: "tar"
      binary: "tar"
      category: "forensics"
    - name: "grep"
      binary: "grep"
      category: "forensics"
  allowlistValidation:
    required: true
    source: "engagements/${ENGAGEMENT_ID}/scope.yaml#assets"
    targetParams: ["target", "host", "hostname", "container", "container_id", "container_image"]
  producesActionLog: true
  executionMode:
    param: "Modo_Ejecucion"
    allowed: ["script-kiddie", "green-hat", "pro"]
    default: "script-kiddie"
  documentation:
    root: "powers/digital-forensics/docker-forensics/docs"
    required: ["prompt.md", "sessions/", "feedback.md"]
---

# Docker Forensics

## Al activar este power (obligatorio, en este orden)

1. **Modo de ejecución (perfil).** Lee el parámetro `Modo_Ejecucion` del frontmatter
   (`x-ethack.executionMode`, valores `script-kiddie` | `green-hat` | `pro`, default
   `script-kiddie`). Si el prompt no lo indica, el agente **pregunta** cuál perfil usar antes de
   recolectar o analizar; si aun así no se define, usa el default `script-kiddie`:
   > ¿Con qué perfil trabajamos?
   > - **script-kiddie:** te doy el comando listo y el hallazgo, con explicación mínima.
   > - **green-hat:** antes de cada comando te explico qué hace y te pido interpretar la salida.
   > - **pro:** no te doy el comando hecho; te guío a construir tu procedimiento y te pido la
   >   justificación ética y legal.
2. **Validar la Allowlist_Objetivos.** El objetivo autorizado es el **contenedor** declarado en
   `engagements/${ENGAGEMENT_ID}/scope.yaml#assets` con `host_is_target: false`; el host EC2
   anfitrión **no** es objetivo. La guardia comprueba el asset, `host_is_target` y la
   `authorized_window` (aborta fuera de alcance o fuera de ventana). No se trabaja "a ojo".
3. **Cargar la guía de la etapa en que estés** (acción `readSteering`, bajo demanda): recolección
   (`docker-evidence-collection.md`), análisis (`docker-evidence-analysis.md`) o reporte
   (`docker-forensics-report.md`). Se sigue el Flujo_Investigacion en orden.

## Overview

Este power de conocimiento convierte la investigación forense de un **contenedor Docker
comprometido** del Entorno_Laboratorio (p. ej. el **DVWA** que atacó el Red Team) en un flujo que
el agente puede seguir en un laboratorio autorizado:

- **Isolate** sin perder estado volátil: `docker pause` por defecto; `docker network disconnect`
  solo si lo pide el Incident Manager; o recolección **en caliente** (sin aislar) en lab
  compartido/producción, con nota de custodia obligatoria.
- **Collect** en **Orden_Volatilidad** (RFC 3227): `docker top` → `docker inspect` → `docker diff`
  → `docker logs --timestamps` → `docker export`.
- **Preserve**: `sha256sum` por evidencia (manifiesto `SHA256SUMS`, verificado antes y después) y
  **Cadena_Custodia** encadenada por `sha256` en `chain_of_custody.jsonl`.
- **Analyze** del `.tar` exportado en **solo lectura**: `docker diff` (A/C/D), logs de Apache
  (XSS, SQLi, inyección de comandos, webshell, escáneres), artefactos de usuario y detección de
  borrado de huellas, cruzando `docker logs` con el `access.log` del `.tar`. Cada hallazgo con su
  evidencia y su técnica **MITRE ATT&CK**.
- **Report**: cronología, IoC, mapeo ATT&CK, Cadena_Custodia y remediación, todo trazable por
  `sha256`.
- **Recolección remota** (Docker en un host EC2 por salto SSH) sin que la clave privada ni la
  evidencia salgan del puesto del analista.

> **Encuadre:** material didáctico para laboratorios autorizados o equipos propios. El power no
> concede autorización por sí mismo: el contenedor objetivo debe estar en `scope.yaml`. Deriva del
> cimiento `dfir-linux` (forense de host): el análisis del sistema de archivos reutiliza esa
> disciplina, pero **sobre la copia**, nunca sobre el contenedor vivo. Creado para el curso de
> Ingeniería Cibernética (ULSA) con asistencia de Kiro.

## Las dos reglas que nunca se rompen

1. **Nada de `docker exec` ni de escribir dentro del contenedor víctima.** Entrar o escribir altera
   la evidencia (mtimes, logs, memoria) y contamina la escena. Todo se observa desde fuera con
   comandos de solo lectura del demonio Docker.
2. **Siempre sobre la copia verificada**, nunca sobre el contenedor de producción ni sobre el host
   EC2 anfitrión (`host_is_target: false`). El análisis se hace sobre el `.tar` exportado, montado
   en **solo lectura**.

## Cómo está organizado el conocimiento (steering/)

Las guías se cargan **bajo demanda** (acción `readSteering`): lee solo la que necesites según la
etapa del Flujo_Investigacion en que estés.

| Guía | Etapas que cubre | Contenido |
|---|---|---|
| `docker-evidence-collection.md` | Isolate · **Collect** · Preserve | Pre-flight del entorno, aislamiento sin pérdida de estado (`pause`/`disconnect`/en caliente), recolección en Orden_Volatilidad, hashing y Cadena_Custodia encadenada (con y sin `jq`). Incluye recolección remota por salto SSH y engagement de prueba local. |
| `docker-evidence-analysis.md` | Analyze | Análisis del `.tar` en solo lectura: `docker diff` (A/C/D) filtrando el ruido del runtime, logs de Apache, artefactos de usuario y detección de borrado de huellas (cruce `docker logs` ↔ `access.log`), con evidencia y técnica MITRE ATT&CK por hallazgo. Incluye la exclusión de IP conocidas del lab antes de atribuir. |
| `docker-forensics-report.md` | Report | Modelo de reporte técnico: cronología, IoC, mapeo ATT&CK, Cadena_Custodia y remediación, con cada afirmación trazable por `sha256`. |

## Flujo_Investigacion (Detect → … → Report)

| Etapa | Qué pasa | Guía |
|---|---|---|
| **Detect** | Señal de compromiso (alerta Blue Team, log DVWA, hallazgo Red Team). | Fuera del power |
| **Isolate** | Cortar el daño sin perder estado volátil. | `docker-evidence-collection.md` |
| **Collect** | Recolección en Orden_Volatilidad (RFC 3227). | `docker-evidence-collection.md` |
| **Preserve** | Hash por evidencia + Cadena_Custodia encadenada. | `docker-evidence-collection.md` |
| **Analyze** | `.tar` en solo lectura; cada hallazgo con evidencia + ATT&CK. | `docker-evidence-analysis.md` |
| **Report** | Cronología, IoC, mapeo ATT&CK, custodia y remediación. | `docker-forensics-report.md` |

## Modos de ejecución (perfil del hacker)

Además del flujo técnico, este power se ejecuta en uno de **tres perfiles** que definen cuánto hace
el agente por ti y cuánto te hace pensar. El perfil se fija con el parámetro **`Modo_Ejecucion`** del
frontmatter (`x-ethack.executionMode`: `allowed: ["script-kiddie", "green-hat", "pro"]`,
`default: "script-kiddie"`). No cambian la metodología, las herramientas ni la frontera de
autorización; cambia la profundidad de la explicación y quién razona.

| `Modo_Ejecucion` | Perfil | Qué hace el agente en docker-forensics |
|---|---|---|
| `script-kiddie` *(default)* | Nivel de entrada | Da el comando listo (`docker top/inspect/diff/logs/export`, los `grep`/`find` del análisis) y entrega el hallazgo interpretado, con explicación mínima. |
| `green-hat` | Aprendiz | Antes de ejecutar, explica el Orden_Volatilidad y por qué `export` va al final, qué delata cada patrón de log y por qué el análisis es en solo lectura; te pide predecir e interpretar la salida. |
| `pro` | Profesional/experto | No da el bloque hecho: te guía a construir la secuencia, el `coc_append` y tus expresiones de análisis, discute aislar con `pause` vs `disconnect` vs en caliente, y exige una justificación ética y legal escrita (alcance, copia, no-`exec`). |

**Elección y cambio de modo:** si el humano no indica el perfil, el agente lo pregunta antes del
primer comando (default `script-kiddie`). Subir la exigencia (script-kiddie → green-hat → pro) lo
pide cualquiera; bajarla (→ script-kiddie) solo el **instructor**. El perfil usado se anota en la
Cadena_Custodia y en el reporte.

## Configuration

**No requiere configuración.** Es un power de conocimiento: no tiene `mcp.json` ni API keys. Solo
guías y comandos sobre herramientas ya instaladas (`docker`, `sha256sum`, `tar`, `grep`).
