---
name: "cloudwatch-dvwa-exploit-detection"
displayName: "Blue Team — Detección de explotación de DVWA con CloudWatch Logs"
description: "Identifica, solo con lectura, que el contenedor DVWA está siendo explotado: consulta el log group /ethack-lab/dvwa (access.log y error.log de Apache) con aws-cli y CloudWatch Logs Insights, detecta scanning, fuerza bruta, SQLi, command injection, XSS, LFI/RFI y webshell, correlaciona por IP origen y emite un hallazgo trazable con veredicto."
keywords: ["blue-team", "defensive", "aws-cli", "cloudwatch", "logs-insights", "dvwa", "detection", "apache", "mitre-attack"]
author: "Blue"
x-ethack:
  kind: "defensive"
  ecCouncilPhase: null
  forensicsStage: null
  track: "BlueTeam"
  team: "blue-team"
  owner: "Blue"
  tools: ["aws-cli", "cloudwatch-logs-insights"]
  allowlistValidation:
    required: true
    source: "engagements/${ENGAGEMENT_ID}/scope.yaml#assets"
    targetParams: ["target", "host", "hostname", "domain", "url"]
  executionMode:
    param: "Modo_Ejecucion"
    allowed: ["script-kiddie", "green-hat", "pro"]
    default: "script-kiddie"
  documentation:
    root: "powers/blue-team/cloudwatch-dvwa-exploit-detection/docs"
    required: ["prompt.md", "sessions/", "feedback.md"]
---
# Blue Team — Detección de explotación de DVWA con CloudWatch Logs

## Al activar este power (obligatorio, en este orden)
1. **Modo de ejecución.** Lee `Modo_Ejecucion` (`script-kiddie` | `green-hat` | `pro`, default
   `script-kiddie`). Si el prompt no lo indica, pregunta; si no se define, usa `script-kiddie`.
2. **Cargar `preflight-y-modos-ejecucion.md`** y ejecutar el preflight: AWS CLI, identidad del
   perfil `blue-team` y validación del asset `dvwa-01` contra `scope.yaml` (incluida la ventana
   autorizada). **Si el preflight falla, no se consulta nada** (ver qué hacer en ese archivo).
3. **Cargar `deteccion-explotacion-dvwa.md`**, ejecutar las detecciones D0–D8 y recoger hits.
4. **Cargar `correlacion-y-veredicto.md`** para correlacionar por IP origen y fijar el veredicto
   (sospecha / probable / confirmado).
5. **Cargar `plantilla-hallazgo.md`** y emitir el hallazgo con su evidencia (Req 4.4).

## Overview
El registro del contenedor DVWA (`vulnerables/web-dvwa`) viaja a CloudWatch Logs, en el log group
`/ethack-lab/dvwa` (región `us-east-1`), con el `access.log` y el `error.log` de Apache. Este Power
lee ese log group con el perfil AWS de **solo lectura** `blue-team` para responder una pregunta:
**¿el asset `dvwa-01` está siendo explotado, y desde dónde?**

Es **detección pasiva**. Nunca modifica infraestructura, nunca ataca y nunca ejecuta una
contención: las acciones de contención solo se **proponen** en el hallazgo. El objetivo es el
contenedor DVWA, no el host EC2.

Seguimiento en vivo (base): `aws logs tail /ethack-lab/dvwa --profile blue-team --region us-east-1 --follow`

## Available Steering Files
- **preflight-y-modos-ejecucion.md** — prerrequisitos (AWS CLI, perfil), validación de asset y
  ventana contra `scope.yaml`, qué hacer si falla, y comportamiento de cada `Modo_Ejecucion`.
- **deteccion-explotacion-dvwa.md** — runbook con las consultas Logs Insights y filter patterns
  D0–D8 (scanning, fuerza bruta, SQLi, command injection, XSS, LFI/RFI, upload/webshell,
  error.log), con límites de visibilidad del access.log.
- **correlacion-y-veredicto.md** — consulta de correlación por IP, cadena scan → bruteforce →
  injection → webshell, criterios de veredicto, mapeo MITRE ATT&CK / fases EC-Council del Red Team,
  contención propuesta y escalada.
- **plantilla-hallazgo.md** — plantilla de hallazgo de detección + evidencia (ejemplo ilustrativo,
  sin datos reales).

## Modos de ejecución
- **script-kiddie** (default): comandos listos y hallazgo con explicación mínima.
- **green-hat**: explica por qué cada consulta detecta lo que detecta y pide razonar el resultado.
- **pro**: no entrega la consulta hecha; guía a diseñar la detección y pide justificación.

## Entregable
Un **hallazgo de detección** (`kind: hallazgo-deteccion`) por IP origen, con veredicto, cadena
de ataque, ATT&CK, y evidencia trazable a cada evento (log stream, `@timestamp`, IP origen,
request, status, ID del evento), más contención propuesta y escalada. Se guarda en
`docs/sessions/`.

> Prerrequisito externo: este Power **no instala** AWS CLI. Ver `preflight-y-modos-ejecucion.md`.
