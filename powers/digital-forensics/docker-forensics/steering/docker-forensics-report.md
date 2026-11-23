---
name: docker-forensics-report
description: Modelo de reporte técnico forense de un contenedor Docker comprometido. Estructura la cronología del incidente, los indicadores de compromiso (IP, archivos, hashes), el mapeo MITRE ATT&CK, la Cadena_Custodia y la remediación, con cada afirmación trazable a una evidencia por su sha256. Cubre la etapa Report. Úsalo para redactar el entregable final a partir de los hallazgos del análisis.
---

# docker-forensics-report — Reporte técnico

Cubre **Report** del Flujo_Investigacion. Convierte los hallazgos de
`docker-evidence-analysis` en un reporte técnico donde **cada afirmación es
trazable** a una evidencia por su `sha256` (manifiesto `SHA256SUMS`) y a su eslabón
de la Cadena_Custodia.

## Reglas del reporte

- **Trazabilidad.** Todo hallazgo cita el archivo de evidencia y su `sha256`; nada se
  afirma sin respaldo.
- **Integridad declarada.** El reporte indica el `hash_pre` y el `hash_post` del
  análisis y confirma que coinciden.
- **Alcance y ética.** Deja constancia de que se trabajó sobre la **copia** del
  contenedor autorizado en `scope.yaml`, sin `docker exec` y sin tocar el host.
- **Objetividad.** Separa hecho (lo que muestra la evidencia) de interpretación
  (hipótesis), con nivel de confianza.
- **Atribución limpia.** Antes de listar IoC, declara y **excluye** las IP conocidas
  del lab (Kali, estaciones de analistas, prof, Blue Team, escáneres autorizados). Una
  IP del equipo **nunca** es un IoC (ver `docker-evidence-analysis` Paso 0.1).

## Plantilla (rellenar y guardar como `reporte-docker-forensics.md`)

```markdown
# Reporte forense — Contenedor Docker comprometido

- Engagement: ${ENGAGEMENT_ID}
- Analista: Aristide Cordonnier (equipo Digital Forensics)
- Contenedor objetivo (copia): <container_id / container_image de scope.yaml>
- Modo_Ejecucion: <script-kiddie | green-hat | pro>
- Fecha del análisis (UTC): <YYYY-MM-DDTHH:MM:SZ>
- Integridad: hash_pre = <...> · hash_post = <...> · ¿coinciden? <sí/no>

## 1. Resumen ejecutivo
<3–6 líneas: qué pasó, cómo entró el atacante, qué logró, impacto y estado actual.>

## 2. Alcance y método
- Objetivo autorizado: contenedor <id> (host_is_target: false). Host EC2 fuera de alcance.
- Flujo: Detect → Isolate → Collect → Preserve → Analyze → Report (RFC 3227).
- Aislamiento aplicado: <docker network disconnect | docker pause> — decidido por el Incident Manager.
- Herramientas: docker, sha256sum, tar, grep. Sin docker exec; análisis en solo lectura.

## 3. Cronología (UTC)
| Hora (UTC) | Evento | Evidencia (archivo · sha256) | ATT&CK |
|---|---|---|---|
| <ts> | <p. ej. escaneo con sqlmap desde 10.50.0.248> | 04_docker_logs.txt · <sha> | T1595 |
| <ts> | <SQLi en /vulnerabilities/sqli/> | access.log (05_..tar) · <sha> | T1190 |
| <ts> | <subida de webshell cmd.php> | /hackable/uploads/cmd.php (05_..tar) · <sha> | T1505.003 |
| <ts> | <persistencia por cron> | etc/crontab (05_..tar) · <sha> | T1053.003 |
| <ts> | <borrado de access.log / historial> | 03_docker_diff.txt (D) · <sha> | T1070.002/003 |

## 4. Indicadores de compromiso (IoC)
- **IP conocidas del lab (EXCLUIDAS de IoC):** <Kali, Mac/estación del analista, prof, Blue Team — con su dueño>. Se separan ANTES de atribuir (Paso 0.1); una IP del equipo no es IoC.
- IP de origen (atacante): <10.50.0.248, …>
- Archivos maliciosos / artefactos: <ruta — sha256>
  - <var/www/html/hackable/uploads/cmd.php — <sha256>>
- Hashes de evidencia (de SHA256SUMS): <lista archivo → sha256>
- Usuarios/cuentas creadas, tareas cron, claves authorized_keys: <...>
- User-Agents y patrones de herramienta: <sqlmap/…>

## 5. Hallazgos detallados
Para cada hallazgo: descripción, evidencia citada (archivo:línea + sha256), técnica
ATT&CK y nivel de confianza (ficha del skill docker-evidence-analysis).

### Hallazgo 1 — <título>
- Qué: <...>
- Evidencia: <archivo:línea · sha256> — cita literal: `<línea del log/diff>`
- ATT&CK: <Txxxx[.sub] — nombre>
- Confianza: <alta/media/baja> — <por qué>

### Hallazgo 2 — <título>
...

## 6. Mapeo MITRE ATT&CK (resumen)
| Táctica | Técnica | Evidencia |
|---|---|---|
| Initial Access | T1190 Exploit Public-Facing Application | <...> |
| Execution | T1059 Command and Scripting Interpreter | <...> |
| Persistence | T1053.003 Cron / T1505.003 Web Shell | <...> |
| Credential Access | T1003.008 /etc/passwd y /etc/shadow | <...> |
| Defense Evasion | T1070.002/.003/.004/.006 Indicator Removal | <...> |

## 7. Cadena de custodia
- Archivo: engagements/${ENGAGEMENT_ID}/evidence/chain_of_custody.jsonl
- Eslabones: <N> · Verificación de encadenado (prev_sha256): <íntegra / rota en línea X>
- Evidencias y sus hashes: ver SHA256SUMS (verificado con `sha256sum -c` antes y después).

## 8. Remediación y recomendaciones
- Contención: <retirar la imagen comprometida, rotar credenciales, cerrar el vector DVWA>
- Erradicación: <eliminar webshell, cron, cuentas; reconstruir desde imagen limpia>
- Recuperación: <desplegar contenedor nuevo verificado; monitoreo reforzado>
- Prevención: <WAF/ModSecurity, parámetros no confiables, mínimos privilegios, read-only rootfs,
  logging centralizado a CloudWatch para evitar borrado local de huellas>

## 9. Anexos
- Lista de evidencias (SHA256SUMS).
- Comandos ejecutados (bitácora) y su salida relevante.
```

## Por modo de ejecución

- **script-kiddie:** entrega el reporte casi lleno a partir de los hallazgos, con la
  cronología y el IoC resumidos.
- **green-hat:** explica por qué cada sección importa y pide completar la cronología y
  justificar el mapeo ATT&CK.
- **pro:** no redacta por el analista; da la estructura y revisa que cada afirmación
  tenga evidencia, hash y técnica, exigiendo rigor y justificación ética/legal.
