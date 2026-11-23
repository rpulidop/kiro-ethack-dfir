# Prompt de generación del Power `docker-forensics` (Req 15.2)

> Artefacto_Documentacion obligatorio. Documenta el objetivo del Power y los
> prompts con los que se generó e invoca. Parte del contrato del modelo estándar
> (`x-ethack.documentation.required` incluye `prompt.md`).

## Objetivo del Power

Guiar a Kiro durante **toda** la investigación forense de un **contenedor Docker
comprometido** del Entorno_Laboratorio (p. ej. el DVWA atacado por el Red Team),
siguiendo el Flujo_Investigacion **Detect → Isolate → Collect → Preserve → Analyze
→ Report** en **Orden_Volatilidad** (RFC 3227), con **Cadena_Custodia** encadenada
por `sha256`.

- Herramientas reales envueltas: `docker`, `sha256sum`, `tar`, `grep`.
- Ubicación en el ciclo: `kind: forensics`, `forensicsStage: Collect`
  (`ecCouncilPhase: null`).
- Sin servidor MCP: solo guías y comandos.

## Prompt(s) usados

Prompt de construcción dado a Kiro:

```
Crea el Power docker-forensics en powers/digital-forensics/docker-forensics/.
Debe guiar la analyse forense de un contenedor Docker comprometido (DVWA)
siguiendo Detect → Isolate → Collect → Preserve → Analyze → Report, en orden de
volatilidad (RFC 3227), con cadena de custodia. Sin MCP: solo guías y comandos.
Tres skills: docker-evidence-collection (docker top → inspect → diff →
logs --timestamps → export, con sha256sum y chain_of_custody.jsonl encadenada;
aislar con docker network disconnect o docker pause, decide el Incident Manager),
docker-evidence-analysis (análisis del .tar en solo lectura: docker diff A/C/D,
logs Apache para XSS/SQLi/inyección de comandos/webshell/escáneres, artefactos de
usuario y detección de borrado de huellas, con MITRE ATT&CK) y
docker-forensics-report (reporte técnico). plugin.json con x-ethack como el
_template: forensics / Collect, allowlist obligatoria, tres modos de ejecución,
documentación. Contenido en español.
```

Prompts de invocación por skill:

```
# Recolección
Activa docker-forensics (skill docker-evidence-collection) con
Modo_Ejecucion=script-kiddie sobre el contenedor <container_id de scope.yaml>.
Aísla según decida el Incident Manager y recoléctame la evidencia en orden de
volatilidad con su cadena de custodia.

# Análisis
Activa docker-forensics (skill docker-evidence-analysis) con
Modo_Ejecucion=green-hat sobre 05_docker_export.tar. Analiza en solo lectura y
dame los hallazgos con evidencia y técnica MITRE ATT&CK.

# Reporte
Activa docker-forensics (skill docker-forensics-report). Redacta el reporte
técnico con cronología, IoC, mapeo ATT&CK, cadena de custodia y remediación.
```

## Decisiones de diseño

- **Orden_Volatilidad (RFC 3227):** `docker top` → `inspect` → `diff` →
  `logs --timestamps` → `export`, de lo más volátil (procesos vivos) a lo más
  estable (snapshot `.tar`), que se hace al final para analizar offline.
- **Aislamiento sin pérdida de estado:** `docker network disconnect` (mantiene
  procesos/memoria) o `docker pause` (congela con el *freezer* de cgroups); **lo
  decide el Incident Manager**. Nunca `docker stop/kill` para aislar.
- **Cadena_Custodia encadenada:** una línea JSON por acción con hora UTC, analista,
  acción, archivo, su `sha256` y el `sha256` de la línea anterior (`prev_sha256`),
  de modo que alterar o borrar una línea rompa el enlace.
- **Integridad:** `sha256sum` por evidencia en `SHA256SUMS`, revalidado con
  `sha256sum -c` antes y después del análisis (`hash_pre == hash_post`).
- **Dos reglas inviolables:** (1) nada de `docker exec` ni de escribir en el
  contenedor víctima; (2) siempre sobre la copia del profesor, nunca producción ni
  host (el host es `host_is_target: false` en `scope.yaml`).
- **Modos de ejecución:** `script-kiddie` (default) / `green-hat` / `pro`, con los
  mismos comandos y frontera de autorización; cambia la profundidad de la
  explicación.
- **Skills, no steering:** el conocimiento se empaquetó en tres `skills/<skill>/SKILL.md`
  con las guías y los comandos; sin código ejecutable ni MCP.
