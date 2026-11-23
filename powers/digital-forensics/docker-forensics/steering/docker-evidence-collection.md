---
name: docker-evidence-collection
description: Recolección forense de un contenedor Docker comprometido en Orden_Volatilidad (RFC 3227). Pre-flight del entorno (daemon Docker, jq opcional). Aísla sin perder estado con docker pause por defecto (docker network disconnect solo si lo pide el Incident Manager), ejecuta docker top → inspect → diff → logs --timestamps → export, calcula sha256sum de cada evidencia y mantiene una Cadena_Custodia encadenada en JSONL (con y sin jq). Cubre las etapas Isolate, Collect y Preserve. Úsalo cuando haya que congelar y recolectar la evidencia de un contenedor del laboratorio autorizado.
---

# docker-evidence-collection — Aislar, recolectar y preservar

Cubre **Isolate → Collect → Preserve** del Flujo_Investigacion sobre un
**contenedor Docker comprometido** del Entorno_Laboratorio (p. ej. el DVWA atacado
por el Red Team). Produce las evidencias, sus hashes y la Cadena_Custodia.

## Las dos reglas que nunca se rompen

1. **Prohibido `docker exec` y prohibido escribir dentro del contenedor víctima.**
   Nada de abrir una shell, tocar archivos ni reiniciar procesos dentro del
   contenedor: altera mtimes, logs y memoria, y contamina la escena. Todo se observa
   **desde fuera** con subcomandos de solo lectura del demonio Docker.
2. **Siempre sobre la copia del profesor**, nunca sobre el contenedor de producción
   ni sobre el host EC2 anfitrión. El objetivo autorizado es el **contenedor**
   (`host_is_target: false` en `scope.yaml`).

## Antes de tocar nada (obligatorio, en este orden)

### 1. Pre-flight: comprobar el entorno

Va **envuelto en una función** para que `return` sea válido tanto si copias el bloque
en una shell como si lo ejecutas en un script; si algo falta, detente y resuélvelo
**fuera** del contenedor víctima:

```bash
preflight() {
  docker info >/dev/null 2>&1 || { echo "ERROR: el demonio Docker no responde (arráncalo: OrbStack/Docker Desktop)"; return 1; }
  command -v sha256sum >/dev/null || { echo "ERROR: falta sha256sum (coreutils)"; return 1; }
  command -v tar        >/dev/null || { echo "ERROR: falta tar"; return 1; }
  command -v python3    >/dev/null || { echo "ERROR: falta python3 (se usa para leer scope.yaml)"; return 1; }
  if command -v jq >/dev/null; then echo "jq OK (cadena de custodia con jq)";
  else echo "AVISO: no hay jq → usa la variante SIN jq de coc_append (Paso 3.2)"; fi
}
preflight || exit 1
```

- El **demonio Docker debe estar corriendo**; nada de instalar herramientas **dentro**
  del contenedor víctima. `jq` es opcional (hay variante sin `jq`); `python3` solo se
  usa para leer `scope.yaml`.

### 2. Modo de ejecución

Lee `Modo_Ejecucion` (`script-kiddie` | `green-hat` | `pro`, default `script-kiddie`).
Si el prompt no lo indica, **pregunta** antes de recolectar.

### 3. Variables de trabajo (todo derivado de `ENGAGEMENT_ID`, nada en duro)

Fijas **dos** valores: el engagement y el asset del `scope.yaml` bajo investigación.
El resto —directorio de evidencia, cadena de custodia y el propio `CONTAINER`— se
**derivan**; el contenedor se **lee del `scope.yaml`**, nunca se teclea a mano:

```bash
export ENGAGEMENT_ID="dvwa-lab-ulsa"      # el engagement (real o de prueba)
export ASSET_ID="dvwa-01"                 # id del asset en scope.yaml a investigar
export ANALYST="Aristide Cordonnier"

# Camino COMPLETO: el scope.yaml real vive bajo agent_ethack_dfir/engagements/.
export ENG_DIR="agent_ethack_dfir/engagements/${ENGAGEMENT_ID}"
export SCOPE="${ENG_DIR}/scope.yaml"
export EVID_DIR="${ENG_DIR}/evidence"
export COC="${EVID_DIR}/chain_of_custody.jsonl"
mkdir -p "${EVID_DIR}"

# CONTAINER derivado del scope.yaml (NO se teclea):
export CONTAINER="$(python3 -c 'import sys,yaml
d=yaml.safe_load(open(sys.argv[1])) or {}
a=[x for x in d.get("assets",[]) if x.get("id")==sys.argv[2]]
print(a[0].get("container_id","") if a else "")' "$SCOPE" "$ASSET_ID")"
[ -n "$CONTAINER" ] || { echo "ERROR: asset '${ASSET_ID}' no está en ${SCOPE}"; exit 1; }
echo "ENGAGEMENT=${ENGAGEMENT_ID}  ASSET=${ASSET_ID}  CONTAINER=${CONTAINER}  EVID_DIR=${EVID_DIR}"
```

### 4. Validar la Allowlist_Objetivos (comando, no "a ojo")

El objetivo autorizado es el **contenedor**; el host queda fuera (`host_is_target:
false`). Esta comprobación **falla y detiene** si el asset no está en `scope.yaml` o
si declara el host como objetivo, de modo que **no se contornea el alcance**:

```bash
python3 -c 'import sys,yaml,datetime
d=yaml.safe_load(open(sys.argv[1])) or {}
aid=sys.argv[2]
a=[x for x in d.get("assets",[]) if x.get("id")==aid]
assert a, f"FUERA DE ALCANCE: asset {aid} no está en scope.yaml"
a=a[0]
assert a.get("host_is_target") is False, "host_is_target debe ser false (objetivo = contenedor, no host)"
# Ventana autorizada (Req 11.6): fuera de ella NO hay actividad.
w=d.get("authorized_window") or {}
now=datetime.datetime.now(datetime.timezone.utc)
s=datetime.datetime.fromisoformat(str(w.get("start","")).replace("Z","+00:00"))
e=datetime.datetime.fromisoformat(str(w.get("end","")).replace("Z","+00:00"))
assert s<=now<=e, "FUERA DE VENTANA AUTORIZADA (authorized_window): revisa scope.yaml"
print("EN ALCANCE y EN VENTANA:", aid, "-> contenedor", a.get("container_id"))' "$SCOPE" "$ASSET_ID" \
  || { echo "Detente: fuera de la Allowlist_Objetivos o de la ventana autorizada."; exit 1; }
```

> **La guardia valida alcance Y ventana.** Además del asset y `host_is_target: false`,
> comprueba `authorized_window`: si estás fuera de la ventana del engagement, aborta.
> No operes fuera de ventana aunque el objetivo esté en la allowlist.

> **El scope no se salta.** Si vas a trabajar contra un contenedor de **prueba** (p. ej.
> `test-dvwa`), no edites comandos ni te saltes esta comprobación: decláralo en un
> **engagement de prueba local** (sección siguiente) para que la validación pase con
> normalidad.

### 5. Confirmar el nombre REAL del contenedor (`docker ps`, antes de tocar estado)

`CONTAINER` viene del `scope.yaml`, pero ese campo puede traer un nombre **sintético o
desactualizado** (caso real: `scope.yaml` decía `dvwa-ec2-i-…` cuando el nombre real
era `dvwa`). **Antes** de cualquier acción que altere estado —sobre todo
`docker pause`— confirma que el nombre existe de verdad en el host objetivo; si no,
pausarías el contenedor equivocado (o producción):

```bash
# en el host donde corre Docker (local, o por el salto SSH de la sección remota):
docker ps --format '{{.Names}}\t{{.Image}}\t{{.Status}}' \
  | grep -E "(^|[[:space:]])${CONTAINER}([[:space:]]|$)" \
  || { echo "ERROR: contenedor '${CONTAINER}' no corre aquí; revisa scope.yaml y 'docker ps -a'"; exit 1; }
```

## Engagement de prueba local (self-test, sin commit)

Para ensayar el Power sobre un contenedor propio **sin tocar el engagement real y sin
contornear el scope**, crea un engagement de prueba cuyo `scope.yaml` declare ese
contenedor. El sufijo `-selftest` lo mantiene **fuera del repositorio** (`.gitignore`
excluye `engagements/*-selftest/`):

```bash
export ENGAGEMENT_ID="test-dvwa-selftest"   # el sufijo -selftest NO se commitea
export ASSET_ID="test-dvwa"
# camino COMPLETO, junto al scope.yaml real (agent_ethack_dfir/engagements/):
mkdir -p "agent_ethack_dfir/engagements/${ENGAGEMENT_ID}"
cat > "agent_ethack_dfir/engagements/${ENGAGEMENT_ID}/scope.yaml" <<'YAML'
engagement_id: test-dvwa-selftest
owner: self-test
status: approved
assets:
  - id: test-dvwa
    kind: container
    service: dvwa-web
    container_id: test-dvwa              # nombre/id del contenedor de prueba
    container_image: vulnerables/web-dvwa
    host_is_target: false                # el host NO es objetivo
YAML
```

Después, **repite el Paso 3 y el Paso 4** con estos valores: el `CONTAINER` se deriva
del `scope.yaml` de prueba y la validación de alcance pasa porque `test-dvwa` está
**declarado** con `host_is_target: false`. El resto del skill no cambia.

## Paso 1 — Isolate: cortar el daño sin perder el estado

Hay que frenar al atacante **sin destruir evidencia volátil**.

**Por defecto, aísla con `docker pause`.** Congela todos los procesos con el
*freezer* de cgroups: detiene la ejecución del atacante al instante y deja
**intactos la memoria y, sobre todo, la configuración de red** (interfaces, IP,
puertos publicados, conexiones) que el paso siguiente, `docker inspect`, debe
capturar. Los cinco comandos de recolección funcionan sobre el contenedor pausado
(son observación externa).

```bash
docker pause ${CONTAINER}          # aislamiento recomendado por defecto
```

**`docker network disconnect` solo si el Incident Manager lo pide** (p. ej. porque
quiere mantener los procesos *vivos* para observarlos en ejecución). Cuidado con el
efecto colateral: **desconectar borra la configuración de red** del contenedor, que
es justo la que `docker inspect` debería recoger. Si el IM lo ordena, captura
**primero** `docker inspect` y **después** desconecta, y déjalo por escrito.

```bash
# SOLO por decisión explícita del Incident Manager, y tras capturar docker inspect:
docker network disconnect <red> ${CONTAINER}   # <red>: el nombre que muestre docker inspect
```

**Tercer caso: recolección EN CALIENTE, sin aislar.** Si el contenedor está en un
**laboratorio compartido o en un entorno tipo producción** donde pausarlo o
desconectarlo afectaría a otras equipas o al servicio, el Incident Manager puede
decidir **no aislar** y recolectar sobre el contenedor vivo. Los cinco subcomandos de
recolección son observación de solo lectura y **no modifican** el contenedor, así que
la recolección en caliente es válida; lo que se pierde es la garantía de que el estado
no cambie **durante** la captura. Deja constancia **obligatoria** en la Cadena_Custodia
de que se recolectó en caliente, sin `pause`, y por qué (caso real: lab compartido por
otras equipas, decisión del Incident Manager/profesor).

- **Nunca** `docker stop` ni `docker kill` para aislar: terminan los procesos y
  **pierden el estado volátil** (RFC 3227). Solo se detiene el contenedor si el
  Incident Manager lo ordena y **después** de recolectar.
- Anota en la Cadena_Custodia la decisión de aislamiento (o la de **no** aislar) y quién
  la tomó.

## Recolección remota (Docker en un host EC2 por salto SSH)

El caso de laboratorio puede tener el demonio Docker **en un host EC2 remoto**,
alcanzable solo por **salto SSH a través de la Kali**. La metodología no cambia; solo
cambia **dónde** corren los comandos y **a dónde** va su salida:

- **La clave privada no sale de tu puesto.** Usa **reenvío de agente** (`ssh -A`) para
  que el salto Kali→host use tu clave sin copiarla a la Kali.
- **No escribas en el host objetivo.** Redirige la salida de cada subcomando a la Kali
  (o a tu puesto); el `docker export` va en **streaming** host→Kali, sin dejar el
  `.tar` en el disco del host.
- **`ssh -n` en los saltos internos.** Un `ssh … 'cmd'` dentro de un script hereda el
  stdin del script (p. ej. un heredoc) y lo **consume**, cortando el resto del script.
  `ssh -n` desconecta el stdin y lo evita.

**Una sola orden de solo lectura por el salto** (confirmar el nombre con el `docker ps`
del Paso 5, o un reconocimiento previo) no necesita el heredoc ni el agente: usa
`ProxyCommand` + `-W`. El `ProxyCommand` corre en **tu puesto**, así que la clave
tampoco sale de ahí y no toca la Kali:

```bash
KEY=/ruta/tu_clave.pem
PROXY="ssh -i $KEY -o StrictHostKeyChecking=accept-new -W %h:%p kali@<KALI>"
# p. ej. el docker ps de confirmación del nombre (Paso 5), en solo lectura:
ssh -i "$KEY" -o StrictHostKeyChecking=accept-new -o ProxyCommand="$PROXY" \
    ec2-user@<HOST_DVWA> 'sudo docker ps --format "{{.Names}}\t{{.Image}}\t{{.Status}}"'
```

**La colecta completa** (varios subcomandos + `export` en streaming) sí usa el agente
(`ssh -A`) y el heredoc:

```bash
# Desde tu puesto: agente con tu clave; master a la Kali con -A; se colecta EN la Kali.
eval "$(ssh-agent -s)"; ssh-add /ruta/tu_clave.pem
ssh -A kali@<KALI> 'bash -s' <<'REMOTE'
  set -e
  EVID=~/forensics/docker-forensics-$(date -u +%Y%m%dT%H%M%SZ)/evidence; mkdir -p "$EVID"
  H="ssh -n -o StrictHostKeyChecking=accept-new ec2-user@<HOST_DVWA>"   # -n: no consumir el heredoc
  $H 'sudo docker top <CONTAINER> auxww'          > "$EVID/01_docker_top.txt"
  $H 'sudo docker inspect <CONTAINER>'            > "$EVID/02_docker_inspect.json"
  $H 'sudo docker diff <CONTAINER>'               > "$EVID/03_docker_diff.txt"
  $H 'sudo docker logs --timestamps <CONTAINER>'  > "$EVID/04_docker_logs.txt" 2>&1
  $H 'sudo docker export <CONTAINER>'             > "$EVID/05_docker_export.tar"   # streaming host->Kali
  ( cd "$EVID" && sha256sum 0*_* > SHA256SUMS && sha256sum -c SHA256SUMS )
REMOTE
ssh-agent -k
```

El resto del skill (hashes, Cadena_Custodia, análisis) es idéntico. La evidencia pesada
queda **en la Kali**, fuera del repositorio.

## Paso 2 — Collect: recolectar en Orden_Volatilidad (RFC 3227)

El orden va **de lo más volátil a lo más estable**: primero lo que vive en memoria
o puede cambiar en segundos, al final el artefacto pesado y estable.

```bash
# 1) docker top — procesos en ejecución (lo más volátil: lista viva del kernel)
docker top ${CONTAINER} auxww > "${EVID_DIR}/01_docker_top.txt"

# 2) docker inspect — estado, configuración, red, montajes, PID, arranque
docker inspect ${CONTAINER} > "${EVID_DIR}/02_docker_inspect.json"

# 3) docker diff — cambios del filesystem respecto a la imagen (A/C/D)
docker diff ${CONTAINER} > "${EVID_DIR}/03_docker_diff.txt"

# 4) docker logs --timestamps — stdout/stderr con marca temporal
docker logs --timestamps ${CONTAINER} > "${EVID_DIR}/04_docker_logs.txt" 2>&1

# 5) docker export — snapshot completo del filesystem (lo más estable; al final)
docker export ${CONTAINER} -o "${EVID_DIR}/05_docker_export.tar"
```

**Por qué ese orden exacto:**

1. **`docker top` primero** — es la foto de los **procesos vivos**, el dato más
   volátil: desaparece en cuanto el contenedor se detiene o el atacante mata su
   proceso. Se captura antes que nada.
2. **`docker inspect`** — el **estado y la configuración en runtime** (red, PID,
   variables, montajes, hora de arranque). Es metadato volátil que cambia si el
   contenedor se reinicia o reconfigura.
3. **`docker diff`** — la **delta del filesystem** (qué se añadió/modificó/borró
   frente a la imagen). Refleja el estado **actual** del disco; se toma antes del
   export para saber qué mirar y para cotejarlo después.
4. **`docker logs --timestamps`** — logs de stdout/stderr con tiempo; útiles pero
   menos volátiles que el proceso y la config. Las marcas temporales dan la primera
   línea de tiempo.
5. **`docker export` al final** — es el artefacto **más pesado y más estable**: un
   `.tar` con todo el filesystem. Se hace al último para que los pasos anteriores
   reflejen el estado vivo **antes** de cualquier cambio, y porque el `.tar` queda
   como copia estable que se analiza **offline**, sin volver a tocar el contenedor.

> **Regla:** entre el paso 1 y el 5 no se entra al contenedor ni se escribe en él;
> todo es observación externa, también con el contenedor pausado.

## Paso 3 — Preserve: hash por evidencia + Cadena_Custodia encadenada

### 3.1 Hash de cada evidencia (y un manifiesto verificable)

```bash
cd "${EVID_DIR}"
sha256sum 01_docker_top.txt 02_docker_inspect.json 03_docker_diff.txt \
          04_docker_logs.txt 05_docker_export.tar > SHA256SUMS
sha256sum -c SHA256SUMS          # verificación inmediata: todo debe decir "OK"
cd - >/dev/null
```

`SHA256SUMS` es el **manifiesto**. La integridad se revalida con `sha256sum -c`
**antes y después** de analizar: el análisis solo es válido si `hash_pre == hash_post`
(ver el skill `docker-evidence-analysis`).

### 3.2 Cadena_Custodia encadenada (`chain_of_custody.jsonl`)

Una **línea JSON por acción**, con hora UTC, analista, acción, archivo, su `sha256`
y el `sha256` de la **línea anterior** (`prev_sha256`), de modo que toda la cadena
quede **encadenada** (si se altera o borra una línea, el enlace se rompe).

Helper para añadir un eslabón (Kiro lo usa tras cada evidencia; en modo `pro` se
guía al analista a escribirlo). **Variante con `jq`** (recomendada):

```bash
coc_append() {                       # uso: coc_append "<acción>" "<archivo-en-EVID_DIR>"
  local accion="$1" archivo="$2" ts analyst fsha prev line
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  analyst="${ANALYST:?define ANALYST}"
  fsha="$(sha256sum "${EVID_DIR}/${archivo}" | awk '{print $1}')"
  if [ -s "${COC}" ]; then
    prev="$(tail -n 1 "${COC}" | sha256sum | awk '{print $1}')"   # sha256 de la línea anterior (CON su salto \n)
  else
    prev="GENESIS"                                                # primer eslabón
  fi
  line="$(jq -c -n --arg ts "$ts" --arg an "$analyst" --arg ac "$accion" \
            --arg f "$archivo" --arg sha "$fsha" --arg prev "$prev" \
            '{ts_utc:$ts, analyst:$an, action:$ac, file:$f, sha256:$sha, prev_sha256:$prev}')"
  printf '%s\n' "${line}" >> "${COC}"
}
```

**Variante SIN `jq`** (si el pre-flight avisó de que no está). Vale porque los campos
aquí son controlados (fechas, hashes hex, rutas y acciones sin comillas dobles ni
`\`); si una acción pudiera contenerlas, usa la variante con `jq`:

```bash
coc_append() {                       # misma firma, sin dependencia de jq
  local accion="$1" archivo="$2" ts analyst fsha prev
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  analyst="${ANALYST:?define ANALYST}"
  fsha="$(sha256sum "${EVID_DIR}/${archivo}" | awk '{print $1}')"
  if [ -s "${COC}" ]; then prev="$(tail -n 1 "${COC}" | sha256sum | awk '{print $1}')"; else prev="GENESIS"; fi
  printf '{"ts_utc":"%s","analyst":"%s","action":"%s","file":"%s","sha256":"%s","prev_sha256":"%s"}\n' \
    "$ts" "$analyst" "$accion" "$archivo" "$fsha" "$prev" >> "${COC}"
}
```

> **Invariante del encadenado (no lo cambies).** `prev_sha256` es el `sha256` de la
> **línea anterior completa, incluido su salto de línea final `\n`**, tal como quedó
> escrita. Por eso se calcula con `tail -n 1 … | sha256sum` al encadenar y con
> `printf '%s\n' "$line" | sha256sum` al verificar: **ambos incluyen el `\n`**. Una
> implementación que hashee la línea **sin** el salto (p. ej. `printf '%s'` a secas)
> verá la cadena "rota" aunque esté intacta. Verifícala siempre con el comando de
> abajo.

```bash
# Un eslabón por cada evidencia recolectada, en orden:
coc_append "isolate: docker pause (por defecto; disconnect solo si lo pide el IM)" "01_docker_top.txt"
coc_append "collect: docker top"              "01_docker_top.txt"
coc_append "collect: docker inspect"          "02_docker_inspect.json"
coc_append "collect: docker diff"             "03_docker_diff.txt"
coc_append "collect: docker logs --timestamps" "04_docker_logs.txt"
coc_append "collect: docker export"           "05_docker_export.tar"
coc_append "preserve: manifiesto SHA256SUMS"  "SHA256SUMS"
```

Una línea de ejemplo:

```json
{"ts_utc":"2026-11-10T14:03:22Z","analyst":"Aristide Cordonnier","action":"collect: docker export","file":"05_docker_export.tar","sha256":"9f2c…","prev_sha256":"4ab1…"}
```

Verificar la integridad de la cadena en cualquier momento (cada `prev_sha256` debe
coincidir con el `sha256` de la línea anterior):

```bash
prev="GENESIS"; n=0; roto=0
while IFS= read -r line; do
  n=$((n+1))
  decl="$(printf '%s' "$line" | sed -E 's/.*"prev_sha256":"([^"]*)".*/\1/')"   # sin jq
  [ "$decl" = "$prev" ] || { echo "CADENA ROTA en línea $n: declara $decl, esperaba $prev"; roto=1; }
  prev="$(printf '%s\n' "$line" | sha256sum | awk '{print $1}')"               # incluye el \n (ver invariante)
done < "${COC}"
[ "$roto" = 0 ] && echo "Cadena_Custodia íntegra: ${n} eslabones."
```

## Salida de este skill

- `${EVID_DIR}/01_docker_top.txt … 05_docker_export.tar` — las cinco evidencias.
- `${EVID_DIR}/SHA256SUMS` — manifiesto verificable con `sha256sum -c`.
- `${EVID_DIR}/chain_of_custody.jsonl` — Cadena_Custodia encadenada por `sha256`.

> **Qué se versiona y qué no.** Las evidencias pesadas (sobre todo
> `05_docker_export.tar`, cientos de MB) y el `rootfs` extraído en el análisis **nunca**
> van al repositorio: `.gitignore` excluye `engagements/*/evidence/*` y
> `engagements/*/analysis/`. Lo **único** que permanece versionado en `evidence/` es
> `chain_of_custody.jsonl` (la cadena ya guarda el `sha256` de cada evidencia).
> Conserva los blobs en un almacén aparte (S3 Object Lock, disco de evidencia) si hay
> que retenerlos.

El análisis continúa en `docker-evidence-analysis` **sobre `05_docker_export.tar`**,
tras revalidar `sha256sum -c SHA256SUMS`.

## Por modo de ejecución

- **script-kiddie:** entrega los comandos de arriba ya listos y un resumen de qué se
  recolectó, con explicación mínima.
- **green-hat:** antes de ejecutar explica el Orden_Volatilidad y por qué `export`
  va al final; pide predecir qué mostrará `docker diff`.
- **pro:** no entrega el bloque hecho; guía al analista a construir la secuencia y el
  `coc_append`, discute aislar con `pause` vs `disconnect` y exige la justificación
  ética/legal (alcance, copia, no-`exec`) por escrito.
