# Realimentación del resultado — `docker-forensics` (Req 15.4)

> Artefacto_Documentacion obligatorio. Registra la realimentación del resultado del
> Power al probarlo contra el Entorno_Laboratorio: qué salió bien, qué se corrigió y
> qué queda pendiente.

## Sesión de prueba (self-test, modo green-hat)

Se probó de punta a punta sobre un contenedor desechable propio (`test-dvwa`, imagen
`vulnerables/web-dvwa`, publicado solo en `127.0.0.1`), simulando un ataque:
webshell `/var/www/html/shell.php` + borrado de una línea del `access.log`. No se
tocó el DVWA del laboratorio (`scope.yaml`) ni el host; las evidencias fueron a un
directorio efímero.

### Qué funcionó

- Recolección en Orden_Volatilidad (`docker top → inspect → diff → logs → export`)
  sin `docker exec` ni escritura en el contenedor víctima.
- Cadena_Custodia encadenada (10 eslabones); la prueba de manipulación de una línea
  rompió el enlace como se espera.
- Integridad `hash_pre == hash_post` del export; análisis del `.tar` en solo lectura.
- `docker diff` marcó el webshell como `A /var/www/html/shell.php`; los `grep`
  identificaron `sqlmap` y `Nikto`.
- El borrado de huella se detectó y la línea eliminada se **recuperó** cruzando
  `docker logs` con el `access.log` del `.tar`.

## Qué se corrigió tras la realimentación (7 huecos detectados en la prueba)

1. **Cruce `docker logs` ↔ `access.log` (lo más importante).** El Power recolectaba
   ambas fuentes pero no decía compararlas. Añadido el Paso **4.1** en
   `docker-evidence-analysis` (`comm -23` para recuperar líneas borradas); explica que
   por eso se recolecta `docker logs` **antes** del `export`.
2. **Aislamiento.** `docker network disconnect` borra el estado de red que
   `docker inspect` debe capturar. Ahora se recomienda **`docker pause` por defecto**
   (con el porqué) y `disconnect` **solo si lo pide el Incident Manager** y tras
   capturar `inspect`. Corregido en `docker-evidence-collection` y en el README.
3. **Pre-flight.** Añadida una comprobación inicial en `docker-evidence-collection`:
   demonio Docker activo, `sha256sum`/`tar` presentes y `jq` opcional, con una
   **variante de `coc_append` sin `jq`**.
4. **Rutas de log.** Antes se asumía `var/log/apache2/`. Ahora el Paso 2 **descubre**
   dónde loguea Apache (`CustomLog`/`ErrorLog`, `find`) y maneja el caso
   **`access.log → /dev/stdout`** (apoyarse en `docker logs`).
5. **Ruido de `docker diff`.** Añadido un filtro del ruido del runtime (sesiones PHP,
   `/run`, `/var/lib/mysql`, certificados de OrbStack/Docker Desktop) y una tabla de
   **dónde mirar de verdad** (docroot, `/tmp`, cron, `/etc`, home, `/var/log`).
6. **Límite de `docker export` con los mtime.** Documentado que el export no conserva
   bien las marcas de tiempo, así que `find -newermt` **no prueba** timestomping
   (T1070.006); es indicio débil. Se apoya en `docker logs`/`docker inspect`.
7. **Invariante del encadenado.** Documentado que `prev_sha256` se calcula sobre la
   línea anterior **incluido su salto `\n`**, con el comando de verificación exacto
   (`tail -n 1 | sha256sum` al encadenar, `printf '%s\n' | sha256sum` al verificar)
   para que otra implementación no vea "cadena rota" en falso.

## Segunda ronda — scope, rutas y pulidos (tras el 2º self-test)

El 2º self-test confirmó que los 7 huecos anteriores se sostienen corriendo el Power
al pie de la letra. Quedaba un problema de fondo —el Power asumía el engagement real y
había que fijar variables a mano y saltarse el scope— ya corregido **sin contornear el
alcance**:

8. **Variables derivadas de `ENGAGEMENT_ID`, nada en duro.** `ENG_DIR`, `SCOPE`,
   `EVID_DIR` y `COC` se derivan; el `CONTAINER` se **lee del `scope.yaml`** (por
   `ASSET_ID`) con `python3`, no se teclea. (`docker-evidence-collection` Paso 3 y
   `docker-evidence-analysis` Paso 0.)
9. **Validación de alcance como comando que detiene.** El Paso 4 comprueba contra
   `scope.yaml` que el asset existe y que `host_is_target: false`; si no, aborta
   (`exit 1`). Ya no es "a ojo" ni se salta.
10. **Engagement de prueba local (sin commit).** Documentado cómo crear el
    `scope.yaml` de prueba en su **camino completo**
    `agent_ethack_dfir/engagements/<algo>-selftest/` (donde vive el scope.yaml real),
    para que la validación de alcance pase con normalidad.
11. **Evidencia pesada fuera del repo.** `.gitignore` con prefijo **`**/`** (casa a
    cualquier profundidad: raíz y `agent_ethack_dfir/engagements/`) excluye
    `**/engagements/*/evidence/*` (incluido el `.tar` y `SHA256SUMS`),
    `**/engagements/*/analysis/` y `**/engagements/*-selftest/`; **solo**
    `chain_of_custody.jsonl` queda versionado. Un patrón anclado a la raíz
    (`engagements/...`) **no** cubría `agent_ethack_dfir/engagements/`; corregido y
    verificado con `git check-ignore --no-index`.
12. **`return 1` del pre-flight.** Envuelto en una función `preflight()` (ahí `return`
    es válido) y llamado con `preflight || exit 1`.
13. **Webshell en los logs no solo en `/hackable/uploads`.** El Paso 2 ahora busca
    también cada `.php` que `docker diff` marcó **añadido (A)** y las peticiones con
    parámetros de ejecución (`cmd=|exec=|command=|shell=|c=|run=…`).
14. **`find -empty` con exclusiones.** Se descartan los vacíos por diseño: `btmp`,
    `wtmp`, `lastlog`, `faillog`, `tallylog`, `other_vhosts_access.log`.

## Tercera ronda — primer caso REAL (DVWA del lab, 2026-11-23, modo green-hat)

Primera pasada contra el contenedor real `dvwa` en AWS (`10.50.0.34`), no un
self-test. Resultado: ataque reconstruido de punta a punta (SQLi UNION con volcado de
`users`, inyección de comandos, 3 webshells, y **borrado de huellas** vía
`cleanup.php`), integridad `hash_pre == hash_post`, cadena de 11 eslabones íntegra.
Lo que el Power **no cubría** para este caso real:

15. **Docker remoto, no local.** El Power asume `docker` en la máquina local y la
    evidencia escrita en el repo. En el caso real `docker` corre en un **host EC2
    remoto**, alcanzable **solo** por salto SSH a través de la Kali. Falta una guía de
    **recolección remota**: salto SSH / reenvío de agente (la clave privada no debe
    salir del puesto del analista), **streaming del `export` host→Kali** para no
    escribir en el host objetivo, y la trampa de que un `ssh ... 'cmd'` dentro de un
    heredoc **consume el stdin** del script (se corrige con `ssh -n`). Hoy el analista
    tuvo que improvisar todo esto; debería ser un modo documentado del Power.
16. **El cruce antiforense solo matchea `GET|POST|HEAD|PUT`.** El `grep` del Paso 4.1
    excluye `OPTIONS`, `PROPFIND` y métodos exóticos (p. ej. los de un escaneo Nmap
    NSE), lo que produjo un **falso positivo de "18 líneas borradas"** que en realidad
    estaban en ambas fuentes. Debe normalizarse con un patrón agnóstico al método
    (`\] "[A-Z]+ `) o comparar solo la parte de la petición.
17. **Archivo creado-y-borrado dentro de la vida del contenedor = invisible.** El
    hallazgo estrella de borrado de huellas (`test_shell.php`) **no** aparece en el
    `.tar` **ni** en `docker diff` (no deja `A` ni `D`, porque nunca estuvo en la
    imagen base y se borró antes del export). El Power enseña a recuperar **líneas de
    log** borradas, pero no advierte este caso de **fichero** borrado que solo
    sobrevive en `docker logs`/`error.log`. Debe decirlo explícitamente.
18. **La advertencia de mtimes está exagerada para `docker export`.** En el caso real
    el `.tar` **sí** conservó los mtime y coincidieron con la cronología de los logs
    (uploads 04:01/04:04/04:06). El límite real es la historia de capas, no los mtime;
    conviene matizar el Paso 4 para no descartar una pista válida.
19. **Fuente de log externa (CloudWatch) como referencia infalsificable.** El profesor
    pidió cotejar con `/ethack-lab/dvwa` en CloudWatch (que la Red Team no puede
    borrar). El Power solo la menciona en "remediación", no como **paso de análisis**.
    Falta una guía para traer una fuente externa (CloudWatch Logs, `aws logs
    get-log-events`) y diferenciarla contra los logs del contenedor. (En esta pasada
    no fue posible: la Kali no tenía rol IAM ni perfil AWS.)
20. **La guardia de alcance no valida la ventana temporal.** El check del Power
    confirma allowlist + `host_is_target`, pero **no** `authorized_window`; hubo que
    verificarla aparte. Debería integrarse en la misma guardia.
21. **Aislamiento "ninguno" como caso de primera clase.** El Power ofrece `pause`
    (defecto) o `disconnect`; el caso real fue **sin aislamiento** por ser un lab
    **compartido/producción**. Falta ese tercer camino explícito ("recolectar en
    caliente, sin aislar") con su nota de custodia obligatoria.
22. **Confirmar el nombre real del contenedor antes de operar.** `container_id` en el
    `scope.yaml` traía un nombre sintético (`dvwa-ec2-i-...`); el nombre real era
    `dvwa`. El Power deriva `CONTAINER` del scope y (en el flujo normal) lo **pausa**:
    si el nombre está mal, se pausaría el contenedor equivocado. Debe exigir un
    `docker ps` de confirmación del nombre **antes** de cualquier acción que altere
    estado.
23. **Excluir las IP conocidas del lab ANTES de atribuir (hueco encontrado por el
    analista).** El primer borrador del reporte clasificó `<IP-analista>` como sonda
    de ataque cuando era el **Mac del analista**. El Power no decía nada sobre separar
    el ruido propio del lab del tráfico del atacante. Debe añadir, al inicio del
    análisis, una **lista de IP conocidas** (Kali, Mac/estaciones de analistas, prof,
    Blue Team, escáneres autorizados) y **excluirlas de los IoC**, dejándolo explícito
    en el reporte. Sin ese paso, cualquier conexión legítima del equipo contamina la
    atribución y los indicadores. Añadido el **Paso 0.1** en `docker-evidence-analysis`
    y una fila "IP conocidas (excluidas)" en la plantilla de `docker-forensics-report`.

## Correcciones aplicadas al Power tras el caso real (ronda 3)

Los huecos **15-18 y 20-23** se **cerraron** en los skills tras el caso real; el
**19 (CloudWatch como paso de análisis)** se deja **pendiente a propósito** (el
profesor pidió dejarlo para después).

- **15** → `docker-evidence-collection`: nueva sección "Recolección remota (Docker en
  host EC2 por salto SSH)" con reenvío de agente (la clave no sale del puesto del
  analista), `ssh -n` para no consumir el stdin del script, y `docker export` en
  **streaming host→Kali** sin escribir en el host objetivo.
- **16** → `docker-evidence-analysis` Paso 4.1: el `grep` del cruce ahora es agnóstico
  al método (`\] "[A-Z]+ `), no solo `GET|POST|HEAD|PUT`.
- **17** → `docker-evidence-analysis` Paso 4.2: nota de que un **archivo creado y
  borrado** dentro de la vida del contenedor no deja `A` ni `D` en `docker diff` ni
  aparece en el `.tar`; solo se recupera por `docker logs`/`error.log`.
- **18** → `docker-evidence-analysis` Paso 4: matizada la advertencia de mtimes
  (`docker export` **sí** guarda mtimes en el tar; el límite real es la historia de
  capas). Mtimes coherentes = corroboración válida.
- **20** → `docker-evidence-collection` Paso 4: la guardia de alcance ahora **también
  valida `authorized_window`** (aborta fuera de ventana).
- **21** → `docker-evidence-collection` Paso 1: **recolección en caliente sin aislar**
  como tercer camino de primera clase (lab compartido/producción), con su nota de
  custodia obligatoria.
- **22** → `docker-evidence-collection` Paso 4: exige `docker ps` para **confirmar el
  nombre real del contenedor** antes de cualquier acción que altere estado.
- **23** → `docker-evidence-analysis` Paso 0.1 + plantilla de reporte (arriba).

## Cuarta ronda — conversión al formato `POWER.md` (instalable en Kiro)

El Power **no se instalaba** en Kiro con **Add Custom Power → Local Directory**: su
formato original era `plugin.json` + `skills/<skill>/SKILL.md` (estilo
agent-plugins.org), que ese instalador **no reconoce**. El cimiento `dfir-linux`
**sí** se instala porque trae un `POWER.md` en la raíz y un directorio `steering/`.
Se convirtió `docker-forensics` al **mismo formato**, sin cambiar los valores del
contrato:

24. **`POWER.md` en la raíz.** Nuevo `POWER.md` con el **mismo frontmatter que
    `dfir-linux`** (`name`, `displayName`, `description`, `keywords`, `author`,
    `x-ethack`) y el **bloque `x-ethack` tal cual del antiguo `plugin.json`** —
    valores sin cambios: `kind: forensics`, `forensicsStage: Collect`
    (`ecCouncilPhase: null`), `team`/`owner`, las 4 herramientas reales (`docker`,
    `sha256sum`, `tar`, `grep`), `allowlistValidation.required: true`,
    `producesActionLog: true`, los tres `Modo_Ejecucion` (default `script-kiddie`) y
    el bloque `documentation`.
25. **Skills → `steering/`.** Las tres skills se **movieron** a `steering/` (un `.md`
    por guía, **contenido tal cual**): `docker-evidence-collection.md`,
    `docker-evidence-analysis.md` y `docker-forensics-report.md`. Quedan listadas en
    `POWER.md` y se cargan **bajo demanda** (como las guías de `dfir-linux`).
26. **`plugin.json` y `skills/` eliminados.** El descubrimiento de Powers
    (`catalog.discover_powers` / `power_adapter.find_power_dirs`) cuenta **por
    directorio** el que tenga `plugin.json` **o** `POWER.md`, y `load_power` lee
    `plugin.json` **antes** que `POWER.md`. Dejar ambos haría que el adaptador
    ignorara el nuevo `POWER.md`; por eso se borró `plugin.json` (el `POWER.md` pasa
    a ser el contrato autoritativo, con los mismos valores) y se borró `skills/` (su
    contenido ya vive en `steering/`). El directorio conserva **un único marcador**
    (`POWER.md`) → el Power se cataloga **una sola vez**.
27. **`make validate` sigue en verde.** 10 Powers descubiertos, `docker-forensics`
    contado una vez, ahora con `format: POWER.md`; el adaptador valida el mismo
    `x-ethack` del frontmatter (herramientas no vacías, etapa forense sin fase
    EC-Council, allowlist obligatoria, modos y documentación). `docStatus` sigue
    completo (`prompt.md`, `sessions/`, `feedback.md` intactos).

> Las sesiones de las rondas 1–3 y el `prompt.md` conservan, como registro
> histórico, las referencias a `plugin.json` y a `skills/`: documentan cómo se
> construyó el Power antes de esta conversión y no se reescriben.

## Quinta ronda — segundo caso real (re-ejecución, 2026-11-23, green-hat)

Segunda pasada completa contra el contenedor real `dvwa` (10.50.0.34, por salto SSH a
través de la Kali), ya con los correctivos 15-18 y 20-27 en las guías. Las seis
correcciones pedidas se sostuvieron corriendo el Power al pie de la letra: recolección
remota (`ssh -A`/`ssh -n`, export en streaming), guardia de alcance + ventana en un
solo bloque, confirmación del nombre con `docker ps`, nota de recolección en caliente
en la custodia, exclusión de IP conocidas y cruce de logs agnóstico al método
(232 vs 232, `comm -23` vacío; captura OPTIONS/PROPFIND/NKFY del escaneo Nmap NSE). Dos
huecos nuevos encontrados y cerrados:

28. **El Paso 0.1 no excluía las direcciones propias del objetivo.** Dos IP "a
    atribuir" no eran ni equipo ni atacante: `3.237.81.237` (la **IP pública del propio
    host DVWA**, tráfico de ataque que entra por la IP pública con **NAT hairpin**) y
    `172.17.0.2` (la **IP del contenedor en el bridge Docker**, tráfico interno). El
    Power listaba Kali/analistas/prof/Blue Team/escáneres, pero no las direcciones
    propias del objetivo. Añadido al Paso 0.1 de `docker-evidence-analysis`: se derivan
    del `scope.yaml` (`target_host`/`ec2_host`) y de `docker inspect`
    (`.NetworkSettings.IPAddress`) y se excluyen antes de atribuir.
29. **La sección remota solo daba el bloque de colecta completa.** Para una **orden
    única de solo lectura** por el salto (el `docker ps` del Paso 5, un reconocimiento
    previo) había que armar la invocación a mano. Añadida la forma con
    `ProxyCommand` + `-W` (sin heredoc ni agente; la clave corre en el puesto del
    analista), junto al bloque de colecta completa con `ssh -A`.

Corrección de un entregable del caso: en el reporte local, `<IP-analista>` se
reclasificó de "sin atribuir" a **IP conocida del analista (excluida)**, como el propio
analista confirmó. `189.216.118.104` (1 petición) queda como "sin atribuir, confianza
baja".

## Pendientes / mejoras futuras

- Validar las rutas de log sobre el `.tar` real del DVWA del laboratorio.
- Confirmar `docker pause` como aislamiento por defecto con el Incident Manager en un
  simulacro.
- Mínimo de ≥2 Powers con Herramienta_Real por alumno (Req 9.6): **no aplica aquí**.
  El profesor confirmó **un solo Power para todo el equipo Digital Forensics**, así
  que el estado "pendiente (<2)" que reporta `make validate` para el responsable es
  **esperado y correcto**, no un fallo a cerrar.
- Power ya cableado al agente de rol `digital-forensics` (lista `powers:` del SOP y
  fila `digital-forensics` de `gen_kiro_agents.py`), con
  `.kiro/agents/ethack-digital-forensics.json` regenerado.
