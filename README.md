# openterminal-proxy — eine eigene Terminal-Instanz pro Nutzer

Open WebUI kennt pro Verbindung **einen** Terminal-Server. Dieser Proxy stellt
sich an diese Stelle, liest den `X-User-Id`-Header, den Open WebUI bei jeder
Anfrage mitschickt, und leitet die Anfrage an einen Container weiter, der nur
diesem Nutzer gehört: beim ersten Zugriff gestartet, nach Leerlauf wieder
entfernt.

Die Container haben **keine Route ins Internet**. Rechnen, Dateien, Shell — ja.
Netz — nein.

```
Open WebUI ──HTTP/WS, Bearer-Key, X-User-Id──► otproxy ──Docker-API──► Container pro Nutzer
                                                  │                    (internes Netz, kein Egress)
                                                  └── /openapi.json, /api/config aus dem Cache
```

---

## Das Wichtigste zuerst — ehrlich

**Kein Egress: ja, und zwar im Kernel.** Jeder Sandbox-Container hängt in einem
eigenen Bridge-Netz mit `Internal: true`. Ein `connect()` nach draußen scheitert
mit „Network is unreachable", bevor ein Paket entsteht. Das ist nichts, was eine
Anwendung durchsetzt und von innen abschaltbar wäre. Nachgeprüft gegen dockerd
29.9.2 (`tests/test_docker.py`).

**Nutzer gegeneinander: ja, über je ein eigenes Netz.** Ein gemeinsames internes
Netz würde Nutzer A erlauben, die Terminal-API von Nutzer B zu erreichen. Jeder
Nutzer bekommt deshalb ein eigenes `/29`, in dem nur sein Container und der
Proxy stehen. Der Test prüft beides: mit `per-user` ist der Nachbar nicht
erreichbar, mit `shared` ist er es — darum ist `per-user` die Voreinstellung.

**Zwei Dinge erledigt Docker nicht für dich:**

1. **Der Host bleibt erreichbar.** Die Gateway-Adresse der Bridge gehört dem
   Host; Pakete dorthin werden lokal zugestellt und nicht geroutet, also sehen
   Dockers Isolations-Regeln sie nie. Ein Container kann damit jeden Dienst
   erreichen, der auf dem Host auf `0.0.0.0` lauscht — Open WebUI, Datenbanken,
   den Proxy selbst. Dagegen hilft genau eine Sache, einmal pro Host:

   ```bash
   sudo scripts/sandbox-host-firewall.sh install 10.88.0.0/16
   ```

   Der Proxy prüft das von innen heraus — er startet einen Container, versucht
   von dort aus Internet und Host zu erreichen, und schreibt eine
   `ISOLATION:`-Zeile ins Log, wenn etwas antwortet. Standardmäßig passiert das
   beim ersten Nutzer; mit `OTPROXY_REQUIRE_ISOLATION=true` schon beim Start,
   und dann startet der Dienst gar nicht, wenn etwas erreichbar ist (und
   verweigert später jede Sandbox, falls die Prüfung kippt).
2. **Der Docker-Socket ist Host-Root.** Der Proxy muss Container starten, also
   braucht er den Socket, und wer den Socket hat, hat die Maschine. Ein
   „Socket-Proxy" ändert daran nichts, weil genau die Endpunkte gebraucht
   werden, die alles erlauben (`containers/create` mit Mounts). Realistische
   Gegenmittel: eigener Host bzw. eigene VM für diesen Dienst, oder rootless
   Docker / Podman-Socket. Der Proxy-Container selbst läuft unprivilegiert,
   read-only, ohne Capabilities und ohne veröffentlichten Port.

**Kaltstart: der erste Aufruf ist der langsame.** Open WebUI gibt `/files/cwd`
fünf Sekunden und `/api/config` drei. Ein Containerstart passt da nicht hinein.
Deshalb: `/openapi.json`, `/api/config` und `/system` beantwortet der Proxy aus
einem Cache ohne Container, und `OTPROXY_POOL_SIZE=1` hält einen Container
vorgewärmt (ohne jedes Netz, bis ihn jemand bekommt). Wie lange dein Image
wirklich braucht, steht nach jedem Start im Log: `sandbox ... ready after 3.4s`.

**Skalierung: automatisch nach oben und nach unten, auf einem Host.** Container
entstehen bei Bedarf, verschwinden nach `OTPROXY_IDLE_TIMEOUT` (900 s) und
spätestens nach `OTPROXY_MAX_LIFETIME` (24 h). Über `OTPROXY_MAX_SANDBOXES`
liegt eine harte Decke: ist sie erreicht, wird der am längsten untätige
Container geräumt — und wenn alle aktiv sind, antwortet der Proxy mit `503` und
`Retry-After` statt den Host zu überbuchen. Mehrere Proxy-Replicas auf **einem**
Docker-Host funktionieren (der Zustand liegt in den Containern, nicht im
Prozess). Über mehrere Hosts hinweg verteilt dieser Proxy nicht — dafür ist
Kubernetes zuständig, siehe „Grenzen".

**Es gibt das auch fertig, aber nicht frei.** Open WebUI bietet selbst einen
Orchestrator für genau diese Aufgabe (`open-webui/terminals`). Der steht unter
der **Open WebUI Enterprise License**: produktiver Einsatz verlangt eine
Lizenz. Dieser Proxy ist eine unabhängige Implementierung gegen die öffentliche
HTTP-Schnittstelle von Open Terminal (MIT) und die Header, die Open WebUI
schickt; aus dem Enterprise-Code ist nichts übernommen. Wenn du Kubernetes,
Terminal-Contexts, Policy-Verwaltung über API und Support brauchst, ist das
Original die ehrlichere Wahl.

---

## Aufsetzen

Voraussetzung ist ein Docker-Host: Engine plus Compose-Plugin. Auf einem
frischen Ubuntu, und ohne `snap` — das Snap-Paket hat einen anderen Socket-Pfad
und bricht bei Bind-Mounts und iptables-Netzen:

```bash
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker "$USER"     # danach neu einloggen
```

**1. Repo, Schlüssel, Einstellungen**

```bash
git clone https://github.com/59jz7vygqm-dot/openterminalproxy.git
cd openterminalproxy
cp .env.example .env
openssl rand -base64 36             # -> OTPROXY_API_KEY in .env
stat -c '%g' /var/run/docker.sock   # -> DOCKER_GID in .env
```

**2. Image vorab ziehen** — 4 GB, sonst wartet der erste Nutzer darauf

```bash
docker pull ghcr.io/open-webui/open-terminal:latest
```

**3. Starten**

```bash
docker compose up -d --build
```

Open WebUI läuft schon? Dann hänge es an das Netz `openterminal-frontend`.
Noch nicht? `--profile with-openwebui` startet es mit.

**4. Host-Regel setzen** (siehe oben, einmal pro Host, nach jedem Reboot)

```bash
sudo scripts/sandbox-host-firewall.sh install 10.88.0.0/16
sudo scripts/sandbox-host-firewall.sh status  10.88.0.0/16
```

**5. In Open WebUI eintragen**

* **Einstellungen → Admin → Integrationen → Open Terminal → +**
  (nicht die persönlichen Integrationen, nicht „External Tools")
* **URL**: `http://otproxy:8800` — bzw. `http://<host>:8800`, wenn Open WebUI
  auf einer anderen Maschine läuft
* **API Key**: der Wert aus `OTPROXY_API_KEY`
* **Auth Type**: `Bearer`
* Beim Modell **Function Calling** auf **Native** stellen, nicht „Legacy"
* Danach im Chat über das Wolken-Symbol unter **System** das Terminal wählen

Prüfen:

```bash
docker exec open-webui curl -s http://otproxy:8800/health
curl -s -H "Authorization: Bearer $OTPROXY_API_KEY" -H "X-User-Id: test-user" \
     -H 'Content-Type: application/json' \
     -d '{"command":"python3 -c \"print(6*7)\""}' \
     http://localhost:8800/execute?wait=20
```

Der zweite Aufruf startet einen echten Container für `test-user` — der erste
dauert entsprechend länger.

---

## Welches Image

| Image | Größe | Für | Nötige Einstellungen |
|---|---|---|---|
| `…/open-terminal:latest` | ~4 GB | Rechnen: python, numpy/pandas/scipy/sklearn, gcc, ffmpeg, LaTeX | Voreinstellung, inklusive `OTPROXY_CAP_ADD=SETGID` |
| `…/open-terminal:slim` | ~430 MB | Shell, git, curl, jq | `OTPROXY_SANDBOX_USER=1000:1000`, `OTPROXY_CAP_ADD=SETGID,SETUID` |
| `…/open-terminal:alpine` | ~230 MB | wie slim, musl | wie slim |

Zum `SETGID`: das große Image gibt seinem Server-Binary die File-Capability
`cap_setgid+ep`. Liegt diese Capability nicht im Bounding-Set des Containers,
**verweigert der Kernel das exec** — der Container stirbt mit
`exec …: operation not permitted`. Nachgemessen; deshalb ist `CAP_DROP=ALL` die
Voreinstellung und `SETGID` die eine Ausnahme. Für slim/alpine startet der
Entrypoint als root und wechselt selbst den Nutzer, was ohne `SETUID`/`SETGID`
nicht geht — mit `OTPROXY_SANDBOX_USER=1000:1000` läuft der Container direkt als
unprivilegierter Nutzer. Scheitert ein Start, steht im Log die Zeile des
Containers und ein Hinweis, welche Einstellung gemeint ist.

Das Image wird beim ersten Bedarf gezogen (`OTPROXY_PULL=missing`). Bei 4 GB
lohnt ein `docker pull` vorab, sonst wartet der erste Nutzer darauf.

---

## Einstellungen

Alles über Umgebungsvariablen, alles beim Start geprüft: ein unbrauchbarer Wert
beendet den Prozess mit einer Zeile, die die Variable nennt.

| Variable | Standard | Bedeutung |
|---|---|---|
| `OTPROXY_API_KEY` | — | **Pflicht.** Der Key, den Open WebUI schickt. Mindestens 16 Zeichen. |
| `OTPROXY_API_KEYS` | — | Weitere gültige Keys, kommagetrennt (Rotation). |
| `OTPROXY_ADMIN_KEY` | — | Key für `/api/v1/*` und `/metrics`. Leer = Admin-API aus. |
| `OTPROXY_IMAGE` | `…/open-terminal:latest` | Sandbox-Image. |
| `OTPROXY_PULL` | `missing` | `never`, `missing`, `always`. |
| `OTPROXY_SANDBOX_USER` | — | `User` des Containers, z. B. `1000:1000`. |
| `OTPROXY_MEMORY` | `2g` | RAM pro Nutzer, Swap wird gleich gesetzt (also keiner). |
| `OTPROXY_CPUS` | `1.0` | CPU-Kontingent pro Nutzer. |
| `OTPROXY_PIDS_LIMIT` | `512` | Prozesse pro Container (gegen Fork-Bomben). |
| `OTPROXY_NOFILE` / `OTPROXY_NPROC` | `4096` / `512` | ulimits im Container. |
| `OTPROXY_TMPFS_SIZE` | `512m` | Größe von `/tmp` (tmpfs, `nosuid,nodev`). |
| `OTPROXY_STORAGE_SIZE` | — | Quota für die Schreibschicht; braucht overlay2 auf XFS mit `pquota`. |
| `OTPROXY_CAP_DROP` / `OTPROXY_CAP_ADD` | `ALL` / `SETGID` | Capabilities, siehe oben. |
| `OTPROXY_NO_NEW_PRIVILEGES` | `true` | Macht das `sudo` im Image wirkungslos. |
| `OTPROXY_READ_ONLY_ROOTFS` | `false` | Read-only root; `/tmp`, `/run`, `/var/tmp` werden tmpfs. Verträgt sich nicht mit Paket-Installationen zur Laufzeit. |
| `OTPROXY_SECCOMP_PROFILE` | — | Pfad zu einem eigenen seccomp-Profil (JSON, im Proxy-Container lesbar). |
| `OTPROXY_APPARMOR_PROFILE` | — | Name eines AppArmor-Profils. |
| `OTPROXY_RUNTIME` | — | Alternative Runtime, z. B. `runsc` (gVisor). Deutlich stärkere Trennung als ein normaler Container. |
| `OTPROXY_SANDBOX_ENV` | `{}` | JSON mit zusätzlichen Variablen für den Container. |
| `OTPROXY_PERSIST_HOME` | `false` | `true` = `/home/user` liegt in einem Volume pro Nutzer und überlebt. |
| `OTPROXY_NETWORK_MODE` | `per-user` | `per-user` oder `shared` (schwächer, siehe oben). |
| `OTPROXY_NET_SUPERNET` | `10.88.0.0/16` | Bereich, aus dem die Sandbox-Netze kommen. |
| `OTPROXY_NET_PREFIX` | `29` | Blockgröße; `/16` + `/29` = 8192 gleichzeitige Netze. |
| `OTPROXY_MAX_SANDBOXES` | `50` | Harte Decke pro Host. |
| `OTPROXY_POOL_SIZE` | `1` | Vorgewärmte Container. |
| `OTPROXY_IDLE_TIMEOUT` | `900` | Sekunden Leerlauf bis zum Entfernen. |
| `OTPROXY_MAX_LIFETIME` | `86400` | Maximale Lebensdauer, `0` = unbegrenzt. |
| `OTPROXY_EVICT_MIN_IDLE` | `60` | Ab wann ein Container bei Platzmangel geräumt werden darf. |
| `OTPROXY_READY_TIMEOUT` | `90` | Wartezeit auf `/health` des Containers. |
| `OTPROXY_SCOPE_BY_CONTEXT` | `true` | `X-Terminal-Context-Id` (z. B. pro Chat) ergibt eine eigene Sandbox. |
| `OTPROXY_POLICIES` | `{}` | JSON mit benannten Profilen, erreichbar über `/p/<id>/…`. |
| `OTPROXY_MAX_BODY` | `1g` | Größte erlaubte Anfrage (Uploads). |
| `OTPROXY_REQUEST_TIMEOUT` | `300` | Obergrenze für eine weitergeleitete Anfrage. |
| `OTPROXY_VERIFY_ISOLATION` | `true` | Selbsttest von innen beim ersten Container. |
| `OTPROXY_REQUIRE_ISOLATION` | `false` | `true` = Start abbrechen, wenn der Selbsttest etwas erreicht. |
| `OTPROXY_REJECT_SANDBOX_CLIENTS` | `true` | Anfragen aus dem Sandbox-Bereich werden mit 403 abgewiesen. |
| `OTPROXY_STOP_ON_SHUTDOWN` | `false` | `true` = Container beim Beenden mitnehmen. Standard: laufen lassen, der nächste Start adoptiert sie. |
| `OTPROXY_LOG_LEVEL` / `OTPROXY_LOG_FORMAT` | `INFO` / `text` | `json` für Log-Sammler. |

### Policies

Open WebUI hängt bei einer Orchestrator-Verbindung mit Policy ein
`/p/<policy>/` vor jeden Pfad. Das wird unterstützt; die Profile stehen in der
Konfiguration, nicht in einer Laufzeit-API:

```bash
OTPROXY_POLICIES='{"ds":{"image":"ghcr.io/open-webui/open-terminal:latest","memory":"8g","cpus":4,"idle_timeout":1800}}'
```

Derselbe Nutzer bekommt pro Policy eine eigene Sandbox.

---

## Betrieb

```bash
# Was läuft gerade, und was hat der Selbsttest gesehen?
curl -s -H "Authorization: Bearer $OTPROXY_ADMIN_KEY" http://localhost:8800/api/v1/status

# Wer hat eine Sandbox, wie lange untätig?
curl -s -H "Authorization: Bearer $OTPROXY_ADMIN_KEY" http://localhost:8800/api/v1/terminals

# Eine Sandbox wegwerfen (der nächste Aufruf des Nutzers startet eine neue)
curl -X DELETE -H "Authorization: Bearer $OTPROXY_ADMIN_KEY" \
     http://localhost:8800/api/v1/terminals/<key>

# Prometheus
curl -s -H "Authorization: Bearer $OTPROXY_ADMIN_KEY" http://localhost:8800/metrics
```

Von außerhalb des Proxys, direkt am Daemon — das Label ist die Zugehörigkeit,
der Name sagt, was ein Container ist (`-c-` gehört einem Nutzer, `-w-` ist aus
dem Pool):

```bash
docker ps --filter 'label=sh.openterminal.proxy/owned=true' --format '{{.Names}}	{{.Status}}'
```

Nicht nach dem Label `role` filtern: Docker-Labels sind unveränderlich, also
trägt ein Container, der aus dem Pool an einen Nutzer gegangen ist, bis zum
Ende `role=warm`. Deshalb entscheidet auch die Adoption nach einem Neustart am
Namen und nicht am Label.

Die drei Pfade `api/v1/status`, `api/v1/terminals` und `api/v1/policies` sind
genau die, die Open WebUI selbst nicht weiterleitet — über eine Open-WebUI-
Sitzung sind sie also nicht erreichbar, auch wenn der Proxy sonst sichtbar ist.
Zusätzlich brauchen sie `OTPROXY_ADMIN_KEY`, und ohne diesen Schlüssel
antworten sie mit 404.

Im Log stehen Containerstarts, Übergaben aus dem Pool, Räumungen,
Kapazitätsgrenzen und die `ISOLATION:`-Zeilen. Schlüssel stehen nicht im Log —
weder der von Open WebUI noch die der Container.

---

## Was geschützt ist, und was nicht

Geschützt:

* kein Weg ins Internet oder ins lokale Netz aus der Sandbox heraus (Kernel-Route)
* kein Weg zum Container eines anderen Nutzers (eigenes Netz pro Nutzer)
* kein Weg zum Host, **sobald** die Firewall-Regel steht
* kein verwertbarer Schlüssel: jeder Container hat einen eigenen, zufälligen;
  der Key von Open WebUI erreicht nie einen Container
* keine Rechteausweitung im Container: `CAP_DROP=ALL`, `no-new-privileges`,
  damit ist auch das mitgelieferte `sudo` wirkungslos
* begrenzte Ressourcen: RAM ohne Swap, CPU-Kontingent, PID-Limit, ulimits,
  tmpfs mit Größe, gedeckeltes Container-Log, OOM-Killer bevorzugt die Sandbox
* kein veröffentlichter Port an einer Sandbox, kein Host-Mount, kein
  Docker-Socket in der Sandbox
* Anfragen aus dem Sandbox-Bereich an den Proxy werden abgewiesen

Nicht geschützt — bewusst benannt:

* **Docker-Socket = Host-Root.** Siehe oben. Der eigentliche Rest-Risiko-Punkt.
* **Container-Ausbruch über eine Kernel-Lücke.** Ein Container ist kein
  Hypervisor. Wenn das zählt: `OTPROXY_RUNTIME=runsc` (gVisor) oder eine eigene
  VM pro Mandant.
* **Was der Nutzer im Container tut, wird nicht aufgezeichnet.** Open Terminal
  loggt Prozesse im Container; eine revisionssichere Aufzeichnung ist das nicht.
* **Dateien des Nutzers.** Mit `PERSIST_HOME=false` ist nach dem Räumen alles
  weg — auch mitten in der Arbeit, wenn 15 Minuten nichts passiert. Mit `true`
  bleibt ein Volume pro Nutzer liegen, das niemand automatisch löscht.
* **Keine Quotas auf dem Home-Volume** außer über `OTPROXY_STORAGE_SIZE`, und
  das verlangt den passenden Storage-Treiber.
* **Open WebUI entscheidet, wer darf.** Der Proxy vertraut dem `X-User-Id` aus
  einer authentifizierten Open-WebUI-Verbindung. Wer den Bearer-Key hat, kann
  sich als beliebiger Nutzer ausgeben — der Key ist also so wertvoll wie jede
  Sandbox. Nicht nach außen veröffentlichen, keinen Port auf `0.0.0.0` öffnen.

---

## Verhältnis zum Enterprise-Orchestrator („Terminals")

**Im Prinzip dasselbe.** Open WebUI beschreibt seinen Orchestrator so: er sitzt
zwischen Open WebUI und den Arbeitsumgebungen pro Nutzer, Open WebUI leitet die
Anfrage an ihn weiter, er löst die Policy auf (Image, Ressourcen, Storage, Env,
Security-Context, Idle-Timeout), legt pro Nutzer — und bei entsprechender
Verbindung pro Chat oder Automation — eine Umgebung an oder verwendet eine
bestehende, **aller** Verkehr läuft über ihn, der Nutzer verbindet sich nie
direkt, Leerlauf wird aufgeräumt. Genau das macht dieser Proxy auch, bis hin
zum `X-User-Id`-Routing und dazu, dass die Werkzeugschnittstelle die
OpenAPI-Beschreibung des Images selbst ist.

**Im Umfang nicht.** Was unten über Terminals steht, stammt aus der
öffentlichen Dokumentation und dem README des Projekts — in den Enterprise-Code
habe ich nicht gesehen, und wo dort „nicht dokumentiert" steht, heißt das
genau das und nicht „fehlt".

| | Terminals (Enterprise) | dieser Proxy |
|---|---|---|
| Backends | Docker, Kubernetes, K8s-Operator mit CRDs, OpenShift | Docker, ein Host |
| Admin-Oberfläche | eingebaut unter `/` | keine; JSON-Status und Prometheus |
| Policies | REST-API, zur Laufzeit änderbar | Konfiguration (`OTPROXY_POLICIES`), Neustart nötig |
| Terminal Contexts | pro Chat/Automation, in Open WebUI konfigurierbar | Header wird ausgewertet, eigene Sandbox pro Kontext; keine eigene Verwaltung |
| Storage | PVC pro Nutzer mit Quota, geteilte Modi | ein Volume pro Nutzer, an/aus; Quota nur mit passendem Storage-Treiber |
| Geplante Resets | ja | nein, nur `MAX_LIFETIME` |
| Netz-Grenze | pro Policy, u. a. Domain-Allow-List über die Firewall *im* Container | internes Netz pro Nutzer, gar kein Egress, kein `NET_ADMIN` im Container |
| Sandbox → Host | in der Dokumentation nicht behandelt | gemessen; Skript dagegen plus Selbsttest im Log |
| Schlüssel pro Container | nicht dokumentiert | ja, zufällig erzeugt |
| Lizenz, Support | Enterprise-Lizenz nötig, Support inklusive | kein Support, 228 Prüfungen als Ersatz |

Kurz: brauchst du Kubernetes, eine Oberfläche, Policies zur Laufzeit, geplante
Resets oder jemanden, den du anrufen kannst — nimm das Original. Brauchst du
einen Host, keine Lizenzkosten und die härtere Netztrennung als Standard —
nimm das hier.

## Grenzen

* **Ein Docker-Host.** Mehrere Proxy-Prozesse am selben Daemon sind in Ordnung;
  mehrere Hosts nicht — es gibt kein Scheduling über Maschinen hinweg. Dafür
  gäbe es Kubernetes, und dann ist der Enterprise-Orchestrator der passendere
  Weg.
* **Netze als Obergrenze.** `/16` mit `/29` ergibt 8192 Netze; die praktische
  Grenze ist vorher der Host (eine Bridge pro aktivem Nutzer) und
  `MAX_SANDBOXES`.
* **Keine WebSocket-Terminals ohne Sitzung.** Der interaktive Shell-Tab braucht
  eine Sandbox, die schon läuft; der Proxy startet sie sonst und Open Terminal
  antwortet mit 4004, bis die Sitzung angelegt ist.
* **`X-Session-Id`/cwd** werden durchgereicht, aber im Container gehalten. Wird
  die Sandbox geräumt, ist das Arbeitsverzeichnis wieder `/home/user`.

---

## Tests

```bash
scripts/run_tests.sh
```

* `tests/test_units.py` — Konfiguration, Identitäten, Subnetz-Vergabe,
  Header-Filter, Container-Spezifikation. Kein Docker nötig.
* `tests/test_proxy.py` — der echte FastAPI-Dienst unter uvicorn gegen einen
  gefälschten Open Terminal: Authentifizierung, Schlüsseltausch, Routing pro
  Nutzer, Streaming, WebSocket, Kapazität, Räumung, Pool, Admin-API. Kein
  Docker nötig.
* `tests/test_docker.py` — gegen einen echten Daemon, mit einem winzigen
  selbstgebauten Image (`tests/fake_terminal.c`, statisch, ein paar hundert
  Zeilen C statt 4 GB). Prüft die Aussagen, die man nicht simulieren kann:
  kein Internet, kein Zugriff auf den Nachbarn, Host erreichbar **ohne** und
  unerreichbar **mit** Firewall-Regel, Hardening-Flags im Daemon, Übergabe aus
  dem Pool, Adoption nach Neustart, Räumung von Container und Netz. Ohne
  Daemon/gcc meldet er den Grund und ist zufrieden.

Zuletzt ausgeführt gegen Docker 29.9.2 (API 1.56), Python 3.13: 238 Prüfungen,
alle grün.
