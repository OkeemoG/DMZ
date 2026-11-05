# DMZ-Laborumgebung

Programmentwurf „Aufbau einer DMZ“, Sichere Unternehmensnetzwerke (SUN), DHBW. Die Aufgabenstellung steht in [`docs/aufgabenstellung.md`](docs/aufgabenstellung.md).

Die gesamte Umgebung läuft als 18 Docker-Container in einer VM und wird mit Containerlab aufgebaut. Die Knoten haben kein Management-Netz. Jeder Verkehr läuft über die nachgebildeten Leitungen und damit durch die Firewalls.

## Aufbau

```
          attacker          ro-client1      ro-client2
        192.0.2.10        198.51.100.2    198.51.100.6
               \                |               /
                +------------ inet ------------+            Internet
                                |
                             fw-edge                         Edge-Firewall, NAT
                  /             |              \
              fw-dmz        router-int       fw-backend
         /    |    |    \       |                |
     proxy   waf  web   ids   client1          siem
     .10.2  .10.6 .10.10 .10.14  10.10.20.10     10.10.30.10
     ---------- DMZ ----------  Client-Netz     Backend-Netz
```

| Knoten | Aufgabe | Stand |
|---|---|---|
| `inet` | Router, bildet das Internet nach | umgesetzt |
| `attacker` | Angreifer im Internet | umgesetzt |
| `ro-client1`, `ro-client2` | Remote Office, VPN-Client (IKEv2/IPsec mit strongSwan nach BSI TR-02102-3) | umgesetzt |
| `fw-edge` | Edge-Firewall zwischen Internet und Firmennetz, NAT, VPN-Endpunkt | umgesetzt |
| `fw-dmz` | Firewall der DMZ, Spiegelport zum IDS | umgesetzt |
| `proxy` | Reverse-Proxy, beendet TLS 1.3 nach BSI TR-02102-2, Ratenbegrenzung, HSTS | umgesetzt |
| `waf` | ModSecurity v3 mit OWASP CRS 4 | umgesetzt |
| `web` | Webanwendung (Flask), verwundbar oder sicher umschaltbar | umgesetzt |
| `ids` | Suricata 8 am Spiegelport von `fw-dmz` | umgesetzt |
| `router-int` | Router zum Client-Netz | umgesetzt |
| `client1` | interner Client | umgesetzt |
| `fw-backend` | Firewall des Backend-Netzes, lässt nur Meldungen an das SIEM durch | umgesetzt |
| `siem` | SIEM im Backend: hält Adresse und Routen, einziger Knoten mit Management-Zugang | umgesetzt |
| `siem-collector`, `siem-loki`, `siem-grafana` | Fluent Bit, Loki und Grafana im Netz von `siem` | umgesetzt |
| `siem-responder` | Automatische Reaktion: wertet die Ereignisse aus und sperrt Angreifer an `fw-edge` | umgesetzt |

Weg einer Anfrage aus dem Internet: `attacker` → `inet` → `fw-edge` (NAT auf 10.10.10.2) → `fw-dmz` → `proxy` → `fw-dmz` → `waf` → `fw-dmz` → `web`.

Weg einer Meldung: `waf`, `ids`, `fw-dmz`, `fw-edge` → Syslog über UDP 5140 → `fw-backend` → Fluent Bit → Loki → Grafana. Gemessen dauert das 50 bis 650 ms.

Weg einer Reaktion: Fluent Bit → `siem-responder` → SSH über `fw-backend` (K-13) → `fw-edge` sperrt die Adresse. Details in [`docs/reaktion.md`](docs/reaktion.md).

Planung und Begründungen: [`docs/adressplan.md`](docs/adressplan.md), [`docs/kommunikationsmatrix.md`](docs/kommunikationsmatrix.md), [`docs/technologieentscheidungen.md`](docs/technologieentscheidungen.md), [`docs/projektplan.md`](docs/projektplan.md).

## Voraussetzungen

| Punkt | Wert |
|---|---|
| VM | 2 vCPU, 4 GB RAM, 10 GB Disk |
| Betriebssystem | Debian mit `sudo`, `curl` und Internetzugang |
| Benutzer | Benutzer mit `sudo`-Rechten |
| Netz | Internetzugang ohne VPN für den Bau der Images (siehe Fehlerquellen) |

## Installation

```
git clone <Repo-URL> DMZ
cd DMZ
bash scripts/install.sh
```

`install.sh` installiert `curl`, `make`, Docker und Containerlab 0.82.0 und nimmt den Benutzer in die Gruppen `docker` und `clab_admins` auf. Am Ende startet eine neue Anmeldung, damit die Gruppen gelten. Dabei fragt das System nach dem Passwort. Eine andere Containerlab-Version: `CLAB_VERSION=0.83.0 bash scripts/install.sh`.

Prüfen, ob Containerlab grundsätzlich läuft:

```
make test-basic
```

## Betrieb

| Befehl | Wirkung |
|---|---|
| `make images` | Baut alle Images |
| `make pki` | Erzeugt die Zertifikate und Schlüssel für das VPN in `configs/vpn/pki/` und die SSH-Schlüssel für K-13 in `configs/response/keys/`, falls noch nicht vorhanden |
| `make deploy` | Baut die Images, erzeugt bei Bedarf die PKI und startet die Topologie neu |
| `make destroy` | Stoppt die Topologie und räumt auf |
| `make test-all` | Führt alle Tests aus und meldet am Ende `ALL TESTS PASSED` oder die fehlgeschlagenen Tests |

Der Webserver läuft standardmäßig verwundbar, damit die Angriffe etwas zum Angreifen haben. Sicherer Modus:

```
APP_MODE=secure make deploy
```

## Reaktion

Der Responder im SIEM sperrt Angreifer automatisch an `fw-edge` (Playbooks P-1 bis P-5 in `configs/response/playbook.json`). Konzept, Schutz vor Fehlsperren und Ablauf bei einem Vorfall: [`docs/reaktion.md`](docs/reaktion.md).

| Befehl | Wirkung |
|---|---|
| `make response-status` | Modus, Kanal zu `fw-edge`, aktive Sperren und Quarantänen |
| `make response-mode MODE=monitor` | Nur melden, nicht sperren. `MODE=enforce` schaltet zurück. Start im Beobachtungsmodus: `RESPONDER_MODE=monitor make deploy` |
| `make block IP=192.0.2.50 TTL=600` | Adresse von Hand sperren |
| `make quarantine IP=10.10.20.10` | Internen Host isolieren, bis er freigegeben wird |
| `make release IP=…` | Sperre oder Quarantäne aufheben |
| `make evidence IP=… MINUTES=30` | Beweise sichern nach `evidence/`, mit SHA-256 |
| `make recover` | Beweise sichern, alle Systeme aus den Images neu aufsetzen (Anwendung sicher), Sperren wieder eintragen |

## SIEM und Dashboard

Grafana lauscht auf Port 3000 der VM.

| Zugriff von | Adresse |
|---|---|
| Browser in der VM | `http://localhost:3000` |
| Browser auf dem Host der VM (Bridge- oder Host-only-Netz) | `http://<IP der VM>:3000`, die IP zeigt `ip -4 -br addr` |
| Host bei NAT-Netz der VM | Portweiterleitung Host 3000 → Gast 3000 oder `ssh -L 3000:localhost:3000 <benutzer>@<VM>` |

Anmeldung mit `admin` und dem Passwort aus `GRAFANA_PASSWORD`, Standard `dmz-soc`. Ein anderes Passwort: `GRAFANA_PASSWORD=… make deploy`.

Nach der Anmeldung erscheint das Dashboard „SOC – DMZ“. Es aktualisiert sich jede Sekunde. Der Link „Alarm-Stream live“ oben öffnet dieselbe Alarm-Abfrage in Explore, dort oben rechts auf **Live** klicken.

Angriffe zum Ausprobieren:

```
docker exec clab-dmz-attacker sh -c 'for p in 21 22 23 3306; do socat -T1 /dev/null TCP:203.0.113.2:$p,connect-timeout=1; done'
docker exec clab-dmz-attacker curl -sk -G --data-urlencode "q=<script>alert(1)</script>" https://203.0.113.2/search
docker exec clab-dmz-attacker curl -sk "https://203.0.113.2/search?q=1%27%20UNION%20SELECT%20name%20FROM%20users--"
docker exec clab-dmz-client1 curl -sk -G --data-urlencode "file=../../etc/passwd" https://10.10.10.2/download
```

## Tests

| Befehl | Prüft |
|---|---|
| `make test-images` | Alle Images enthalten ihre Werkzeuge |
| `make test-topology` | Adressen, Routen, Nachbarn, Ende-zu-Ende-Verbindungen, Rechte im Container |
| `make test-matrix` | Jede erlaubte und verbotene Verbindung der Kommunikationsmatrix |
| `make test-proxy` | Kette bis zum Webserver, echte Client-Adresse, TLS nach BSI, HSTS, Ratenbegrenzung |
| `make test-waf` | Normale Anfragen kommen durch, Angriffe werden geblockt und protokolliert |
| `make test-ids` | Suricata, Spiegelport, Erkennung mit echter Client-Adresse |
| `make test-siem` | SIEM-Dienste, Zugang, Latenz bis zum SIEM, Meldungen von WAF, IDS und Firewalls mit Feldern, Dashboard |
| `make test-web` | Webanwendung in beiden Betriebsarten, eigene Container außerhalb der Topologie |
| `make test-vpn` | Tunnel und Verfahren nach BSI TR-02102-3, Zugriff über den Tunnel, Sperren, Abweisung unzulässiger Verfahren, PKI |
| `make test-response` | Automatische Reaktion: Kanal K-13 nach BSI TR-02102-4, Schutzliste, alle Playbooks, Reaktionszeit unter 1 s, Anti-Spoofing, Beobachtungsmodus, Ablauf, Neustart, Dashboard |
| `make test-attacks` | Die drei Angriffe A-1 bis A-3 mit Selbstprüfung (`attacks/README.md`) |

Alle Tests außer `test-images` und `test-web` setzen eine laufende Topologie voraus (`make deploy`). Die Tests der einzelnen Schichten schalten die automatische Reaktion für ihre Dauer in den Beobachtungsmodus und heben vorhandene Sperren auf, damit ihre Angriffe den Angreifer nicht für die folgenden Tests aussperren.

## Verzeichnisse

| Pfad | Inhalt |
|---|---|
| `topology/dmz.clab.yml` | Knoten, Images, Adressen, Routen, Leitungen, eingebundene Konfiguration |
| `images/` | Ein Dockerfile je Image, dazu der Code der Webanwendung |
| `configs/` | Konfiguration je Knoten: Firewall-Regeln, Proxy, WAF, IDS, VPN |
| `configs/vpn/pki/` | Labor-PKI des VPN, erzeugt von `make pki`, nicht im Repo |
| `configs/response/` | Playbooks, `fw-response` und `sshd` für K-13. `keys/` erzeugt `make pki`, nicht im Repo |
| `attacks/` | Angriffe A-1 bis A-3 |
| `evidence/` | Gesicherte Beweise von `make evidence`, nicht im Repo |
| `scripts/` | `install.sh`, `build-images.sh`, `gen-vpn-pki.sh`, `gen-response-keys.sh`, `collect-evidence.sh`, `recover.sh` |
| `tests/` | Ein Testskript je Thema |
| `docs/` | Aufgabenstellung, Planung, Netzpläne |
| `docs/quellen/` | BSI TR-02102-1, TR-02102-2 und TR-02102-3 |

## Fehlerquellen

| Meldung | Ursache | Lösung |
|---|---|---|
| `apk` meldet `I/O error` oder `no such package` beim Bau | Ein VPN verkleinert die MTU, große Downloads brechen ab | VPN trennen. Falls ein VPN nötig ist: `{ "mtu": 1400 }` in `/etc/docker/daemon.json`, dann `sudo systemctl restart docker` |
| `failed to extract … I/O error` | Disk voll | `df -h /` prüfen, `docker builder prune -af` und `docker image prune -f` |
| Tests schlagen nach `git pull` breit fehl, z. B. Suricata fehlt | Es läuft noch die alte Topologie | `make deploy` |
| `test-waf` oder `test-proxy` direkt nach dem Start fehlgeschlagen | WAF noch im Zustand `health: starting` | Die Tests warten bis 60 s. Danach `docker inspect clab-dmz-waf` prüfen |
| `permission denied` bei `docker` oder `containerlab` | Gruppen nach der Installation noch nicht aktiv | Neu anmelden |
| `containerlab deploy` meldet eine fehlende Datei unter `configs/vpn/pki` | PKI noch nicht erzeugt | `make pki` oder `make deploy` |
| `make` meldet `missing separator` | Befehle im Makefile mit Leerzeichen statt Tab eingerückt | Tab verwenden |
| Grafana im Browser nicht erreichbar | Netz der VM erlaubt keinen Zugriff vom Host | In der VM `curl -s http://localhost:3000/api/health` prüfen, dann Portweiterleitung oder SSH-Tunnel (siehe SIEM und Dashboard) |
| `test-siem` meldet „Loki ready“ oder „Grafana healthy“ als fehlgeschlagen | Loki braucht nach dem Start 15 s, Grafana beim ersten Start länger | Der Test wartet bis 60 bzw. 120 s. Danach `docker logs clab-dmz-siem-loki` bzw. `clab-dmz-siem-grafana` prüfen |
| Keine Meldungen im Dashboard | Ein Sensor meldet nicht oder Fluent Bit verwirft die Meldung | `docker logs clab-dmz-siem-collector`, danach in Explore `{job="dmz"}` ohne Filter |
| `containerlab deploy` meldet eine fehlende Datei unter `configs/response/keys` | SSH-Schlüssel für K-13 noch nicht erzeugt | `make pki` oder `make deploy` |
| `make response-status` zeigt `channel:  down` | `sshd` auf `fw-edge` läuft nicht oder die Schlüssel passen nicht zusammen | `docker logs clab-dmz-siem-responder`, `docker exec clab-dmz-fw-edge pgrep -fa sshd`. Nach neu erzeugten Schlüsseln `make deploy` |
| Angriffe oder Tests laufen ins Leere, Verbindungen vom `attacker` hängen | Der Angreifer ist noch von einem früheren Angriff gesperrt | `make response-status`, dann `make release IP=192.0.2.10`. Die Testskripte heben Sperren selbst auf |
| `test-response` RE-03 meldet mehr als 1000 ms | Last auf der VM, z. B. durch den Bau von Images | Test wiederholen, Messwert in `docs/reaktion.md` eintragen |
