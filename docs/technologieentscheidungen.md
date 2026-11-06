# Technologieentscheidungen – DMZ-Laborumgebung

Stand: 2026-11-06, Version 0.5.

Die Spalte „RAM geschätzt“ stammt aus der Planung. Gemessene Werte stehen bei den Entscheidungen (z. B. R-04, R-07) und am Ende jeder Testausgabe (Abschnitt „Resources“).

## Übersicht

| Knoten | Technik | Image | RAM geschätzt | Grenze |
|---|---|---|---|---|
| `fw-edge` | nftables, strongSwan, ulogd2, OpenSSH-Server für K-13 | `fw` | 10–25 MB | 64 MB |
| `fw-dmz` | nftables, ulogd2, Spiegelung mit tc | `fw` | 10–25 MB | 64 MB |
| `fw-backend` | nftables | `fw` | 5–15 MB | 64 MB |
| `router-int`, `inet` | Linux-Routing mit statischen Routen | `router` | je 5–10 MB | je 64 MB |
| `client1`, `attacker` | curl, socat, openssl | `client` | je 5–15 MB | je 64 MB |
| `ro-client1`, `ro-client2` | curl, strongSwan | `client` | je 5–15 MB | je 64 MB |
| `proxy` | Nginx | `proxy` | 10–30 MB | 64 MB |
| `waf` | Nginx, ModSecurity v3, OWASP CRS 4 | `waf` | 60–150 MB | 256 MB |
| `web` | Python, Flask, gunicorn, SQLite | `web` | 30–80 MB | 128 MB |
| `ids` | Suricata 8 | `ids` | 150–350 MB, gemessen 37 MB | 256 MB |
| `siem` | hält nur Adressen und Routen | `client` | gemessen 1 MB | 64 MB |
| `siem-collector` | Fluent Bit | `fluent/fluent-bit:5.1.5` | gemessen 13 MB | 64 MB |
| `siem-loki` | Loki | `grafana/loki:3.7.9` | gemessen 77–86 MB | 256 MB |
| `siem-grafana` | Grafana | `grafana/grafana:13.3.0` | gemessen 316–350 MB | 512 MB |
| `siem-responder` | Python, OpenSSH-Client | `responder` | gemessen 16 MB | 64 MB |
| Summe, 18 Container | | | gemessen ca. 540 MB | 2240 MB |

Verfügbar sind 3423 MB RAM (Messung vom 2026-10-07). Gemessen am 2026-11-04 mit `docker stats` und `free -m` im laufenden Betrieb: 2598 MB verfügbar, kein Swap genutzt.

## Images

| Image | Basis | Inhalt | Größe |
|---|---|---|---|
| `fw` | `alpine:3.24` | iproute2, nftables, ulogd, tcpdump, strongSwan, OpenSSH-Server, conntrack-tools | 27,1 MB |
| `router` | `alpine:3.24` | iproute2, tcpdump | 11,6 MB |
| `client` | `alpine:3.24` | iproute2, curl, tcpdump, strongSwan, socat, openssl | 24,2 MB |
| `proxy` | `nginx:1.28-alpine` | Nginx, selbst signiertes Zertifikat nach BSI TR-02102-2 | 70,4 MB |
| `waf` | `owasp/modsecurity-crs:4.30.0-nginx-alpine` | Nginx, ModSecurity v3, CRS 4.30, iproute2 | 110 MB |
| `web` | `python:3.12-alpine3.24` | Flask, gunicorn, eigene Anwendung | 58,2 MB |
| `ids` | `alpine:3.24` | Suricata 8.0.8, iproute2 | 87,2 MB |
| `responder` | `python:3.12-alpine3.24` | Responder, Befehl `respond`, OpenSSH-Client, su-exec. Teilt die Basisschichten mit `web`. | 52,6 MB |
| `fluent/fluent-bit:5.1.5`, `grafana/loki:3.7.9`, `grafana/grafana:13.3.0` | offiziell, unverändert | SIEM | nicht einzeln gemessen, alle Images zusammen 2,2 GB (`docker system df`, 2026-11-04) |
| Summe eigene Images | | | 373 MB |

Größen gemessen am 2026-11-02 mit `make images`, `fw`, `router` und `client` dabei noch auf `alpine:3.20`. Verfügbar sind 7,0 GB Disk. Neun Knoten teilen sich die drei kleinen Images `fw`, `router` und `client`.

## Entscheidungen

### E-01 Drei schlanke Images für die Netzknoten

- **Entscheidung:** Je ein Image für Firewalls (`fw`), Router (`router`) und Clients (`client`), alle auf `alpine:3.24`.
- **Begründung:** Jede Rolle bekommt nur die Werkzeuge, die sie braucht. Router enthalten keine Werkzeuge für Tests oder Angriffe, Firewalls kein curl oder socat. Das verkleinert die Angriffsfläche. Die Images bleiben klein, zusammen unter 50 MB.
- **Basis:** Alpine 3.24. Alpine 3.20 hat seit dem 2026-04-01 keine Unterstützung mehr und ist für den Betrieb nach dem Stand der Technik ungeeignet.
- **Alternative:** Ein gemeinsames Image `lab-net` für alle Netzknoten (Entwurf 0.1). Etwas weniger Pflege, aber jedes Werkzeug auf jedem Knoten.
- **Offen:** Werkzeuge des Angreifers. Festlegung mit den Angriffen in Phase 6.

### E-02 Firewalls mit nftables

- **Entscheidung:** nftables auf `fw-edge`, `fw-dmz`, `fw-backend`. Ein Regelwerk pro Firewall als Datei.
- **Begründung:** Standard im aktuellen Linux-Kernel, zustandsbehaftete Filterung und Adressumsetzung in einem Werkzeug, Regelwerk als lesbare Datei.
- **Alternativen:** iptables (Vorgänger, verteilt auf mehrere Werkzeuge). OPNsense oder pfSense (läuft nicht als Container).
- **Anforderungen:** SYS-01, SYS-06, NET-03, SEC-02.

### E-03 Statisches Routing ohne FRR

- **Entscheidung:** `router-int` und `inet` leiten mit dem Linux-Kernel und festen Routen weiter.
- **Begründung:** Die Topologie ist fest. Ein Routing-Protokoll hat keine Aufgabe.
- **Alternative:** FRR mit OSPF. Zusätzliches Image und ein weiterer Dienst pro Router. Zugleich eine weitere Angriffsfläche.
- **Abweichung:** Der Stack-Vorschlag des Projekts nennt FRR.
- **Anforderung:** NET-02.

### E-04 VPN mit IKEv2/IPsec (strongSwan)

- **Entscheidung:** IKEv2/IPsec mit strongSwan zwischen den beiden Clients des Remote Office und `fw-edge` (UDP 500, ESP). Verfahren nach BSI TR-02102-3: AES-256-GCM, PRF HMAC-SHA2-512, brainpoolP512r1, Authentisierung mit Zertifikaten aus einer eigenen Labor-PKI (`make pki`), kein Pre-Shared Key. Richtlinienbasiertes IPsec ohne Tunnel-Schnittstelle: Jeder Client erhält eine feste virtuelle Adresse (10.99.0.2, 10.99.0.3) und schickt nur 10.10.0.0/16 durch den Tunnel. Konfiguration: `configs/vpn/`.
- **Begründung:** BSI TR-02102-3 beschreibt IKEv2 und IPsec mit konkreten Verfahren und Mindestanforderungen. Damit lässt sich die Konfiguration nach dem Stand der Technik belegen und testen (N-00 bis N-10).
- **Ursprünglicher Plan:** WireGuard (UDP 51820). Verworfen, weil WireGuard fest Curve25519 und ChaCha20-Poly1305 nutzt. Beide stehen nicht in TR-02102-3, und die Verfahren lassen sich nicht anpassen. Test N-09 belegt, dass `fw-edge` genau diese Verfahren abweist.
- **Alternativen:** WireGuard (siehe oben). OpenVPN (eigenes Protokoll auf TLS-Basis, nicht in TR-02102-3).
- **Geprüft:** `test-vpn` (N-00 bis N-10), XFRM im Container (R-03), ohne Privilegien (H-01).
- **Anforderung:** NET-05.

### E-05 Reverse-Proxy mit Nginx

- **Entscheidung:** Nginx. Aufgaben: TLS beenden, Anfragen an die WAF weiterreichen, ursprüngliche Absenderadresse im Header mitgeben, Anfragerate begrenzen, HSTS setzen.
- **Grenze:** Browser beachten HSTS nicht für IP-Adressen. Ohne Namensdienst (E-12) wirkt der Header erst mit einem Domainnamen.
- **Begründung:** Kleines Image. Die WAF basiert ebenfalls auf Nginx, es bleibt bei einer Konfigurationssprache.
- **Alternativen:** HAProxy (gleichwertig, zweite Konfigurationssprache). Traefik, Caddy (auf wechselnde Dienste ausgelegt).
- **Anforderungen:** SYS-02, SEC-02.

### E-06 WAF mit ModSecurity und OWASP Core Rule Set

- **Entscheidung:** Image `owasp/modsecurity-crs` in der Variante `nginx-alpine`. Das Image enthält ModSecurity v3 und CRS 4 und lauscht auf Port 8080.
- **Konfiguration:** Paranoia-Stufe 1, Anomalie-Schwelle 5. Die echte Client-Adresse kommt aus `X-Real-IP`, aber nur vom `proxy` (`configs/waf/realip.conf`). Regel 920350 ist nur für die eigenen Adressen abgeschaltet (`configs/waf/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf`, siehe E-12).
- **Image:** Das eigene Image wechselt nur für `apk` auf root und danach mit `USER nginx` zurück wie das Upstream-Image. Containerlab führt die `exec`-Befehle für Adressen und Routen trotzdem als root aus. Nginx-Master und Worker laufen ohne root (H-02, WA-00). Bis Phase 4 blieb das Image auf `USER root`, das hat Phase 5 behoben.
- **Doppelte Angabe:** Die Real-IP-Einstellung steht zusätzlich als Umgebungsvariablen in der Topologie (`SET_REAL_IP_FROM`, `REAL_IP_HEADER`), die die Vorlage des Images auswertet. Die Werte sind gleich wie in `realip.conf`.
- **Begründung:** Fertiges, gepflegtes Image des CRS-Projekts. Der Regelsatz ist der verbreitete offene Standard. Die Empfindlichkeit ist über eine Stufe einstellbar.
- **Alternative:** Coraza. Jüngeres Projekt, kein vergleichbares fertiges Image mit Nginx.
- **Anforderungen:** SYS-04, SEC-02, SEC-03.

### E-07 Webserver und Webanwendung

- **Entscheidung:** Eigene kleine Anwendung in Python mit Flask, gunicorn und SQLite. Anmeldung, Suche, Datei-Abruf. Port 8080.
- **Betriebsart:** `APP_MODE` schaltet zwischen `vulnerable` (Standard, Ziel der Angriffe) und `secure` (parametrisierte Abfragen, Escaping der Ausgabe, Prüfung des Dateipfads, Content-Security-Policy). Umschalten mit `APP_MODE=secure make deploy`. So lässt sich in der Demo zeigen, was die WAF abfängt und was erst sicherer Code behebt.
- **Begründung:** Geringer Speicherbedarf. Der Code ist vollständig bekannt, jeder Angriff lässt sich erklären. Schwachstellen sind gezielt einbaubar, damit die WAF etwas abzuwehren hat.
- **Alternativen:** OWASP Juice Shop (mehrere hundert MB RAM, fremder Code). DVWA (zusätzliche Datenbank). Statische Seite (kein lohnendes Angriffsziel).
- **Anforderungen:** SYS-05, ATK-05, ATK-06.

### E-08 IDS mit Suricata und eigenen Regeln

- **Entscheidung:** Suricata am Spiegelport. Eigene Regeln, passend zu den Angriffen. Kein vollständiger fremder Regelsatz.
- **Regeln** (`configs/ids/local.rules`): 1000001 UNION SELECT im URI, 1000002 Pfad-Traversal, 1000003 Verbindungsaufbau aus der DMZ auf nicht freigegebenen Ports (V-12, auch mit ECN-Bits), 1000004 SQL-Injection mit OR-Vergleich im Formular, 1000005 `script`-Tag im URI, 1000006 bekannte Scanner im User-Agent, 1000007 Ausgabe von `id` aus der DMZ nach außen. 1000004 bis 1000007 kamen mit dem Review vom 2026-11-06 hinzu. P-5 reagiert nur auf 1000003 und 1000007 (`docs/reaktion.md`), neue Regeln ändern die Reaktion also nicht unbemerkt.
- **Begründung:** Verbreitetes offenes IDS mit Ausgabe als JSON. Eigene Regeln halten den Speicherbedarf klein und belegen das Verständnis.
- **Alternativen:** Snort 3 (kein gepflegtes kleines Image). Zeek (Protokollanalyse, keine Signaturen).
- **Geprüft:** Alpine 3.24 enthält Suricata 8.0.8 (Test I-00). Alpine 3.20 enthielt nur 7.0.7.
- **Spiegelung:** `tc` kopiert alle eingehenden Pakete von `fw-dmz` eth1 bis eth4 vor der Filterung nach eth6. Das IDS sieht damit auch Pakete, die `fw-dmz` verwirft (Test I-05).
- **Folge:** Anfragen, die die WAF durchlässt, sieht das IDS zweimal: auf dem Weg `proxy` → `waf` und auf dem Weg `waf` → `web`. Ein Alarm auf dem zweiten Weg (Quelle 10.10.10.6) zeigt, dass ein Angriff die WAF passiert hat. Das SIEM muss die Dopplung beim Zählen berücksichtigen.
- **Netze:** `HOME_NET` ist die DMZ 10.10.10.0/24 (`configs/ids/lab.yaml`, Abschnitt `vars`). Damit gilt für SID 1000003 auch ein Verbindungsaufbau aus der DMZ ins Client- oder Backend-Netz als Verbindung nach außen. Vorher galt der Standard von Suricata (alle privaten Netze). Weil `--include` gleichnamige Abschnitte vollständig ersetzt, enthält `lab.yaml` den ganzen Abschnitt `vars` aus Suricata 8.0.8.
- **Betrieb:** Seit Phase 5 überwacht ein Watchdog Suricata, die Logdateien sind auf 50 MB begrenzt (H-06). Seit dem Review läuft Suricata als Benutzer `suricata` nur mit `NET_ADMIN` und `NET_RAW` (H-02).
- **Anforderungen:** SYS-03, SEC-03, MON-01.

### E-09 SIEM mit Grafana und Loki

- **Entscheidung:** Fluent Bit nimmt die Meldungen an, Loki speichert und durchsucht sie, Grafana zeigt das Dashboard. Jeder Dienst läuft in einem eigenen Container mit unverändertem offiziellem Image. Alle SIEM-Container (Fluent Bit, Loki, Grafana, Responder) teilen sich das Netz des Knotens `siem` (`network-mode: container:siem`), wie die Container eines Pods in Kubernetes. `siem` selbst hält nur Adressen und Routen.
- **Begründung:** Passt in das Speicherbudget. Der Wazuh-Indexer verlangt mindestens 4 GB RAM und scheidet damit aus. Elasticsearch und Graylog liegen in derselben Größenordnung. Getrennte Container erlauben eine Speichergrenze je Dienst und brauchen keine Prozessverwaltung. Adressplan und Firewall-Regeln bleiben unverändert, weil alle Dienste unter 10.10.30.10 erreichbar sind und sich über `localhost` ansprechen.
- **Abweichung vom Entwurf:** Das gemeinsame Image `lab-siem` entfällt, damit auch Risiko R-02.
- **Härtung:** Loki lauscht nur auf `127.0.0.1` und ist von außerhalb von `siem` nicht erreichbar (Test S-01). Aufbewahrung 24 h (R-05). Grafana ohne Registrierung, ohne Verbindungen ins Internet. Seit Phase 5 mit erzeugtem Admin-Passwort und weiteren Maßnahmen (E-21, `docs/haertung.md`).
- **Grenze:** Grafana mit Loki ist eine Log-Plattform mit Abfragen und Dashboards, kein vollständiges SIEM. Es fehlen fertige Korrelationsregeln und Fallbearbeitung. Die Korrelation über das Feld `client` (E-14) ist ein einfacher Ersatz. Die Grenze gehört in das Fazit der Dokumentation.
- **Anforderungen:** SYS-07, MON-02, MON-03, MON-05.

### E-10 Meldeweg über Syslog

- **Entscheidung:** Die vier meldenden Systeme senden Syslog über UDP 5140 an `siem`, wo Fluent Bit die Meldungen annimmt. Die Wege je Quelle:

| Quelle | Weg |
|---|---|
| `waf` | Nginx sendet sein Fehlerprotokoll zusätzlich per Syslog, Stufe `info` (`configs/waf/siem.conf`). Fluent Bit verwirft Zeilen ohne „ModSecurity:“. |
| `ids` | Zweite eve-Ausgabe von Suricata mit `filetype: syslog`, nur Alarme, ohne Paketinhalt und Zusatzdaten. Im Container leitet `busybox syslogd -R` weiter. |
| `fw-edge`, `fw-dmz` | NFLOG und ulogd2 (E-11), ebenfalls über `busybox syslogd -R` |

- **Begründung:** Kein eigener Agent auf den meldenden Systemen. UDP puffert nicht, Fluent Bit gibt alle 0,2 s an Loki weiter. Gemessen vom Ereignis bis zur Auffindbarkeit in Loki: im Mittel 167 bis 314 ms, höchstens 650 ms (Tests S-02 bis S-05).
- **Grenze:** BusyBox verarbeitet höchstens 2048 Zeichen pro Meldung. Deshalb gehen Suricata-Alarme ohne Paketinhalt und Metadaten hinaus. Fluent Bit setzt `host` bei IDS, WAF und Firewalls über die Absenderadresse (`src_addr`), nicht über den Hostnamen in der Meldung. Ein Sensor kann sich so nicht als anderer ausgeben (E-22).
- **Grenze:** Syslog über UDP ist unverschlüsselt und nicht authentifiziert. `fw-backend` lässt nur die vier Absenderadressen zu (K-09 bis K-11).
- **Alternativen:** Fluent Bit auf jedem meldenden System (strukturierte Daten, vier zusätzliche Dienste). Promtail (seit dem 2. März 2026 abgekündigt). Grafana Alloy (Nachfolger, deutlich größer).
- **Anforderungen:** MON-02, MON-04.

### E-11 Firewall-Meldungen über NFLOG und ulogd2

- **Entscheidung:** `fw-edge` und `fw-dmz` protokollieren verworfene Pakete mit `log prefix "<firewall> <kette> drop: " group 1 queue-threshold 1`, gedrosselt auf 20 Meldungen pro Sekunde mit 40 als Puffer. ulogd2 im selben Container nimmt die Einträge an und gibt sie als Text an den lokalen Syslog weiter (`configs/fw/ulogd.conf`).
- **Begründung:** Der Kernel verwirft gewöhnliche Log-Einträge aus Containern. NFLOG ist davon nicht betroffen. Die Drosselung verhindert, dass ein Angreifer mit einem schnellen Scan das SIEM flutet. Ein Scan bleibt mit 20 Meldungen pro Sekunde deutlich erkennbar.
- **Gemessen:** Ohne `queue-threshold 1` sammelt der Kernel bis zu 100 Meldungen oder 1 s, bevor er sie weitergibt. Die Meldungen brauchten dann 1,1 bis 1,2 s. Mit `queue-threshold 1` liegen sie wie die übrigen Quellen bei etwa 0,2 s (Test S-05).
- **Abgrenzung:** `fw-backend` meldet nicht. Was aus dem Internet oder dem Client-Netz ins Backend will, verwirft bereits `fw-edge`.
- **Anforderung:** MON-02.

### E-12 Kein Namensdienst

- **Entscheidung:** Alle Systeme verwenden Adressen. Wo ein Name nötig ist, genügt ein Eintrag in der Hosts-Datei.
- **Begründung:** Spart einen Container und einen Dienst.
- **Folge:** Das TLS-Zertifikat des Proxys ist selbst signiert.
- **Folge:** Jede Anfrage trägt eine IP-Adresse im Host-Header. Die CRS-Regel 920350 würde deshalb bei jeder legitimen Anfrage anschlagen und das SIEM mit Fehlalarmen füllen. Sie ist nur für die beiden eigenen Adressen abgeschaltet, fremde IP-Adressen im Host-Header meldet die WAF weiterhin (Test WA-05).

### E-13 Feste Containerlab-Version

- **Entscheidung:** `scripts/install.sh` installiert Containerlab 0.82.0. Eine andere Version lässt sich mit `CLAB_VERSION` setzen.
- **Begründung:** Die Installation ist wiederholbar und verhält sich auf der Labor-VM wie auf den Entwicklungs-VMs.

### E-14 Normalisierung im Collector

- **Entscheidung:** Fluent Bit zerlegt die Meldungen beim Eingang in Felder (`configs/siem/fluent-bit.yaml`): Suricata-Alarme als JSON, WAF und Firewalls über die regulären Ausdrücke `waf-deny`, `waf-warn` und `fw-drop`. Die Herkunft heißt bei allen Sensoren `client`: bei der WAF die echte Client-Adresse, beim IDS `xff` nur für Alarme hinter dem Proxy (Absender `proxy` oder `waf`, dort setzt der Proxy den Header selbst), sonst `src_ip`, bei den Firewalls die Quelladresse. Seit 2026-11-05: Vorher übernahm der Collector `xff` auch vor dem Proxy, ein Angreifer konnte auf TCP 80 so eine fremde Adresse als Quelle angeben (RE-09). Suricata 8 legt `xff` bei Alarmen in das Objekt `alert`. Der Filter `nest` hebt dieses Objekt auf die oberste Ebene (`alert_xff`, `alert_signature_id`, …), das sind dieselben Namen, die Loki beim Zerlegen erzeugt. Der Ausdruck `fw-drop` erlaubt seit der neueren ulogd-Version aus Alpine 3.24 mehrere Leerzeichen nach dem Präfix. Die Originalmeldung bleibt erhalten.
- **Begründung:** Ein einheitliches Feld macht die Korrelation über Sensoren hinweg zu einer einfachen Abfrage („Top-Quellen“). Die Dashboard-Abfragen bleiben kurz und lesbar.
- **Geprüft:** Die Ausdrücke wurden an allen echten Meldungen eines Testlaufs geprüft. Die Tests S-03 bis S-05 prüfen die Felder bei jedem Lauf.

### E-15 Zugang des Operators über ein Out-of-Band-Netz

- **Entscheidung:** Nur `siem` erhält ein Management-Netz (`network-mode: bridge`). Docker gibt Port 3000 nur auf 127.0.0.1 der VM frei, von anderen Rechnern führt ein SSH-Tunnel dorthin. `configs/siem/mgmt-routing.sh` leitet eigenen Verkehr von `siem` über `fw-backend` und schickt Antworten an den Browser über `eth0` zurück. Ein nftables-Filter auf `eth0` lässt nur TCP 3000 hinein und nur Antworten hinaus, `siem` leitet nicht weiter (`ip_forward` 0). IPv6 ist auf `eth0` abgeschaltet.
- **Seit dem Review vom 2026-11-06:** Vorher war Grafana auf allen Schnittstellen der VM erreichbar, und jeder Verkehr mit der Adresse von `eth0` ging dort hinaus, nicht nur Antworten (Test S-01).
- **Begründung:** Ein eigenes Netz für den Operator entspricht dem Out-of-Band-Management echter SOCs. Es führt in keine Zone. Das SIEM erhält darüber keinen Internetzugang am Firewall-Konzept vorbei (V-08).
- **Alternative:** Leitung von `siem` in die VM über einen `host:`-Endpunkt von Containerlab. Die Adresse auf der VM-Seite müsste bei jedem Start mit `sudo` gesetzt werden, ohne Vorteil.
- **Anforderung:** MON-03 (K-12).

### E-16 Dashboard und Anzeige innerhalb von 1 s

- **Entscheidung:** Das Dashboard „SOC – DMZ“ (`configs/siem/dashboards/soc.json`) wird beim Start geladen, ist die Startseite von Grafana und aktualisiert sich jede Sekunde. Inhalt: Zähler je Sensor, Alarm-Stream mit einer lesbaren Zeile je Ereignis, Top-Quellen über alle Sensoren, Verlauf je Sensor, Angriffsarten der WAF, Signaturen des IDS, Zielports und Regelketten der Firewalls, angegriffene Pfade.
- **Begründung:** Die Anzeige setzt sich zusammen aus Transport bis Grafana (S-07, gemessen über dieselbe Abfrage-Schnittstelle, die die Panels nutzen) und der Wartezeit bis zur nächsten Aktualisierung (im Mittel 0,5 s, höchstens 1 s). Im Mittel liegt sie damit unter 1 s, im ungünstigsten Fall darüber. Für die garantierte Vorgabe verlinkt das Dashboard dieselbe Alarm-Abfrage in Explore. Dort schiebt Grafana neue Meldungen im Modus „Live“ ohne Abfrage-Intervall nach.
- **Geprüft:** Alle Abfragen des Dashboards wurden gegen Loki 3.7.9 ausgeführt. Test S-06 prüft Dashboard, Startseite und Alarm-Stream, S-07 die Zeit bis zur Sichtbarkeit in Grafana.
- **Anforderungen:** MON-03, MON-05.

### E-17 Reaktive Maßnahmen über einen Responder im SIEM

- **Entscheidung:** Ein eigener Container `siem-responder` im Netz von `siem` erhält von Fluent Bit jedes normalisierte Ereignis (TCP 5170, nur lokal). Er wertet es gegen die Playbooks P-1 bis P-5 aus `configs/response/playbook.json` aus und setzt Sperren und Quarantänen an `fw-edge`. Jede Aktion meldet er per Syslog an das SIEM. Der Operator steuert ihn mit `respond` (`make response-status`, `block`, `release`, `response-mode`). Konzept, Playbooks und Ablauf bei einem Vorfall: `docs/reaktion.md`.
- **Begründung:** Die Entscheidung fällt dort, wo alle Sensoren zusammenlaufen. So kann eine Regel Ereignisse verschiedener Sensoren nutzen, etwa „IDS-Alarm hinter der WAF“ (P-2). Fluent Bit gibt die Ereignisse ohne Umweg über Loki weiter, das hält die Reaktion unter 1 s. Ein eigener Container hält die offiziellen SIEM-Images unverändert (E-09).
- **Alternativen:** Grafana-Alerting mit Webhook (Auswertung frühestens alle 10 s). fail2ban auf jeder Firewall (sieht nur die eigenen Meldungen, keine Korrelation). Suricata im IPS-Modus (nur ein Sensor, und das IDS hängt am Spiegelport, nicht im Datenweg).
- **Anforderungen:** SEC-04, A-06, A-07.

### E-18 Kanal K-13 über SSH mit Forced Command

- **Entscheidung:** Der Responder hält eine SSH-Sitzung zu `fw-edge` 10.10.0.9. `sshd` lauscht nur dort, nimmt nur `root@10.10.30.10` mit einem ECDSA-P-384-Schlüssel an und startet für jede Sitzung `configs/response/fw-response.sh`. Verfahren nach BSI TR-02102-4: `ecdh-sha2-nistp384`, `ecdsa-sha2-nistp384`, AES-256-GCM.
- **Begründung:** Verschlüsselt und gegenseitig authentisiert, ohne eigenen Code für die Authentisierung. Die Firewall prüft jede Zeile selbst und verweigert geschützte Adressen. Ein kompromittiertes SIEM erhält damit keine Shell und kann DMZ und Backend nicht sperren. Die stehende Sitzung spart den Verbindungsaufbau bei jeder Sperre.
- **Alternativen:** Abruf einer Sperrliste durch die Firewall (kein lauschender Dienst, aber Verzögerung um das Abrufintervall). Eigene HTTP-Schnittstelle (mehr eigener Code auf der Firewall).
- **Geprüft:** RE-01 und RE-02.

### E-19 Anti-Spoofing auf `fw-edge`

- **Entscheidung:** Kette `prerouting` mit Priorität `raw` in `table inet filter`. Jede Schnittstelle nimmt nur Absender aus ihrem Netz an. Aus dem Internet kommen keine internen, privaten oder reservierten Absender und nicht die eigene öffentliche Adresse, außer entschlüsselt aus dem VPN-Tunnel (`meta ipsec`). Verworfene Pakete meldet `fw-edge` gedrosselt als `spoof drop`.
- **Begründung:** Automatische Sperren dürfen nur auf echten Absendern beruhen. Sonst sperrt ein Angreifer mit gefälschten Paketen einen internen Client oder die VPN-Gegenstellen. Explizite Regeln je Schnittstelle statt `fib`, damit das Regelwerk ohne weiteres Kernelmodul lädt und im Bericht lesbar bleibt.
- **Geprüft:** RE-10.
- **Seit dem Review vom 2026-11-06 auch auf `fw-dmz`:** Jede DMZ-Adresse ist an ihren Port gebunden, am Transit-Port kommen keine DMZ-Absender an, am Spiegelport nichts (H-11).

### E-20 Beweissicherung und Wiederherstellung als Skripte

- **Entscheidung:** `scripts/collect-evidence.sh` (`make evidence`) sichert Ereignisse, Zustände, Logs und Container-Änderungen mit Prüfsummen. `scripts/recover.sh` (`make recover`) sichert Beweise, setzt alle Systeme aus den Images neu auf und trägt die Sperren wieder ein.
- **Begründung:** Die Vorlesung verlangt nach der Eindämmung Beweissicherung und die Wiederherstellung des sicheren Betriebs nach festgelegten Abläufen. Skripte machen den Ablauf wiederholbar und verhindern, dass Beweise beim Neuaufbau verloren gehen.

### E-21 Härtung nach dem Prinzip der minimalen Rechte

- **Entscheidung:** Firewalls, Router, DMZ-Server und SIEM-Dienste laufen nicht mehr privilegiert, sondern mit genau den nötigen Zusatzrechten (`NET_ADMIN`, `NET_RAW` ist ohnehin Docker-Standard) und `no-new-privileges`, gebündelt über die Gruppen `router`, `dmz` und `siem` in der Topologie. Dazu Kernel-Einstellungen gegen Redirects und Source-Routing, Spiegelports ohne IPv6-Adresse, Output-Ketten mit `policy drop` auf den Firewalls, Watchdog und Logbegrenzung für Suricata, Zeitlimits im Proxy, erzeugtes Grafana-Passwort, Docker-Loglimits auf dem Host. Einzelheiten und Tests: `docs/haertung.md`.
- **Begründung:** Containerlab startet Knoten standardmäßig privilegiert. Damit wäre jede Codeausführung in einem DMZ-Server ein Zugriff auf den Host. Minimale Rechte begrenzen den Schaden eines erfolgreichen Angriffs (Defense in Depth hinter WAF und Firewall).
- **Alternativen:** Schreibgeschütztes Dateisystem und `cap-drop` (von Containerlab nicht angeboten). Adressen von außen über einen Hilfscontainer setzen, damit die DMZ-Server ohne `NET_ADMIN` auskommen (Containerlab sieht das nicht vor, Ablauf würde unübersichtlich). User-Namespace-Remapping für Docker (Umstellung des Hosts).
- **Geprüft:** `make test-hardening`, H-01 bis H-11. Vorab: Regelwerke mit nftables, Proxy-Konfiguration und Slowloris mit Nginx 1.28.
- **Nachtrag aus dem Review vom 2026-11-06:** Suricata ohne root, Firewalls laden das Regelwerk vor den Adressen und schließen bei einem Fehler (H-10), Anti-Spoofing auf `fw-dmz` (H-11), Management-Zugang des SIEM gefiltert (E-15).
- **Anforderungen:** Aufgabenstellung „gehärtet … Wirksamkeit überprüft“, Phase 5. Eine ID in der Anforderungsliste nachtragen.

### E-22 Bindung der Sensoren an ihre Absenderadresse

- **Entscheidung:** Der Responder nimmt Meldungen eines Sensortyps nur von dessen Adresse an: `ulogd` von `fw-edge` und `fw-dmz`, `suricata` von `ids`, `modsecurity` von `waf` (`sensors` in `configs/response/playbook.json`). Die Adresse liefert Fluent Bit im Feld `src_addr`. Fremde Meldungen zählt der Responder als `rejected` und meldet sie gedrosselt.
- **Begründung:** Alle Sensoren senden an denselben UDP-Eingang. Ohne Bindung könnte ein kompromittierter Sensor, etwa die WAF, Firewall-Meldungen über Seitwärtsbewegungen von `client1` schicken und damit eine unbefristete Quarantäne auslösen. Die Absenderadresse ist belastbar, weil `fw-dmz` und `fw-edge` gefälschte Absender verwerfen (E-19).
- **Alternativen:** Ein eigener Eingang je Sensor (vier Ports, mehr Regeln auf drei Firewalls). Signierte Meldungen (eigener Agent auf jedem Sensor).
- **Geprüft:** RE-15, H-11.

## Risiken und Prüfungen

| Nr. | Risiko | Prüfung |
|---|---|---|
| R-01 | Die Anzeige im Dashboard dauert länger als 1 s. | Transport bis Loki gemessen 50 bis 650 ms (S-02 bis S-05), bis Grafana S-07. Mit 1 s Aktualisierung im Mittel unter 1 s, im ungünstigsten Fall darüber. Live-Ansicht für die garantierte Vorgabe (E-16). |
| R-02 | Das gemeinsame Image `lab-siem` mit drei Diensten lässt sich nicht sauber bauen. | Entfällt: drei Container mit offiziellen Images (E-09). |
| R-03 | nftables, tc und XFRM (IPsec) brauchen erweiterte Rechte im Container. | Erledigt: Test R-03 in `test-topology` bestanden, seit Phase 5 mit `NET_ADMIN` statt Privilegien (H-01). |
| R-04 | Suricata belegt mehr RAM als geschätzt. | Erledigt: gemessen 37 MB, Grenze auf 256 MB gesenkt. |
| R-05 | Logs füllen die Disk. | Loki speichert 24 h. Suricata-Logs über 50 MB werden geleert (H-06), Docker-Logs je Container höchstens 3 × 10 MB (H-07). |
| R-06 | Der Bau der Images bricht über ein VPN ab (`I/O error` bei `apk`), weil das VPN die MTU verkleinert. | Images ohne VPN bauen oder die MTU von Docker anpassen. Vor dem Labortermin alle Images bauen. Hinweis im README. |
| R-07 | Grafana erreicht seine Speichergrenze und wird vom Kernel beendet. | Gemessen bis 349 MB, Grenze von 384 auf 512 MB erhöht. Test S-00 prüft auf Abbruch wegen Speichermangel. |
| R-08 | Die Disk der VM wird knapp: 1,9 GB frei (2026-11-04). | Nicht benötigte Images löschen, Build-Cache leeren, vor dem Labortermin messen. Das Image `responder` teilt die Basis mit `web`. |
| R-09 | Die automatische Sperre trifft Unbeteiligte (gefälschte Absender, gefälschter `X-Forwarded-For`, Fehlalarme, gefälschte Sensoren). | Anti-Spoofing (E-19), `xff` nur hinter dem Proxy (E-14), Sensorbindung (E-22), Schutzliste dreifach, Schwellen, Ablaufzeiten, Beobachtungsmodus. Tests RE-02, RE-09, RE-10, RE-11, RE-15. Restrisiko: P-3 lässt sich mit gefälschten öffentlichen Absendern auslösen (`docs/reaktion.md`, Grenzen). |
| R-10 | Ein kompromittiertes SIEM missbraucht K-13. | Forced Command, Prüfung auf der Firewall, Schutzliste im Regelwerk (E-18). Restrisiko: Sperre nicht geschützter Adressen. |
| R-11 | Der Responder fällt aus. | Sperren bleiben auf `fw-edge` und laufen dort ab. Herzschlag im Dashboard. Test RE-13. |
| R-12 | Die Angriffe der Schicht-Tests sperren den Angreifer für die folgenden Tests aus. | `tests/lib-response.sh` schaltet für diese Tests in den Beobachtungsmodus und hebt Sperren vorher und nachher auf. |

## Quellen

- Grafana Labs: Promtail, Hinweis zum Supportende. https://grafana.com/docs/loki/latest/clients/promtail/
- Wazuh: Installationsanleitung Wazuh-Indexer, Hardwareanforderungen. https://documentation.wazuh.com/current/installation-guide/wazuh-indexer/
- Fluent Bit: Syslog-Eingang. https://docs.fluentbit.io/manual/5.0/data-pipeline/inputs/syslog
- OISF: Suricata, Eve JSON Output. https://docs.suricata.io/en/suricata-7.0.13/output/eve/eve-json-output.html
- OWASP CRS-Projekt: modsecurity-crs-docker. https://github.com/coreruleset/modsecurity-crs-docker
- Linux-Kernel: netfilter, allow logging from non-init namespaces. https://lkml.iu.edu/hypermail/linux/kernel/1701.3/05214.html
- BSI: TR-02102-4, Verwendung von Secure Shell (SSH). https://www.bsi.bund.de/DE/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/Technische-Richtlinien/TR-nach-Thema-sortiert/tr02102/tr02102_node.html
- OpenSSH: sshd_config(5). https://man.openbsd.org/sshd_config
- nftables Wiki: Sets. https://wiki.nftables.org/wiki-nftables/index.php/Sets
