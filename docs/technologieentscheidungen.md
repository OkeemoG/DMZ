# Technologieentscheidungen – DMZ-Laborumgebung

Stand: 2026-11-02, Version 0.2.

Alle Speicherwerte sind Schätzungen ohne Messung. Die Messung folgt mit dem Ressourcenbudget. Versionen werden in Phase 2 festgelegt.

## Übersicht

| Knoten | Technik | Image | RAM geschätzt | Grenze |
|---|---|---|---|---|
| `fw-edge` | nftables, WireGuard, ulogd2 | `fw` | 10–25 MB | 64 MB |
| `fw-dmz` | nftables, ulogd2, Spiegelung mit tc | `fw` | 10–25 MB | 64 MB |
| `fw-backend` | nftables | `fw` | 5–15 MB | 64 MB |
| `router-int`, `inet` | Linux-Routing mit statischen Routen | `router` | je 5–10 MB | je 64 MB |
| `client1`, `attacker` | curl, socat, openssl | `client` | je 5–15 MB | je 64 MB |
| `ro-client1`, `ro-client2` | curl, WireGuard | `client` | je 5–15 MB | je 64 MB |
| `proxy` | Nginx | `proxy` | 10–30 MB | 64 MB |
| `waf` | Nginx, ModSecurity v3, OWASP CRS 4 | `waf` | 60–150 MB | 256 MB |
| `web` | Python, Flask, gunicorn, SQLite | `web` | 30–80 MB | 128 MB |
| `ids` | Suricata 8 | `ids` | 150–350 MB, gemessen 37 MB | 512 MB |
| `siem` | Grafana, Loki, Fluent Bit (geplant) | `siem` (geplant) | 250–500 MB | 768 MB (geplant) |
| Summe, 14 Container | | | 555–1255 MB | 2304 MB |

Verfügbar sind 3423 MB RAM (Messung vom 2026-10-07). Gemessen am 2026-11-02 mit `docker stats` im laufenden Betrieb.

## Images

| Image | Basis | Inhalt | Größe |
|---|---|---|---|
| `fw` | `alpine:3.24` | iproute2, nftables, ulogd, tcpdump, wireguard-tools | 15,8 MB |
| `router` | `alpine:3.24` | iproute2, tcpdump | 11,6 MB |
| `client` | `alpine:3.24` | iproute2, curl, tcpdump, wireguard-tools, socat, openssl | 19,6 MB |
| `proxy` | `nginx:1.28-alpine` | Nginx, selbst signiertes Zertifikat nach BSI TR-02102-2 | 70,4 MB |
| `waf` | `owasp/modsecurity-crs:4.30.0-nginx-alpine` | Nginx, ModSecurity v3, CRS 4.30, iproute2 | 110 MB |
| `web` | `python:3.12-alpine3.24` | Flask, gunicorn, eigene Anwendung | 58,2 MB |
| `ids` | `alpine:3.24` | Suricata 8.0.8, iproute2 | 87,2 MB |
| `siem` | geplant | Grafana, Loki, Fluent Bit | 600–900 MB geschätzt |
| Summe ohne `siem` | | | 373 MB |

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

### E-04 VPN mit WireGuard

- **Entscheidung:** WireGuard zwischen den beiden Clients des Remote Office und `fw-edge`, UDP 51820. Jeder Client hat einen eigenen Schlüssel und einen eigenen Tunnel.
- **Begründung:** Im Linux-Kernel enthalten, kein eigener Dienst im Container, Konfiguration mit wenigen Zeilen.
- **Alternativen:** OpenVPN (eigener Dienst, Zertifikate). IPsec mit strongSwan (aufwendigste Konfiguration).
- **Geprüft:** Eine WireGuard-Schnittstelle lässt sich im Container anlegen (Test R-03). Auf der Labor-VM der DHBW noch zu prüfen.
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
- **Abweichung:** Das eigene Image setzt `USER root`. Containerlab führt die `exec`-Befehle für Adressen und Routen mit dem Standardbenutzer des Images aus, und dafür braucht es Root. Die Nginx-Worker, die die Anfragen bearbeiten, laufen ohne Root (Test WA-00).
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
- **Begründung:** Verbreitetes offenes IDS mit Ausgabe als JSON. Eigene Regeln halten den Speicherbedarf klein und belegen das Verständnis.
- **Alternativen:** Snort 3 (kein gepflegtes kleines Image). Zeek (Protokollanalyse, keine Signaturen).
- **Geprüft:** Alpine 3.24 enthält Suricata 8.0.8 (Test I-00). Alpine 3.20 enthielt nur 7.0.7.
- **Spiegelung:** `tc` kopiert alle eingehenden Pakete von `fw-dmz` eth1 bis eth4 vor der Filterung nach eth6. Das IDS sieht damit auch Pakete, die `fw-dmz` verwirft (Test I-05).
- **Folge:** Anfragen, die die WAF durchlässt, sieht das IDS zweimal: auf dem Weg `proxy` → `waf` und auf dem Weg `waf` → `web`. Ein Alarm auf dem zweiten Weg (Quelle 10.10.10.6) zeigt, dass ein Angriff die WAF passiert hat. Das SIEM muss die Dopplung beim Zählen berücksichtigen.
- **Grenze:** Suricata läuft ohne Überwachung (`-D`) und `eve.json` wächst ohne Begrenzung. Beides wird mit dem Meldeweg in Phase 4 gelöst.
- **Anforderungen:** SYS-03, SEC-03, MON-01.

### E-09 SIEM mit Grafana und Loki

- **Entscheidung:** Loki speichert und durchsucht die Meldungen. Grafana zeigt Dashboards und Alarme. Beides läuft im Knoten `siem`.
- **Begründung:** Passt in das Speicherbudget. Der Wazuh-Indexer verlangt mindestens 4 GB RAM und scheidet damit aus. Elasticsearch und Graylog liegen in derselben Größenordnung.
- **Grenze:** Grafana mit Loki ist eine Log-Plattform mit Alarmregeln, kein vollständiges SIEM. Es fehlen fertige Korrelationsregeln und Fallbearbeitung. Die Grenze gehört in das Fazit der Dokumentation.
- **Alternative im Aufbau:** Drei getrennte Knoten für Grafana, Loki und Sammler. Unveränderte offizielle Images, dafür ein größerer Adressplan und mehr Firewall-Regeln.
- **Anforderungen:** SYS-07, MON-02, MON-03, MON-05.

### E-10 Meldeweg über Syslog

- **Entscheidung:** Die vier meldenden Systeme senden Syslog über UDP 5140 an `siem`. Dort nimmt Fluent Bit die Meldungen an und übergibt sie an Loki.
- **Begründung:** Kein Agent auf den meldenden Systemen. Nginx sendet Syslog selbst (`error_log syslog:server=…`). Suricata schreibt nur in den lokalen Syslog, für die Weiterleitung braucht es im Container einen Weiterleiter, z. B. `busybox syslogd -R` (ungeprüft, Phase 4). UDP puffert nicht, das hilft bei der Vorgabe von 1 s.
- **Alternativen:** Fluent Bit auf jedem meldenden System (strukturierte Daten, vier zusätzliche Dienste). Promtail (seit dem 2. März 2026 abgekündigt). Grafana Alloy (Nachfolger, deutlich größer).
- **Grenze:** Syslog über UDP ist unverschlüsselt und nicht authentifiziert. Die Firewalls lassen nur die vier Absenderadressen zu.
- **Anforderungen:** MON-02, MON-04.

### E-11 Firewall-Meldungen über NFLOG und ulogd2

- **Entscheidung:** Die Regelwerke protokollieren mit `log group`. ulogd2 im selben Container nimmt die Einträge an und gibt sie als Syslog weiter.
- **Begründung:** Der Kernel verwirft gewöhnliche Log-Einträge aus Containern. Die Freischaltung gelingt nur auf dem Host, und die Einträge landen dann im Kernel-Log des Hosts. NFLOG ist davon nicht betroffen.
- **Geprüft:** ulogd ist im Image `fw` enthalten (Test `test-images`). Das Zusammenspiel im Container ist ungeprüft, Phase 4.
- **Anforderung:** MON-02.

### E-12 Kein Namensdienst

- **Entscheidung:** Alle Systeme verwenden Adressen. Wo ein Name nötig ist, genügt ein Eintrag in der Hosts-Datei.
- **Begründung:** Spart einen Container und einen Dienst.
- **Folge:** Das TLS-Zertifikat des Proxys ist selbst signiert.
- **Folge:** Jede Anfrage trägt eine IP-Adresse im Host-Header. Die CRS-Regel 920350 würde deshalb bei jeder legitimen Anfrage anschlagen und das SIEM mit Fehlalarmen füllen. Sie ist nur für die beiden eigenen Adressen abgeschaltet, fremde IP-Adressen im Host-Header meldet die WAF weiterhin (Test WA-05).

### E-13 Feste Containerlab-Version

- **Entscheidung:** `scripts/install.sh` installiert Containerlab 0.82.0. Eine andere Version lässt sich mit `CLAB_VERSION` setzen.
- **Begründung:** Die Installation ist wiederholbar und verhält sich auf der Labor-VM wie auf den Entwicklungs-VMs.

## Risiken und Prüfungen

| Nr. | Risiko | Prüfung |
|---|---|---|
| R-01 | Die Anzeige im Dashboard dauert länger als 1 s. Grafana aktualisiert standardmäßig frühestens alle 5 s. Die Einstellung `min_refresh_interval` senkt den Wert. Berichte über die Wirkung sind uneinheitlich. | Vorabtest zu Beginn von Phase 4, vor dem Bau der Dashboards. |
| R-02 | Das gemeinsame Image `lab-siem` mit drei Diensten lässt sich nicht sauber bauen. | Ausweichen auf drei Knoten (E-09). |
| R-03 | nftables, tc und WireGuard brauchen erweiterte Rechte im Container. | Erledigt: Test R-03 in `test-topology` bestanden. |
| R-04 | Suricata belegt mehr RAM als geschätzt. | Erledigt: gemessen 37 MB von 512 MB (2026-11-02). |
| R-05 | Logs füllen die Disk. | Aufbewahrungsdauer in Loki begrenzen, Log-Größe der Container begrenzen, `eve.json` begrenzen. |
| R-06 | Der Bau der Images bricht über ein VPN ab (`I/O error` bei `apk`), weil das VPN die MTU verkleinert. | Images ohne VPN bauen oder die MTU von Docker anpassen. Vor dem Labortermin alle Images bauen. Hinweis im README. |

## Quellen

- Grafana Labs: Promtail, Hinweis zum Supportende. https://grafana.com/docs/loki/latest/clients/promtail/
- Wazuh: Installationsanleitung Wazuh-Indexer, Hardwareanforderungen. https://documentation.wazuh.com/current/installation-guide/wazuh-indexer/
- Fluent Bit: Syslog-Eingang. https://docs.fluentbit.io/manual/5.0/data-pipeline/inputs/syslog
- OISF: Suricata, Eve JSON Output. https://docs.suricata.io/en/suricata-7.0.13/output/eve/eve-json-output.html
- OWASP CRS-Projekt: modsecurity-crs-docker. https://github.com/coreruleset/modsecurity-crs-docker
- Linux-Kernel: netfilter, allow logging from non-init namespaces. https://lkml.iu.edu/hypermail/linux/kernel/1701.3/05214.html
