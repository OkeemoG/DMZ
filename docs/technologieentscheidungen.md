# Technologieentscheidungen – DMZ-Laborumgebung

Stand: 2026-10-08, Version 0.1 .

Alle Speicherwerte sind Schätzungen ohne Messung. Die Messung folgt mit dem Ressourcenbudget. Versionen werden in Phase 2 festgelegt.

## Übersicht

| Knoten | Technik | Image | RAM geschätzt |
|---|---|---|---|
| `fw-edge` | nftables, WireGuard, ulogd2 | `lab-net` | 10–25 MB |
| `fw-dmz` | nftables, ulogd2, Spiegelung mit tc | `lab-net` | 10–25 MB |
| `fw-backend` | nftables | `lab-net` | 5–15 MB |
| `router-int`, `inet` | Linux-Routing mit statischen Routen | `lab-net` | je 5–10 MB |
| `client1`, `attacker` | curl | `lab-net` | je 5–15 MB |
| `ro-client1`, `ro-client2` | curl, WireGuard | `lab-net` | je 5–15 MB |
| `proxy` | Nginx | `nginx`, Alpine-Variante | 10–30 MB |
| `waf` | Nginx, ModSecurity v3, OWASP CRS 4 | `owasp/modsecurity-crs`, Variante `nginx-alpine` | 60–150 MB |
| `web` | Python, Flask, gunicorn, SQLite | `lab-web` | 30–80 MB |
| `ids` | Suricata | `lab-ids` | 150–350 MB |
| `siem` | Grafana, Loki, Fluent Bit | `lab-siem` | 250–500 MB |
| Summe, 14 Container | | | 555–1255 MB |

Verfügbar sind 3423 MB RAM (Messung vom 2026-10-07).

## Images

| Image | Herkunft | Inhalt | Disk geschätzt |
|---|---|---|---|
| `lab-net` | Eigenbau auf Alpine | iproute2, nftables, ulogd2, wireguard-tools, curl, tcpdump | 40 MB |
| `nginx` | offiziell | Nginx | 50 MB |
| `owasp/modsecurity-crs` | offiziell, OWASP CRS-Projekt | Nginx, ModSecurity, CRS | 100–200 MB |
| `lab-web` | Eigenbau auf Python-Alpine | Flask, gunicorn, eigene Anwendung | 80–100 MB |
| `lab-ids` | Eigenbau auf Alpine | Suricata | 100–200 MB |
| `lab-siem` | Eigenbau auf Grafana | Grafana, Loki, Fluent Bit | 600–900 MB |
| Summe | | | 1,0–1,5 GB |

Verfügbar sind 7,0 GB Disk. Neun Knoten teilen sich das Image `lab-net`. Docker speichert es nur einmal.

## Entscheidungen

### E-01 Gemeinsames Basis-Image `lab-net`

- **Entscheidung:** Ein Image für alle Firewalls, Router, Clients und den Angreifer.
- **Begründung:** Geringer Disk-Bedarf, eine Stelle für Aktualisierungen. Die Rolle eines Knotens entsteht durch seine Konfiguration, nicht durch das Image.
- **Alternative:** Ein Image pro Rolle. Kleinere Angriffsfläche pro Knoten, mehr Pflege.
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
- **Ungeprüft:** Verfügbarkeit des Kernelmoduls auf der VM.
- **Anforderung:** NET-05.

### E-05 Reverse-Proxy mit Nginx

- **Entscheidung:** Nginx. Aufgaben: TLS beenden, Anfragen an die WAF weiterreichen, ursprüngliche Absenderadresse im Header mitgeben, Anfragerate begrenzen.
- **Begründung:** Kleines Image. Die WAF basiert ebenfalls auf Nginx, es bleibt bei einer Konfigurationssprache.
- **Alternativen:** HAProxy (gleichwertig, zweite Konfigurationssprache). Traefik, Caddy (auf wechselnde Dienste ausgelegt).
- **Anforderungen:** SYS-02, SEC-02.

### E-06 WAF mit ModSecurity und OWASP Core Rule Set

- **Entscheidung:** Image `owasp/modsecurity-crs` in der Variante `nginx-alpine`. Das Image enthält ModSecurity v3 und CRS 4. Es läuft ohne Root-Rechte und lauscht auf Port 8080.
- **Begründung:** Fertiges, gepflegtes Image des CRS-Projekts. Der Regelsatz ist der verbreitete offene Standard. Die Empfindlichkeit ist über eine Stufe einstellbar.
- **Alternative:** Coraza. Jüngeres Projekt, kein vergleichbares fertiges Image mit Nginx.
- **Anforderungen:** SYS-04, SEC-02, SEC-03.

### E-07 Webserver und Webanwendung

- **Entscheidung:** Eigene kleine Anwendung in Python mit Flask, gunicorn und SQLite. Anmeldung, Suche, Datei-Abruf. Port 8080.
- **Begründung:** Geringer Speicherbedarf. Der Code ist vollständig bekannt, jeder Angriff lässt sich erklären. Schwachstellen sind gezielt einbaubar, damit die WAF etwas abzuwehren hat.
- **Alternativen:** OWASP Juice Shop (mehrere hundert MB RAM, fremder Code). DVWA (zusätzliche Datenbank). Statische Seite (kein lohnendes Angriffsziel).
- **Anforderungen:** SYS-05, ATK-05, ATK-06.

### E-08 IDS mit Suricata und eigenen Regeln

- **Entscheidung:** Suricata am Spiegelport. Eigene Regeln, passend zu den Angriffen. Kein vollständiger fremder Regelsatz.
- **Begründung:** Verbreitetes offenes IDS mit Ausgabe als JSON. Eigene Regeln halten den Speicherbedarf klein und belegen das Verständnis.
- **Alternativen:** Snort 3 (kein gepflegtes kleines Image). Zeek (Protokollanalyse, keine Signaturen).
- **Ungeprüft:** Aktualität des Suricata-Pakets in Alpine. Ausweichoption ist das Image `jasonish/suricata`.
- **Anforderungen:** SYS-03, SEC-03, MON-01.

### E-09 SIEM mit Grafana und Loki

- **Entscheidung:** Loki speichert und durchsucht die Meldungen. Grafana zeigt Dashboards und Alarme. Beides läuft im Knoten `siem`.
- **Begründung:** Passt in das Speicherbudget. Der Wazuh-Indexer verlangt mindestens 4 GB RAM und scheidet damit aus. Elasticsearch und Graylog liegen in derselben Größenordnung.
- **Grenze:** Grafana mit Loki ist eine Log-Plattform mit Alarmregeln, kein vollständiges SIEM. Es fehlen fertige Korrelationsregeln und Fallbearbeitung. Die Grenze gehört in das Fazit der Dokumentation.
- **Alternative im Aufbau:** Drei getrennte Knoten für Grafana, Loki und Sammler. Unveränderte offizielle Images, dafür ein größerer Adressplan und mehr Firewall-Regeln.
- **Anforderungen:** SYS-07, MON-02, MON-03, MON-05.

### E-10 Meldeweg über Syslog

- **Entscheidung:** Die vier meldenden Systeme senden Syslog über UDP 5140 an `siem`. Dort nimmt Fluent Bit die Meldungen an und übergibt sie an Loki.
- **Begründung:** Kein Agent auf den meldenden Systemen. Suricata und Nginx senden Syslog selbst. UDP puffert nicht, das hilft bei der Vorgabe von 1 s.
- **Alternativen:** Fluent Bit auf jedem meldenden System (strukturierte Daten, vier zusätzliche Dienste). Promtail (seit dem 2. März 2026 abgekündigt). Grafana Alloy (Nachfolger, deutlich größer).
- **Grenze:** Syslog über UDP ist unverschlüsselt und nicht authentifiziert. Die Firewalls lassen nur die vier Absenderadressen zu.
- **Anforderungen:** MON-02, MON-04.

### E-11 Firewall-Meldungen über NFLOG und ulogd2

- **Entscheidung:** Die Regelwerke protokollieren mit `log group`. ulogd2 im selben Container nimmt die Einträge an und gibt sie als Syslog weiter.
- **Begründung:** Der Kernel verwirft gewöhnliche Log-Einträge aus Containern. Die Freischaltung gelingt nur auf dem Host, und die Einträge landen dann im Kernel-Log des Hosts. NFLOG ist davon nicht betroffen.
- **Ungeprüft:** ulogd2 als Paket in Alpine, Zusammenspiel im Container.
- **Anforderung:** MON-02.

### E-12 Kein Namensdienst

- **Entscheidung:** Alle Systeme verwenden Adressen. Wo ein Name nötig ist, genügt ein Eintrag in der Hosts-Datei.
- **Begründung:** Spart einen Container und einen Dienst.
- **Folge:** Das TLS-Zertifikat des Proxys ist selbst signiert.

## Risiken und Prüfungen

| Nr. | Risiko | Prüfung |
|---|---|---|
| R-01 | Die Anzeige im Dashboard dauert länger als 1 s. Grafana aktualisiert standardmäßig frühestens alle 5 s. Die Einstellung `min_refresh_interval` senkt den Wert. Berichte über die Wirkung sind uneinheitlich. | Vorabtest zu Beginn von Phase 4, vor dem Bau der Dashboards. |
| R-02 | Das gemeinsame Image `lab-siem` mit drei Diensten lässt sich nicht sauber bauen. | Ausweichen auf drei Knoten (E-09). |
| R-03 | nftables, tc und WireGuard brauchen erweiterte Rechte im Container. | Test in Phase 2 mit dem ersten Firewall-Knoten. |
| R-04 | Suricata belegt mehr RAM als geschätzt. | Messung mit `docker stats`, Speichergrenze pro Knoten in der Topologie. |
| R-05 | Logs füllen die Disk. | Aufbewahrungsdauer in Loki begrenzen, Log-Größe der Container begrenzen. |

## Quellen

- Grafana Labs: Promtail, Hinweis zum Supportende. https://grafana.com/docs/loki/latest/clients/promtail/
- Wazuh: Installationsanleitung Wazuh-Indexer, Hardwareanforderungen. https://documentation.wazuh.com/current/installation-guide/wazuh-indexer/
- Fluent Bit: Syslog-Eingang. https://docs.fluentbit.io/manual/5.0/data-pipeline/inputs/syslog
- OISF: Suricata, Eve JSON Output. https://docs.suricata.io/en/suricata-7.0.13/output/eve/eve-json-output.html
- OWASP CRS-Projekt: modsecurity-crs-docker. https://github.com/coreruleset/modsecurity-crs-docker
- Linux-Kernel: netfilter, allow logging from non-init namespaces. https://lkml.iu.edu/hypermail/linux/kernel/1701.3/05214.html
