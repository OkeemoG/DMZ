# Projektplan – DMZ-Laborumgebung

Stand: 2026-11-05, Version 0.4.

## Ergebnisse der Phase 1

| Ergebnis | Datei | Stand |
|---|---|---|
| Anforderungsliste | Projektwissen, nicht im Repo | 0.4, A-01 bis A-05 entschieden |
| Netzplan mit Zonenmodell | `docs/DMZ_Netzplan_0.2.drawio` | 0.2 |
| Adressplan | `docs/adressplan.md` | 0.3 |
| Kommunikationsmatrix | `docs/kommunikationsmatrix.md` | 0.3 |
| Technologieentscheidungen | `docs/technologieentscheidungen.md` | 0.3 |
| Ressourcenbudget | diese Datei | 0.2 |

## Festgelegter Stack

- Firewalls: nftables
- Routing: Linux-Kernel mit statischen Routen, kein FRR
- VPN: IKEv2/IPsec mit strongSwan nach BSI TR-02102-3, zwei Clients, Endpunkt `fw-edge`
- Reverse-Proxy: Nginx
- WAF: ModSecurity v3 mit OWASP CRS 4
- Webanwendung: eigene Anwendung mit Python, Flask, SQLite
- IDS: Suricata mit eigenen Regeln am Spiegelport
- SIEM: Grafana und Loki, Sammler Fluent Bit, ein Container mit eigenem Image
- Meldeweg: Syslog über UDP 5140, Firewall-Meldungen über NFLOG und ulogd2
- Reaktion: Responder im SIEM, Sperren über SSH mit Forced Command an `fw-edge` (E-17, E-18)
- Kein Namensdienst

## Ressourcenbudget

Schätzungen aus Phase 1, Grenzen und Messungen Stand 2026-11-04.

### RAM

| Gruppe | Knoten | Schätzung | Gemessen | Grenze je Knoten | Summe der Grenzen |
|---|---|---|---|---|---|
| Netzknoten (`fw`, `router`, `client`) | 9 | je 5–25 MB | je 0,5–1,2 MB | 64 MB | 576 MB |
| `proxy` | 1 | 10–30 MB | 3 MB | 64 MB | 64 MB |
| `waf` | 1 | 60–150 MB | 44 MB | 256 MB | 256 MB |
| `web` | 1 | 30–80 MB | 28 MB | 128 MB | 128 MB |
| `ids` | 1 | 150–350 MB | 34 MB | 256 MB | 256 MB |
| `siem` mit vier Diensten | 5 | 265–530 MB | 410–450 MB ohne Responder | 64/64/64/256/512 MB | 960 MB |
| Summe | 18 | 570–1285 MB | ca. 520 MB ohne Responder | | 2240 MB |

Verfügbar sind 3423 MB. Die Reserve für Debian, Docker und den Bau der Images beträgt 1183 MB. Gemessen am 2026-11-04: 2598 MB verfügbar, kein Swap. Die Grenzen werden in der Topologie je Knoten gesetzt und wirken (`docker stats`).

### Disk

| Posten | Schätzung |
|---|---|
| Images | 1,0–1,5 GB |
| Zwischenstände beim Bau der Images | 0,5 GB |
| Meldungen im SIEM, begrenzt über die Aufbewahrungsdauer | 0,5 GB |
| Logs und Dateisysteme der Container, Größe begrenzt | 0,2 GB |
| Summe | 2,2–2,7 GB |

Verfügbar sind 7,0 GB. Die Reserve beträgt mindestens 4,3 GB.

### Regeln

- Der Swap von 582 MB bleibt als Sicherheitsnetz erhalten.
- CPU: keine Grenzen zu Beginn. Suricata und Grafana sind die einzigen Knoten mit nennenswerter Last.
- Messung nach jeder Phase mit `docker stats --no-stream`, `docker system df`, `free -m` und `df -h /`. Die Werte gehen in die Systeminfo.

## Stand der Umsetzung (2026-11-02)

| Phase | Stand |
|---|---|
| 2 Grundaufbau | Erledigt. 14 Knoten ohne Management-Netz, Adressen und Routen nach Adressplan (T-01 bis T-03), Rechte im Container (R-03). |
| 3 Sicherheitssysteme | Firewalls nach Matrix 0.3, `proxy`, `web`, `waf` und `ids` erledigt und getestet. Offen: VPN (Schritt 4), in Arbeit. |
| 4 Logging und SIEM | Erledigt. Fluent Bit, Loki und Grafana in drei Containern (E-09), alle vier Sensoren melden in unter 1 s (E-10, E-11), Normalisierung (E-14), Zugang über Out-of-Band-Netz (E-15), Dashboard „SOC – DMZ“ (E-16). Test `test-siem`. |
| 5 Härtung (Stand 2026-11-05) | Umgesetzt und in der VM getestet (`make test-all` bestanden): Container ohne Privilegien, minimale Rechte, Kernel-Einstellungen, Output-Ketten der Firewalls, IDS-Watchdog und Logbegrenzung, Proxy-Zeitlimits, Grafana-Passwort, Docker-Loglimits (`docs/haertung.md`, E-21, `test-hardening`). |
| 7 bis 8 | Offen: schriftliche Dokumentation, Ablaufplan der Live-Demo. |
| 6 Reaktion (Stand 2026-11-05) | Umgesetzt und in der VM getestet (`make test-all` bestanden): Responder mit Playbooks P-1 bis P-5, Sperren und Quarantäne an `fw-edge`, Kanal K-13, Anti-Spoofing, Beweissicherung, Wiederherstellung, Dashboard, Test `test-response`, A-1 bis A-3 mit Reaktion (`docs/reaktion.md`). |

Alle Tests laufen mit `make test-all` (Ablauf siehe `README.md`).

## Umsetzungsreihenfolge

### Phase 2 – Grundaufbau

1. Images `fw`, `router` und `client` bauen (E-01).
2. Topologie `topology/dmz.clab.yml` mit allen 14 Knoten. Systeme ohne fertiges Image starten zunächst mit dem Image `client`.
3. Adressen und Routen nach Adressplan. Standardroute über das Management-Netz ersetzen.
4. Tests T-01 bis T-03: Adressen, Nachbarn, Ende zu Ende.
5. Rechte im Container prüfen: nftables, tc, WireGuard (R-03).
6. Ressourcen messen.

Ergebnis: Alle Knoten laufen und erreichen sich ohne Filterung.

### Phase 3 – Sicherheitssysteme

1. Regelwerke für `fw-edge`, `fw-dmz`, `fw-backend` nach Kommunikationsmatrix. An dieser Stelle steht die Entscheidung zum Internetzugang der DMZ erneut an.
2. `proxy`, danach `web`, danach `waf`.
3. `ids` mit Spiegelung.
4. VPN.

Ergebnis: Jede Zeile der Matrix ist getestet, erlaubt wie verboten.

### Phase 4 – Logging und SIEM

1. SIEM-Container und Zugang für den Operator.
2. Vorabtest der Anzeige innerhalb von 1 s (R-01).
3. Meldungen der vier Systeme anbinden: WAF, IDS, Firewalls.
4. Normalisierung im Collector und Dashboard. Zugriff im Labor prüfen.

### Phase 5 bis 8

- Phase 5: Härtung je Sicherheitssystem mit Prüfverfahren.
- Phase 6: Drei Angriffe, mindestens einer aus dem Client-Netz. Reaktive Maßnahme (A-06). Messung der 1 s (A-07).
- Phase 7: Dokumentation abschnittsweise.
- Phase 8: Ablaufplan der Live-Demo.

## Ordnerstruktur im Repo

```
DMZ/
├── Makefile           # Bau, Start, Tests (make test-all)
├── README.md          # Installation und Betrieb
├── scripts/           # install.sh, build-images.sh
├── topology/          # dmz.clab.yml, basicTest.clab.yml
├── images/            # fw, router, client, proxy, waf, web, ids
├── configs/           # fw-edge, fw-dmz, fw-backend, proxy, waf, ids
├── tests/             # ein Testskript je Thema
├── quellen/           # BSI TR-02102-1 und TR-02102-2
└── docs/              # Aufgabenstellung, Planung, Netzpläne
```

Seit Phase 4 kommen `configs/siem` (Fluent Bit, Loki, Grafana, Dashboard) und `configs/fw` (ulogd2) dazu, seit Phase 6 `attacks/`, `configs/response` (Playbooks, `fw-response`, `sshd`) und `images/responder`.

## Abgleich mit den Bewertungskriterien

| Kriterium | Stand am 2026-11-05 |
|---|---|
| Vollständigkeit der Netze und Systeme | DMZ mit Firewall, Reverse-Proxy, WAF, IDS und Webserver sowie SIEM im Backend umgesetzt und getestet. VPN mit strongSwan umgesetzt (`test-vpn`). |
| Drei Angriffe, hoher Schwierigkeitsgrad | A-1 bis A-3 in `attacks/`, A-3 aus dem Client-Netz. |
| Proaktive, detektierende und reaktive Maßnahmen | Reaktion umgesetzt: automatische Sperre, Quarantäne, Sperre von C2-Zielen, Beweissicherung, Wiederherstellung (`docs/reaktion.md`). `test-response` und A-1 bis A-3 bestanden. |
| Anzeige innerhalb von 1 s | Erfüllt: Transport bis Loki 50 bis 650 ms, Dashboard mit 1 s Aktualisierung, Live-Ansicht ohne Abfrage-Intervall (E-16). |
| Stabilität in der Demo | Alle Tests bestanden. Speichergrenzen gesetzt. Bekannt: Suricata ohne Überwachung. |
| Methodenkompetenz | Phasenmodell, IDs für Anforderungen, Verbindungen und Tests, Entscheidungen mit Alternativen. |
| Design | Netzplan, Adressplan 0.3, Matrix 0.4 und Entscheidungen 0.4 passen zur Umsetzung. Netzplan um `siem-responder` und K-13 ergänzen. |
| Installation | `install.sh` mit fester Containerlab-Version, README mit Anleitung und Fehlerquellen. Wiederholungsnachweis auf frischer VM fehlt. |
| Nachweise | Elf Testskripte, `make test-all`, Latenzmessung in `test-siem`, Reaktionszeit in `test-response`. Protokolle der Testläufe für die Dokumentation sichern. |
| Dokumentation | Nicht begonnen. Ein Diagramm der Datenflüsse fehlt. |

## Offene Punkte

| Nr. | Punkt | Stand |
|---|---|---|
| 1 | Internetzugang aus der DMZ | Erledigt: K-06 bleibt (Matrix 0.2), V-12 sperrt alle übrigen Dienste. |
| 2 | Standardroute und Erreichbarkeit über das Management-Netz | Erledigt: kein Management-Netz (`network-mode: none`), Test T-01. |
| 3 | Rechte für nftables, tc und WireGuard im Container | Erledigt: Test R-03. Kernelmodul WireGuard auf der Labor-VM noch prüfen. |
| 4 | Ziele des VPN-Clients über die Webanwendung hinaus (K-08) | Offen, mit dem VPN. |
| 5 | Anzeige innerhalb von 1 s, Grafana mit Loki ausreichend | Erledigt (R-01, E-16). |
| 6 | Zugriff auf das Dashboard (K-12) | Erledigt: Management-Netz nur für `siem`, Port 3000 auf der VM (E-15). Zugriff im Labor der DHBW noch prüfen. |
| 7 | Reaktive Maßnahme (A-06) und Messmethode (A-07) | Umgesetzt (E-17 bis E-20). Messung: RE-03 misst die Zeit vom dritten geblockten Angriff bis zur wirksamen Sperre, gemessen 70 bis 250 ms, Ziel unter 1 s erfüllt. |
| 8 | Drei Angriffe und Werkzeuge des Angreifers | Umgesetzt: A-1 bis A-3 mit curl, socat und openssl aus dem Image `client`. |
| 9 | Diagramm der Datenflüsse (DOC-03) | Offen, Phase 7. |
| 10 | Wiederholungsnachweis für `install.sh`, Containerlab-Version festschreiben | Version 0.82.0 festgeschrieben (E-13). Wiederholungsnachweis offen. |
| 11 | Übersicht der KI-Unterstützung für das Hilfsmittelverzeichnis | Laufend, Abschluss in Phase 7. |
| 12 | IDS sieht durchgelassene Anfragen doppelt | Bekannt. Ein Alarm von 10.10.10.6 → 10.10.10.10 zeigt, dass ein Angriff die WAF passiert hat. Für die Demo nutzbar. |
| 13 | Suricata ohne Überwachung, `eve.json` unbegrenzt | Erledigt in Phase 5: Watchdog mit Neustart und Meldung, Logdateien höchstens 50 MB (H-06). |
| 14 | Bau der Images über VPN bricht ab | Hinweis im README, vor dem Labortermin Images bauen (R-06). |
| 15 | Nach dem VPN-Merge fehlten auf `fw-edge` das Bind für `ulogd.conf` und die Log-Regel der Input-Kette. `fw-edge` meldete keine verworfenen Pakete. | Behoben im Branch `response`. S-05 prüft es wieder. |
| 16 | Beim Neubau des Images `fw` kam eine neuere ulogd-Version mit anderem Zeilenformat (`drop:  IN=`, `MARK=0x0`). Suricata 8 schreibt `xff` bei Alarmen in `alert`. Beides hat die Zerlegung im Collector gebrochen. | Behoben im Branch `response` (E-14). Gegen die echten Zeilen mit Fluent Bit 5.1.5 geprüft. |
| 17 | Grafana 13.3 liefert die Startseite als virtuelles Dashboard `default-home-dashboard` aus der Datei und leitet dorthin um. | S-06 akzeptiert die Umleitung. |
