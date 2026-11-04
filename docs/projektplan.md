# Projektplan – DMZ-Laborumgebung

Stand: 2026-11-02, Version 0.2.

## Ergebnisse der Phase 1

| Ergebnis | Datei | Stand |
|---|---|---|
| Anforderungsliste | Projektwissen, nicht im Repo | 0.4, A-01 bis A-05 entschieden |
| Netzplan mit Zonenmodell | `docs/DMZ_Netzplan_0.2.drawio` | 0.2 |
| Adressplan | `docs/adressplan.md` | 0.2 |
| Kommunikationsmatrix | `docs/kommunikationsmatrix.md` | 0.2 |
| Technologieentscheidungen | `docs/technologieentscheidungen.md` | 0.2 |
| Ressourcenbudget | diese Datei | 0.2 |

## Festgelegter Stack

- Firewalls: nftables
- Routing: Linux-Kernel mit statischen Routen, kein FRR
- VPN: WireGuard als Client-VPN, zwei Clients, Endpunkt `fw-edge`
- Reverse-Proxy: Nginx
- WAF: ModSecurity v3 mit OWASP CRS 4
- Webanwendung: eigene Anwendung mit Python, Flask, SQLite
- IDS: Suricata mit eigenen Regeln am Spiegelport
- SIEM: Grafana und Loki, Sammler Fluent Bit, ein Container mit eigenem Image
- Meldeweg: Syslog über UDP 5140, Firewall-Meldungen über NFLOG und ulogd2
- Kein Namensdienst

## Ressourcenbudget

Alle Werte sind Schätzungen. Die erste Messung folgt am Ende von Phase 2.

### RAM

| Gruppe | Knoten | Schätzung | Grenze je Knoten | Summe der Grenzen |
|---|---|---|---|---|
| Netzknoten (`fw`, `router`, `client`) | 9 | je 5–25 MB | 64 MB | 576 MB |
| `proxy` | 1 | 10–30 MB | 64 MB | 64 MB |
| `waf` | 1 | 60–150 MB | 256 MB | 256 MB |
| `web` | 1 | 30–80 MB | 128 MB | 128 MB |
| `ids` | 1 | 150–350 MB | 512 MB | 512 MB |
| `siem` | 1 | 250–500 MB | 768 MB | 768 MB |
| Summe | 14 | 555–1255 MB | | 2304 MB |

Verfügbar sind 3423 MB. Die Reserve für Debian, Docker und den Bau der Images beträgt 1119 MB. Die Grenzen werden in der Topologie je Knoten gesetzt. Die Option dafür ist ungeprüft.

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
| 3 Sicherheitssysteme | Firewalls nach Matrix 0.2, `proxy`, `web`, `waf` und `ids` erledigt und getestet. Offen: VPN (Schritt 4). |
| 4 Logging und SIEM | Offen. |
| 5 bis 8 | Offen. Grundlagen für die Angriffe liegen vor: verwundbare Webanwendung, WAF und IDS mit Erkennung. |

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

1. Vorabtest der Anzeige innerhalb von 1 s (R-01).
2. Image `lab-siem`.
3. Meldungen der vier Systeme anbinden.
4. Dashboards. Zugriff im Labor prüfen.

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

Geplant: `images/siem`, `configs/siem`, `attacks/`.

## Abgleich mit den Bewertungskriterien

| Kriterium | Stand am 2026-11-02 |
|---|---|
| Vollständigkeit der Netze und Systeme | DMZ mit Firewall, Reverse-Proxy, WAF, IDS und Webserver umgesetzt und getestet. Offen: VPN, SIEM. |
| Drei Angriffe, hoher Schwierigkeitsgrad | Nicht entworfen. Phase 6. |
| Anzeige innerhalb von 1 s | Risiko R-01. Phase 4. |
| Stabilität in der Demo | Alle Tests bestanden. Speichergrenzen gesetzt. Bekannt: Suricata ohne Überwachung. |
| Methodenkompetenz | Phasenmodell, IDs für Anforderungen, Verbindungen und Tests, Entscheidungen mit Alternativen. |
| Design | Netzplan, Adressplan 0.2, Matrix 0.2 und Entscheidungen 0.2 passen zur Umsetzung. |
| Installation | `install.sh` mit fester Containerlab-Version, README mit Anleitung und Fehlerquellen. Wiederholungsnachweis auf frischer VM fehlt. |
| Nachweise | Sieben Testskripte, `make test-all`. Protokolle der Testläufe für die Dokumentation sichern. |
| Dokumentation | Nicht begonnen. Ein Diagramm der Datenflüsse fehlt. |

## Offene Punkte

| Nr. | Punkt | Stand |
|---|---|---|
| 1 | Internetzugang aus der DMZ | Erledigt: K-06 bleibt (Matrix 0.2), V-12 sperrt alle übrigen Dienste. |
| 2 | Standardroute und Erreichbarkeit über das Management-Netz | Erledigt: kein Management-Netz (`network-mode: none`), Test T-01. |
| 3 | Rechte für nftables, tc und WireGuard im Container | Erledigt: Test R-03. Kernelmodul WireGuard auf der Labor-VM noch prüfen. |
| 4 | Ziele des VPN-Clients über die Webanwendung hinaus (K-08) | Offen, mit dem VPN. |
| 5 | Anzeige innerhalb von 1 s, Grafana mit Loki ausreichend | Offen, Phase 4. |
| 6 | Zugriff auf das Dashboard (K-12) | Offen. Ohne Management-Netz gibt es keinen Weg vom Browser zu `siem`. Möglich sind ein eigener Link `siem` ↔ Host über einen `host:`-Endpunkt oder ein Management-Netz nur für `siem`. Entscheidung beim Aufbau des SIEM. |
| 7 | Reaktive Maßnahme (A-06) und Messmethode (A-07) | Offen, Phase 6. |
| 8 | Drei Angriffe und Werkzeuge des Angreifers | Offen, Phase 6. |
| 9 | Diagramm der Datenflüsse (DOC-03) | Offen, Phase 7. |
| 10 | Wiederholungsnachweis für `install.sh`, Containerlab-Version festschreiben | Version 0.82.0 festgeschrieben (E-13). Wiederholungsnachweis offen. |
| 11 | Übersicht der KI-Unterstützung für das Hilfsmittelverzeichnis | Laufend, Abschluss in Phase 7. |
| 12 | IDS sieht durchgelassene Anfragen doppelt | Beim Bau der Dashboards berücksichtigen (E-08). |
| 13 | Suricata ohne Überwachung, `eve.json` unbegrenzt | Phase 4 (E-08, R-05). |
| 14 | Bau der Images über VPN bricht ab | Hinweis im README, vor dem Labortermin Images bauen (R-06). |
