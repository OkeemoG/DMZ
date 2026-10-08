# Projektplan – DMZ-Laborumgebung

Stand: 2026-10-08, Version 0.1. Grober Umriss.

## Ergebnisse der Phase 1

| Ergebnis | Datei | Stand |
|---|---|---|
| Anforderungsliste | Projektwissen, `docs/anforderungen.md` | 0.4, A-01 bis A-05 entschieden |
| Netzplan mit Zonenmodell | `docs/diagrams/DMZ_Netzplan_0.5.drawio` | 0.2 |
| Adressplan | `docs/adressplan.md` | 0.1 |
| Kommunikationsmatrix | `docs/kommunikationsmatrix.md` | 0.1 |
| Technologieentscheidungen | `docs/technologieentscheidungen.md` | 0.1, am 2026-10-08 bestätigt |
| Ressourcenbudget, Umriss | diese Datei | 0.1 |

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
| Netzknoten (`lab-net`) | 9 | je 5–25 MB | 64 MB | 576 MB |
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

## Umsetzungsreihenfolge

### Phase 2 – Grundaufbau

1. Image `lab-net` bauen.
2. Topologie `topology/dmz.clab.yml` mit allen 14 Knoten. Systeme ohne fertiges Image starten zunächst als `lab-net`.
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
SUN_DMZ/
├── Makefile
├── README.md
├── scripts/install.sh
├── topology/
│   ├── dmz.clab.yml
│   └── test/basicTest.clab.yml
├── images/            # lab-net, lab-web, lab-ids, lab-siem
├── configs/           # ein Ordner pro Knoten: fw-edge, fw-dmz, fw-backend,
│                      # router-int, proxy, waf, web, ids, siem, ro-client1, ro-client2
├── attacks/
├── tests/
└── docs/
    ├── adressplan.md
    ├── kommunikationsmatrix.md
    ├── technologieentscheidungen.md
    ├── projektplan.md
    └── diagrams/DMZ_Netzplan_0.5.drawio
```

Ordner entstehen mit der ersten Datei.

## Abgleich mit den Bewertungskriterien

| Kriterium | Stand nach Phase 1 |
|---|---|
| Vollständigkeit der Netze und Systeme | Im Entwurf vollständig. |
| Drei Angriffe, hoher Schwierigkeitsgrad | Nicht entworfen. Phase 6. |
| Anzeige innerhalb von 1 s | Risiko R-01. Phase 4. |
| Stabilität in der Demo | Offen. Speichergrenzen und Reserve sind eingeplant. |
| Methodenkompetenz | Phasenmodell, Anforderungs-IDs, Entscheidungen mit Alternativen liegen vor. |
| Design | Netzplan, Adressplan, Matrix und Begründungen liegen vor. |
| Installation | `install.sh` und Basistest liegen vor. Wiederholungsnachweis fehlt. |
| Nachweise | Testfälle sind benannt, Ergebnisse fehlen. |
| Dokumentation | Nicht begonnen. Ein Diagramm der Datenflüsse fehlt. |

## Offene Punkte

| Nr. | Punkt | Klärung |
|---|---|---|
| 1 | Internetzugang aus der DMZ. Die strenge Lesart der Aufgabenstellung ist nicht erfüllt (Matrix, V-09). | Phase 3, bei den Firewall-Regeln |
| 2 | Standardroute und Erreichbarkeit über das Management-Netz | Phase 2 |
| 3 | Rechte für nftables, tc und WireGuard im Container. Kernelmodul WireGuard. | Phase 2 und 3 |
| 4 | Ziele des VPN-Clients über die Webanwendung hinaus (K-08) | Phase 3 |
| 5 | Anzeige innerhalb von 1 s. Grafana mit Loki als SIEM ausreichend. | Phase 4 |
| 6 | Zugriff auf das Dashboard im Labor (K-12) | Test im Labor mit dem ersten Gesamtstand |
| 7 | Reaktive Maßnahme (A-06) und Messmethode (A-07) | Phase 6 |
| 8 | Drei Angriffe und Werkzeuge des Angreifers | Phase 6 |
| 9 | Diagramm der Datenflüsse für die Dokumentation (DOC-03) | Entwurf nach Phase 3, Reinzeichnung in Phase 7 |
| 10 | Wiederholungsnachweis für `install.sh`, Containerlab-Version festschreiben | Vor der Abgabe |
| 11 | Übersicht der KI-Unterstützung für das Hilfsmittelverzeichnis | Laufend, Abschluss in Phase 7 |
