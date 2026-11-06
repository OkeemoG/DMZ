# Drehbuch der Live-Demo – DMZ-Laborumgebung

Stand: 2026-11-06, Entwurf. Die Zeit ist hart begrenzt: Jede angefangene Minute über 15 Minuten kostet 3 Punkte (`docs/aufgabenstellung.md`). Das Drehbuch plant deshalb 14 Minuten und eine Minute Puffer.

## Vorbereitung (vor dem Termin)

| Wann | Was |
|---|---|
| Tag davor | `make destroy deploy test-all` auf der Labor-VM, Ausgabe als `evidence/test-all-<Datum>.log` sichern. Bildschirmaufnahme der Demo als Rückfallebene. |
| 15 min vorher | `make deploy` (Grafana braucht bis zu 120 s). Danach `make preflight`, erwartet: `READY FOR THE DEMO`. |
| 5 min vorher | Browser: Dashboard „SOC – DMZ“ und in einem zweiten Tab den Link „Alarm-Stream live“ (Explore, **Live** an). Zwei Terminals im Repo: links für die Angriffe, rechts für `make response-status`. Schriftgröße so, dass die letzte Reihe mitlesen kann. |
| direkt vorher | `make preflight` noch einmal. Zeigt eine Zeile `FAIL`, zuerst die Abhilfe in der letzten Zeile versuchen, sonst auf die Aufnahme wechseln. |

Regel für die Demo: Nichts live reparieren. Scheitert ein Schritt, sagen, was zu sehen gewesen wäre, und die gesicherte Ausgabe oder die Aufnahme zeigen.

## Ablauf

| Zeit | Inhalt | Zeigen | Kernaussage |
|---|---|---|---|
| 0:00–1:30 | Architektur | Netzplan: Zonen Internet, DMZ, Client-Netz, Backend, Remote Office. Weg einer Anfrage, einer Meldung, einer Reaktion (`README.md`). | Drei Firewalls, nur der Proxy ist von außen erreichbar, jeder Sensor meldet an das SIEM im Backend, das SIEM kann über einen einzigen Kanal (K-13) an `fw-edge` sperren. |
| 1:30–2:30 | Laufendes System | Dashboard „SOC – DMZ“, rechts `make response-status` | Alle Sensoren melden, Responder im Modus `enforce`, Kanal zu `fw-edge` steht. |
| 2:30–5:30 | A-1 Angriff aus dem Internet | Links `bash attacks/a1-external.sh`, dabei auf das Dashboard und Explore Live schauen | Scan an `fw-edge` verworfen, Web-Angriffe von der WAF geblockt und vom IDS unabhängig erkannt. Nach dem dritten Block sperrt der Responder den Angreifer in einigen hundert Millisekunden, die Reaktionszeit steht in der Ausgabe und im Dashboard. |
| 5:30–7:30 | A-3 kompromittierter Client | `bash attacks/a3-internal.sh` | Auch intern hält die WAF, jeder Pivot scheitert an `fw-edge`. Nach drei verbotenen Zielen ist `client1` isoliert. Freigabe nur durch den Operator, vorher Beweise sichern (`make evidence`). |
| 7:30–10:00 | A-4 kompromittierter Webserver | `bash attacks/a4-compromised-web.sh` | Reverse Shell über 4444 scheitert an `fw-dmz`, das IDS sieht sie trotzdem, der Responder sperrt den C2-Server für das ganze Firmennetz. Zu einer neuen Adresse über 443 kommen die ersten Antworten durch, dann erkennt das IDS die Befehlsausgabe und die Verbindung wird gekappt. Ehrliche Grenze: echtes TLS. |
| 10:00–10:45 | A-2 WAF-Evasion | Nur das Ergebnis aus dem gesicherten Log (Zeile „Coverage“) | Alle Verschleierungen geblockt, mit Reaktion bricht die Kampagne nach wenigen Versuchen ab. |
| 10:45–11:45 | VPN | `docker exec clab-dmz-fw-edge swanctl --list-sas` | IKEv2/IPsec nach BSI TR-02102-3, Zertifikate aus eigener PKI, nicht konforme Verfahren werden abgewiesen (N-09). Der Tunnel öffnet nur die Webanwendung. |
| 11:45–13:15 | Härtung | `docker exec clab-dmz-web mount -t tmpfs none /mnt` (verweigert), `docker exec clab-dmz-ids ps -o user,args` (Suricata als `suricata`), dann Zusammenfassung aus dem gesicherten `test-all`-Log | Container ohne Privilegien, Dienste ohne root, Firewalls schließen bei einem Fehler, gefälschte Absender in der DMZ werden verworfen. Jede Maßnahme hat einen Test. |
| 13:15–14:00 | Grenzen und Verbesserungen | Folie | Anzeige im ungünstigsten Fall etwas über 1 s auf dem Dashboard (Live-Ansicht ohne Wartezeit), P-3 mit gefälschten Absendern auslösbar, Shell in echtem TLS unsichtbar, feste Ausgangsziele der DMZ als nächster Schritt. |
| 14:00–15:00 | Puffer | – | – |

## Was bei einer Störung zu tun ist

| Störung | Sofortmaßnahme |
|---|---|
| `make preflight` meldet aktive Sperren | `docker exec clab-dmz-siem-responder respond flush` |
| Grafana zeigt nichts | Explore Live-Tab nutzen, sonst die Ausgabe der Angriffsskripte zeigen (sie prüfen die Erkennung selbst) |
| Ein Angriffsskript endet mit `FAIL` | Die Zeile vorlesen, im gesicherten Log den bestandenen Lauf zeigen, weiter im Ablauf |
| VM hängt | Bildschirmaufnahme |
