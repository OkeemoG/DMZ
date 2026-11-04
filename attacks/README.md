# Angriffe

Selbst erstellte Cyber-Angriffe zum Nachweis der Sicherheit der DMZ (Phase 6, Anforderung ATK-*). Alle Angriffe laufen innerhalb der isolierten Laborumgebung gegen die eigenen Systeme. Die Adressen stammen aus den Dokumentationsbereichen nach RFC 5737 und sind im Internet nicht erreichbar.

## Aufruf

Nach `make deploy` auf der VM:

```
bash attacks/a1-external.sh
bash attacks/a2-waf-evasion.sh
bash attacks/a3-internal.sh
```

Oder alle zusammen als Nachweis: `make test-attacks`.

Jedes Skript prüft am Ende selbst, ob jede Verteidigungsschicht gehalten hat, und endet mit `RESULT: all defenses held`. Danach gibt es die passenden Abfragen für Grafana aus. Für die Live-Demo das Dashboard „SOC – DMZ“ offen lassen, am besten die Alarm-Ansicht über den Link „Alarm-Stream live“.

## Übersicht

| ID | Angriff | Herkunft | Geprüfte Schicht |
|---|---|---|---|
| A-1 | Mehrstufig: Portscan, Fingerprinting, Angriff auf die Webanwendung (SQLi, UNION, XSS, Path Traversal, Scanner) | Internet (`attacker`) | `fw-edge` verwirft den Scan, die WAF blockt die Web-Angriffe, das IDS erkennt UNION und Path Traversal |
| A-2 | WAF-Evasion: dieselben Angriffe in vielen Verschleierungen (Groß-/Kleinschreibung, Inline-Kommentare, Kodierung) | Internet (`attacker`) | Widerstandsfähigkeit der WAF. Durchkommende Varianten sind ein belegter Befund und werden über die Paranoia-Stufe geschlossen. |
| A-3 | Kompromittierter interner Host: Angriff auf das Portal, danach Pivot-Versuche ins DMZ-Innere und ins Backend | Client-Netz (`client1`) | Die WAF behandelt interne Angreifer gleich, `fw-edge` und `fw-dmz` sperren jeden Pivot (V-03, V-04) |

## Bezug zur Aufgabenstellung

- Mindestens drei Angriffe, davon mindestens einer aus dem Client-Netz (A-3): erfüllt.
- Hoher technischer Schwierigkeitsgrad: A-1 ist mehrstufig, A-2 prüft die Evasion-Resistenz systematisch.
- Erkennung innerhalb von 1 s im SIEM: über das Dashboard und die Live-Ansicht (siehe `docs/technologieentscheidungen.md`, E-16).
- Defense in Depth: Kein einzelner Sensor sieht alles. XSS erkennt nur die WAF, UNION und Path Traversal zusätzlich das IDS, den Scan nur die Firewall. Erst zusammen ergibt sich das vollständige Bild.
