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

Jedes Skript beginnt mit einem sauberen Zustand der automatischen Reaktion (Sperren aufgehoben, Zähler zurückgesetzt) und stellt den Modus selbst ein. A-1 und A-3 laufen mit aktiver Reaktion, A-2 misst zuerst die WAF allein im Beobachtungsmodus und wiederholt die Kampagne dann mit aktiver Reaktion. Konzept und Playbooks: [`docs/reaktion.md`](../docs/reaktion.md).

## Übersicht

| ID | Angriff | Herkunft | Geprüfte Schicht |
|---|---|---|---|
| A-1 | Mehrstufig: Portscan, Fingerprinting, Angriff auf die Webanwendung (SQLi, UNION, XSS, Path Traversal, Scanner) | Internet (`attacker`) | `fw-edge` verwirft den Scan, die WAF blockt die Web-Angriffe, das IDS erkennt UNION und Path Traversal. Nach dem dritten WAF-Block sperrt der Responder den Angreifer an `fw-edge` (P-1), die restlichen Angriffe laufen ins Leere. |
| A-2 | WAF-Evasion: dieselben Angriffe in vielen Verschleierungen (Groß-/Kleinschreibung, Inline-Kommentare, Kodierung) | Internet (`attacker`) | Teil 1: Widerstandsfähigkeit der WAF allein. Durchkommende Varianten sind ein belegter Befund und werden über die Paranoia-Stufe geschlossen. Teil 2: dieselbe Kampagne mit aktiver Reaktion, der Angreifer wird nach wenigen Versuchen ausgesperrt. |
| A-3 | Kompromittierter interner Host: Angriff auf das Portal, danach Pivot-Versuche ins DMZ-Innere und ins Backend | Client-Netz (`client1`) | Die WAF behandelt interne Angreifer gleich, `fw-edge` und `fw-dmz` sperren jeden Pivot (V-03, V-04). Nach dem dritten Pivot-Versuch isoliert der Responder `client1` (P-4), die Freigabe erfolgt erst durch den Operator. |

## Bezug zur Aufgabenstellung

- Mindestens drei Angriffe, davon mindestens einer aus dem Client-Netz (A-3): erfüllt.
- Hoher technischer Schwierigkeitsgrad: A-1 ist mehrstufig, A-2 prüft die Evasion-Resistenz systematisch.
- Erkennung innerhalb von 1 s im SIEM: über das Dashboard und die Live-Ansicht (siehe `docs/technologieentscheidungen.md`, E-16).
- Reaktive Maßnahmen: automatische Sperre (A-1, A-2) und Isolation eines internen Hosts (A-3) mit Anzeige im Dashboard.
- Defense in Depth: Kein einzelner Sensor sieht alles. XSS erkennt nur die WAF, UNION und Path Traversal zusätzlich das IDS, den Scan nur die Firewall. Erst zusammen ergibt sich das vollständige Bild.
