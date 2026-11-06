# Angriffe

Selbst erstellte Cyber-Angriffe zum Nachweis der Sicherheit der DMZ (Phase 6, Anforderung ATK-*). Alle Angriffe laufen innerhalb der isolierten Laborumgebung gegen die eigenen Systeme. Die Adressen stammen aus den Dokumentationsbereichen nach RFC 5737 und sind im Internet nicht erreichbar.

## Aufruf

Nach `make deploy` auf der VM:

```
bash attacks/a1-external.sh
bash attacks/a2-waf-evasion.sh
bash attacks/a3-internal.sh
bash attacks/a4-compromised-web.sh
```

Oder alle zusammen als Nachweis: `make test-attacks`.

Jedes Skript prüft am Ende selbst, ob jede Verteidigungsschicht gehalten hat, und endet mit `RESULT: all defenses held`. Danach gibt es die passenden Abfragen für Grafana aus. Für die Live-Demo das Dashboard „SOC – DMZ“ offen lassen, am besten die Alarm-Ansicht über den Link „Alarm-Stream live“.

Jedes Skript beginnt mit einem sauberen Zustand der automatischen Reaktion (Sperren aufgehoben, Zähler zurückgesetzt) und stellt den Modus selbst ein. A-1, A-3 und A-4 laufen mit aktiver Reaktion, A-2 misst zuerst die WAF allein im Beobachtungsmodus und wiederholt die Kampagne dann mit aktiver Reaktion. Konzept und Playbooks: [`docs/reaktion.md`](../docs/reaktion.md).

## Übersicht

| ID | Angriff | Herkunft | Geprüfte Schicht |
|---|---|---|---|
| A-1 | Mehrstufig: Portscan, Fingerprinting, Angriff auf die Webanwendung (SQLi, UNION, Path Traversal, XSS, Scanner) | Internet (`attacker`) | `fw-edge` verwirft den Scan, die WAF blockt die Web-Angriffe, das IDS erkennt die ersten drei unabhängig davon am Spiegelport (SID 1000004, 1000001, 1000002, vom Skript geprüft). Nach dem dritten WAF-Block sperrt der Responder den Angreifer an `fw-edge` (P-1), XSS und Scanner laufen ins Leere. |
| A-2 | WAF-Evasion: dieselben Angriffe in vielen Verschleierungen (Groß-/Kleinschreibung, Inline-Kommentare, Kodierung) | Internet (`attacker`) | Teil 1: Widerstandsfähigkeit der WAF allein, das Skript scheitert, sobald eine Variante die Anwendung erreicht. Die Varianten, die CRS auf Paranoia-Stufe 1 durchließ, schließt der virtuelle Patch VP-01 (`configs/waf/REQUEST-899-DMZ-VIRTUAL-PATCHES.conf`, WA-07). Teil 2: dieselbe Kampagne mit aktiver Reaktion, der Angreifer wird nach wenigen Versuchen ausgesperrt. |
| A-3 | Kompromittierter interner Host: Angriff auf das Portal, danach Pivot-Versuche ins DMZ-Innere und ins Backend | Client-Netz (`client1`) | Die WAF behandelt interne Angreifer gleich, `fw-edge` sperrt jeden Pivot (V-03, V-04), bevor er die DMZ erreicht. Nach dem dritten Pivot-Versuch isoliert der Responder `client1` (P-4), die Freigabe erfolgt erst durch den Operator. |
| A-4 | Code in der Webanwendung (Benutzer `app`) baut eine Reverse Shell zu einem C2-Server auf: TCP 4444, dann TCP 443, dann TCP 443 zu einer neuen Adresse | DMZ (`web`) | `fw-dmz` verwirft den Verbindungsaufbau nach außen (V-12), das IDS meldet ihn vom Spiegelport (SID 1000003). Der Responder sperrt den C2-Server für Verbindungen von innen aus dem gesamten Firmennetz (P-5, `egress`), auch den Ausweichweg über 443. Zur neuen Adresse kommen die ersten Antworten durch, dann erkennt das IDS die Befehlsausgabe (SID 1000007) und der Responder kappt die Verbindung vor dem nächsten Befehl. Grenze: Eine Shell in echtem TLS bliebe unsichtbar. |

## Bezug zur Aufgabenstellung

- Mindestens drei Angriffe, davon mindestens einer aus dem Client-Netz (A-3): erfüllt.
- Hoher technischer Schwierigkeitsgrad: A-1 ist mehrstufig, A-2 prüft die Evasion-Resistenz systematisch, A-4 zeigt den Rückkanal eines kompromittierten Servers und die Reaktion darauf.
- Erkennung innerhalb von 1 s im SIEM: Transport bis Loki (S-02 bis S-05) und bis Grafana (S-07) gemessen, Dashboard mit 1 s Aktualisierung, Live-Ansicht ohne Wartezeit (`docs/technologieentscheidungen.md`, E-16).
- Reaktive Maßnahmen: automatische Sperre eines externen Angreifers (A-1, A-2), Isolation eines internen Hosts (A-3) und Sperre eines Command-and-Control-Servers (A-4, P-5), alle mit Anzeige im Dashboard.
- Defense in Depth: Kein einzelner Sensor sieht alles. Den Scan sieht nur die Firewall, die Web-Angriffe WAF und IDS unabhängig voneinander, den Rückkanal eines kompromittierten Servers Firewall, IDS und Responder gemeinsam (A-4). Erst zusammen ergibt sich das vollständige Bild.
- Grenzen transparent gemacht: A-2 nennt die Varianten, die erst der virtuelle Patch schließt, A-4 zeigt, dass die ersten Antworten einer Shell zu einer neuen Adresse durchkommen und echtes TLS die Erkennung verhindern würde. Beide verweisen auf die jeweilige Verbesserung (sicherer Anwendungscode, feste Ausgangsziele der DMZ).
