# Kommunikationsmatrix – DMZ-Laborumgebung

Stand: 2026-11-02, Version 0.2 (passend zu Netzplan 0.2, Adressplan 0.2 und den Regelwerken in `configs/fw-*`)

## Grundsätze

- Whitelisting.
- Die Tabelle nennt den Verbindungsaufbau. Antworten auf bestehende Verbindungen sind erlaubt.
- `fw-edge` und `fw-dmz` protokollieren verworfene Pakete und melden sie an das SIEM. Umsetzung in Phase 4, bis dahin zählen die Regelwerke verworfene Pakete nur.
- Kein DNS nur IP-Adressen

## Erlaubte Verbindungen

| ID | Quelle | Ziel | Dienst | Filternde Systeme | Zweck | Anforderung |
|---|---|---|---|---|---|---|
| K-01 | Internet (beliebig) | 203.0.113.2, umgesetzt auf `proxy` 10.10.10.2 | TCP 443, TCP 80 nur als Umleitung | `fw-edge`, `fw-dmz` | Zugriff auf die Webanwendung von außen | SYS-02, A-01 |
| K-02 | `proxy` | `waf` 10.10.10.6 | TCP 8080 | `fw-dmz` | Weitergabe der Anfrage zur Prüfung | SYS-04 |
| K-03 | `waf` | `web` 10.10.10.10 | TCP 8080 | `fw-dmz` | Weitergabe der geprüften Anfrage | SYS-05 |
| K-04 | Client-Netz 10.10.20.0/24 | `proxy` 10.10.10.2 | TCP 443 | `fw-edge`, `fw-dmz` | Zugriff auf die Webanwendung von intern | SYS-05, NET-02 |
| K-05 | Client-Netz 10.10.20.0/24 | Internet | TCP 80, TCP 443, ICMP Echo | `fw-edge` (Quellumsetzung) | Internetzugang der Clients | NET-06 |
| K-06 | DMZ 10.10.10.0/24 | Internet | TCP 80, TCP 443, ICMP Echo | `fw-dmz`, `fw-edge` (Quellumsetzung) | Internetzugang der DMZ-Systeme, z. B. für Aktualisierungen. Die Aufgabenstellung verlangt, dass das Internet von der DMZ aus erreichbar ist. Alle übrigen Dienste sperrt V-12. | NET-06 |
| K-07 | `ro-client1` 198.51.100.2, `ro-client2` 198.51.100.6 | `fw-edge` 203.0.113.2 | UDP 51820 | `fw-edge` | Aufbau des VPN-Tunnels | NET-05 |
| K-08 | Remote Office im Tunnel, 10.99.0.2 und 10.99.0.3 | `proxy` 10.10.10.2 | TCP 443 | `fw-edge`, `fw-dmz` | Zugriff auf die Webanwendung über VPN. Vorläufig, weitere Ziele offen. | NET-05 |
| K-09 | `ids` 10.10.10.14, `waf` 10.10.10.6 | `siem` 10.10.30.10 | UDP 5140 (Syslog) | `fw-dmz`, `fw-edge`, `fw-backend` | Meldung erkannter Angriffe | MON-02 |
| K-10 | `fw-dmz` 10.10.0.2 | `siem` 10.10.30.10 | UDP 5140 (Syslog) | `fw-edge`, `fw-backend` | Meldung verworfener Pakete | MON-02 |
| K-11 | `fw-edge` 10.10.0.9 | `siem` 10.10.30.10 | UDP 5140 (Syslog) | `fw-backend` | Meldung verworfener Pakete | MON-02 |
| K-12 | Browser des Operators | `siem` | TCP 3000 (Grafana) | offen | Anzeige für das SOC. Zugangsweg offen: Die Knoten haben kein Management-Netz (`network-mode: none`). Klärung beim Aufbau des SIEM. | MON-03 |
| K-13 | `siem` | `fw-edge` | offen | `fw-backend` | Reaktive Sperre, zurückgestellt | SEC-04, A-06 |

## Verbotene Verbindungen

Die Liste ist eine Auswahl. Jede Zeile ist ein Testfall für Phase 3 und ein möglicher Ansatzpunkt für einen Angriff.

| ID | Quelle | Ziel | Begründung |
|---|---|---|---|
| V-01 | Internet | Client-Netz, Backend-Netz | Kein Dienst für außen. |
| V-02 | Internet | `waf`, `web`, `ids` direkt | Der einzige Eingang ist `proxy`. |
| V-03 | Client-Netz | `waf`, `web`, `ids` direkt | Auch interne Zugriffe laufen über `proxy` und `waf`. |
| V-04 | Client-Netz | Backend-Netz | Das SIEM ist für Clients nicht erreichbar. |
| V-05 | `web` | `proxy`, `waf`, `ids` | Ein kompromittierter Webserver erreicht keine Nachbarn. |
| V-06 | DMZ | Client-Netz | Kein Verbindungsaufbau aus der DMZ nach innen. |
| V-07 | DMZ | Backend-Netz, außer K-09 und K-10 | Nur Meldungen erreichen das SIEM. |
| V-08 | Backend-Netz | Internet | Entscheidung A-05. |
| V-09 | – | – | Entfällt seit Version 0.2. Ersetzt durch K-06 (DMZ → Internet nur TCP 80, TCP 443 und ICMP Echo) und V-12 (alle übrigen Dienste). |
| V-10 | Remote Office im Tunnel | Client-Netz, Backend-Netz | Der Tunnel öffnet vorerst nur die Webanwendung. |
| V-11 | beliebig | Spiegelport von `ids` | Schnittstelle ohne Adresse. |
| V-12 | DMZ (alle Systeme) | Internet auf anderen Diensten als K-06, z. B. TCP 22 oder TCP 4444 | Typische Wege für Reverse Shells und Datenabfluss. `fw-dmz` verwirft die Verbindung, das IDS meldet den Versuch trotzdem (SID 1000003). |

## Filterpunkte

| System | Aufgabe |
|---|---|
| `fw-edge` | Übergänge zwischen Internet, DMZ, Client-Netz, Backend-Netz und Tunnel. Adressumsetzung. VPN-Endpunkt. |
| `fw-dmz` | Eingang und Ausgang der DMZ. Jeder Verkehr zwischen zwei DMZ-Systemen. |
| `fw-backend` | Lässt nur K-09 bis K-11 hinein. Lässt nichts hinaus. |
| `router-int` | Routet nur. Die Filterung des Client-Netzes liegt bei `fw-edge`. |

## Festlegungen

1. Die Verschlüsselung (TLS) endet am `proxy`. Zwischen `proxy`, `waf` und `web` läuft HTTP. Nur so liest das IDS den Inhalt der Anfragen.
2. Interne Clients und die VPN-Clients sprechen `proxy` unter 10.10.10.2 an, nicht unter der öffentlichen Adresse.
3. Restrisiko von K-06: Ein kompromittierter Webserver kann über TCP 80 und 443 Daten hinausschicken oder Schadcode nachladen. Gegenmaßnahmen sind die Erkennung durch das IDS und die Meldung an das SIEM. Eine Beschränkung auf feste Ziele, z. B. die Paketquellen, ist eine mögliche Verbesserung.

## Testabdeckung

| Test | Geprüfte IDs |
|---|---|
| `tests/test-matrix.sh` | K-01 bis K-06, K-09, V-01 bis V-08, V-12 |
| `tests/test-ids.sh` | V-11 (I-01), V-12 mit Erkennung (I-05) |
| `tests/test-proxy.sh` | K-01 bis K-04 Ende zu Ende |
| noch offen | K-07, K-08, V-10 (VPN), K-10, K-11 (Phase 4), K-12, K-13 |


