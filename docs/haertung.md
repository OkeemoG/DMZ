# Härtung der Sicherheitssysteme – DMZ-Laborumgebung

Stand: 2026-11-05, Version 0.1, Phase 5. Anforderung der Aufgabenstellung: „Die Sicherheits-Systeme sind mittels Sicherheitsmaßnahmen gegenüber Angriffen gehärtet, deren Wirksamkeit überprüft wird.“

## Vorgehen

1. Bestandsaufnahme: Mit welchen Rechten laufen die Systeme, welche Dienste und Verbindungen sind offen, was ist schon gehärtet?
2. Maßnahmen je System nach dem Prinzip der minimalen Rechte. Orientierung: BSI IT-Grundschutz-Kompendium, Baustein SYS.1.6 Containerisierung, und CIS Docker Benchmark.
3. Für jede Maßnahme ein Test, der ihre Wirkung zeigt, nicht nur die Einstellung (`make test-hardening`, H-01 bis H-09).

## Bestandsaufnahme

| Befund | Risiko |
|---|---|
| Containerlab startet jeden Knoten der Art `linux` privilegiert (`PrivilegedByDefault`, Quelle: `nodes/node_registry.go` in Containerlab 0.82). Das betraf auch `web`, `proxy`, `waf`, `ids` und die SIEM-Dienste. | Ein Angreifer mit Codeausführung im Webserver hat alle Rechte des Hosts: Geräte, Dateisysteme, Kernelmodule. Der Ausbruch aus dem Container ist trivial. |
| Die Firewalls dürfen selbst beliebig nach außen senden (`output` mit `policy accept`). | Ein kompromittierter Dienst auf einer Firewall (IKE, `sshd`) kann Daten abfließen lassen oder nachladen. |
| Kernel-Einstellungen der Router und Server unverändert, `ip_forward` vom Host geerbt. | ICMP-Redirects und Source-Routing können Verkehr umleiten. DMZ-Server leiten Pakete weiter. |
| Suricata läuft ohne Überwachung, `eve.json` wächst unbegrenzt (offener Punkt 13, R-05). | Ein Absturz des IDS bleibt unbemerkt, die Disk läuft voll. |
| Grafana mit Standardpasswort `dmz-soc` aus dem Repo. | Jeder mit Zugang zum Repo kennt das Passwort des SOC. |
| Das Image `waf` wechselt für `apk` auf root und bleibt dabei. | Der Nginx-Master der WAF läuft als root, obwohl das Upstream-Image ohne root gedacht ist. |
| Proxy ohne Zeitlimits für Kopf und Körper einer Anfrage. | Slowloris: wenige langsame Verbindungen blockieren den Proxy. |
| Docker-Logs der Container ohne Größengrenze. | Die Disk der VM (R-08) läuft voll. |

Bereits umgesetzt und getestet waren: TLS 1.3 nach BSI TR-02102-2 (P-07), Ratenbegrenzung (P-08), keine Versionsangaben (P-06, WA-06), Webanwendung ohne root (W-00), Loki nur lokal (S-01), Whitelisting der Firewalls (test-matrix), VPN nach TR-02102-3 (N-09), Kanal K-13 nach TR-02102-4 (RE-01), Anti-Spoofing (RE-10).

## Maßnahmen

### Container-Isolierung (H-01 bis H-03)

Die Topologie fasst die Knoten in drei Gruppen zusammen (`topology/dmz.clab.yml`, Abschnitt `groups`):

| Gruppe | Knoten | Rechte |
|---|---|---|
| `router` | `fw-edge`, `fw-dmz`, `fw-backend`, `router-int` | nicht privilegiert, zusätzlich `NET_ADMIN` und `NET_RAW` für nftables, tc, XFRM und NFLOG, `no-new-privileges` |
| `dmz` | `proxy`, `waf`, `web`, `ids` | nicht privilegiert, zusätzlich `NET_ADMIN` zum Setzen der Adressen, `ids` dazu `NET_RAW` für den Spiegelport, `no-new-privileges` |
| `siem` | `siem-collector`, `siem-loki`, `siem-grafana`, `siem-responder` | nicht privilegiert, keine zusätzlichen Rechte, `no-new-privileges` |

Dazu laufen die Dienste ohne root: WAF (`USER nginx` wie im Upstream-Image), Fluent Bit (`65534`), Loki, Grafana, Responder (`su-exec`). Webanwendung und Proxy geben root nach dem Start an `app` bzw. `nginx` ab.

Bewusst privilegiert bleiben `inet`, `attacker`, `client1`, `ro-client1`, `ro-client2` (sie bilden Internet und Endgeräte nach, gehören nicht zur geschützten Umgebung) und `siem` (hält nur Adresse und Routen, führt nur `sleep` aus und muss IPv6 auf `eth0` abschalten, was ohne Privilegien nicht geht).

`NET_ADMIN` in den DMZ-Servern ist ein Restrisiko: Ein Angreifer könnte Adressen und Routen des Servers ändern. Die Wirkung ist begrenzt, weil `fw-dmz` Absender an die Schnittstelle bindet und `fw-edge` gefälschte Absender verwirft (E-19). Ohne `NET_ADMIN` müsste ein Hilfscontainer die Adressen von außen setzen, was Containerlab nicht vorsieht.

Wirkung (H-03, Root-Shell im Webserver): Einhängen von Dateisystemen, Schreiben von Kernelparametern und `sysrq` werden verweigert, Datenträger des Hosts sind nicht sichtbar. Zum Vergleich gelingt das Einhängen im weiterhin privilegierten `inet`.

### Kernel-Einstellungen (H-04)

Für die Gruppen `router` und `dmz` über `sysctls`: keine ICMP-Redirects annehmen oder senden, kein Source-Routing, SYN-Cookies, ICMP-Broadcasts und fehlerhafte ICMP-Antworten ignorieren. Die Werte gelten für `all` und `default`, damit auch die später von Containerlab angelegten Schnittstellen sie erhalten. Router leiten weiter (`ip_forward` 1).

Zwei Funde aus dem ersten Lauf in der VM:

- Ein neuer Netz-Namespace erbt die IPv4-Einstellungen des Hosts, auf dem Docker-Host also `ip_forward` 1. Wer `ip_forward` schreibt, setzt im Kernel zugleich `accept_redirects` für `all` zurück (`inet_forward_change`: Redirects nur annehmen, wenn nicht weitergeleitet wird). runc setzt die `sysctls` in zufälliger Reihenfolge, damit stand `accept_redirects` mal auf 0, mal auf 1. Die DMZ-Server schalten die Weiterleitung deshalb über `conf.default.forwarding` 0 ab, das gilt für `eth1` und lässt `all` unberührt.
- Docker verwaltet `disable_ipv6` beim Aufbau des Netz-Namespace selbst. Die gesetzten Werte kamen nicht verlässlich an. IPv6 wird im Labor nicht genutzt, alle Firewalls verwerfen es (Tabellen `inet`, `policy drop` in `input` und `forward`). Die beiden Spiegelports (`ids` `eth2`, `fw-dmz` `eth6`) erhalten über `ip link set … addrgenmode none` sicher keine IPv6-Adresse (V-11), dafür genügt `NET_ADMIN`.

### Ausgehender Verkehr der Firewalls (H-05)

Die Kette `output` steht auf allen drei Firewalls auf `policy drop`. Erlaubt sind nur:

| Firewall | Erlaubt | Grund |
|---|---|---|
| alle | Loopback, Antworten auf bestehende Verbindungen, ICMP Echo Request | Betrieb, Diagnose |
| `fw-edge` | UDP 5140 an `siem` von 10.10.0.9 | K-11 |
| `fw-edge` | IKE UDP 500 und ESP an die beiden VPN-Gegenstellen | K-07, Neuverhandlung und verschlüsselter Verkehr nach der Verschlüsselung |
| `fw-dmz` | UDP 5140 an `siem` von 10.10.0.2 | K-10 |

Verworfene Pakete melden `fw-edge` und `fw-dmz` gedrosselt als `output drop` an das SIEM. Eine Firewall, die selbst nach außen will, ist ein deutliches Zeichen für eine Kompromittierung. Vorab mit echtem nftables geprüft: Meldungen, IKE und ESP an die Gegenstellen gehen hinaus, alles andere nicht.

### IDS (H-06)

`configs/ids/ids-start.sh` startet zwei Schleifen:

- `ids-watchdog.sh` startet Suricata im Vordergrund und nach jedem Ende nach 2 s neu. Jeder Neustart geht als Meldung `ids-watchdog` an das SIEM.
- `ids-logguard.sh` prüft alle 30 s die Logdateien von Suricata und leert eine Datei, die größer als 50 MB ist (`IDS_LOG_MAX_MB`). Auch das geht an das SIEM. Die Alarme liegen ohnehin im SIEM, die lokale Datei dient nur Tests und Beweissicherung.

### Proxy (H-08)

`client_header_timeout` und `client_body_timeout` 5 s, `send_timeout` 10 s, `keepalive_timeout` 15 s, Verbindungen nach Zeitüberschreitung werden hart zurückgesetzt, höchstens 50 gleichzeitige Anfragen je Adresse (`limit_conn`). Vorab mit Nginx 1.28 geprüft: Eine Verbindung mit unvollständigem Kopf wird nach 5,0 s geschlossen.

### SIEM (H-09)

- `make pki` erzeugt ein zufälliges Grafana-Passwort (24 Byte, hexadezimal) in `configs/siem/secrets/grafana.env`, Rechte 600, nicht im Repo. Anzeigen: `make grafana-password`.
- Grafana: kein anonymer Zugriff, keine Gravatar-Abfragen, keine externen Snapshots, `SameSite=strict` für Cookies, Content Security Policy und die Header `X-Content-Type-Options` und `X-Frame-Options`.

### Host (H-07)

`scripts/harden-host.sh` (`make host-hardening`, auch in `install.sh`) begrenzt die Docker-Logs jedes Containers auf 3 Dateien zu 10 MB. Eine vorhandene `/etc/docker/daemon.json` wird ergänzt, nicht ersetzt. Wirksam nach Neustart von Docker und `make deploy`.

## Tests

`make test-hardening` (`tests/test-hardening.sh`):

| ID | Prüft |
|---|---|
| H-01 | Alle zwölf gehärteten Container nicht privilegiert, `no-new-privileges` aktiv, ohne `SYS_ADMIN`, `SYS_MODULE`, `SYS_RAWIO`, `SYS_PTRACE`, `DAC_READ_SEARCH`, `NET_ADMIN` nur wo nötig |
| H-02 | WAF, Fluent Bit, Loki, Grafana und Responder ohne root, Worker von Webanwendung und Proxy ohne root |
| H-03 | Ausbruchsversuche aus einer Root-Shell im Webserver scheitern |
| H-04 | Kernel-Einstellungen auf Routern und Servern (`all` und `eth1`), DMZ-Server leiten auf `eth1` nicht weiter, Spiegelports ohne Adresse, Firewalls verwerfen auch IPv6 |
| H-05 | Output-Ketten: `fw-edge` und `fw-dmz` erreichen das Internet nicht selbst, Zähler und Meldung im SIEM, VPN und K-13 funktionieren weiter |
| H-06 | Suricata wird nach einem `kill -9` neu gestartet, der Neustart erscheint im SIEM, danach erkennt das IDS wieder Angriffe. Eine Logdatei über 50 MB wird geleert und gemeldet. |
| H-07 | Docker-Logs mit Größengrenze |
| H-08 | Slowloris: unvollständiger Kopf nach dem Zeitlimit geschlossen (gemessen beim Ende des Clients), Zeitlimits und Verbindungsgrenze aktiv |
| H-09 | Altes Standardpasswort abgewiesen, neues angenommen, ohne Anmeldung kein Zugriff, Passwortdatei geschützt und nicht im Repo, Sicherheits-Header |

## Grenzen und mögliche Verbesserungen

- Containerlab bietet weder `cap-drop` noch ein schreibgeschütztes Dateisystem an. Die Standardrechte von Docker (z. B. `CHOWN`, `DAC_OVERRIDE`, `SETUID`) bleiben deshalb erhalten. Die Dienste laufen trotzdem größtenteils ohne root, damit greifen diese Rechte nicht.
- Kein eigenes Seccomp- oder AppArmor-Profil, es gelten die Standardprofile von Docker.
- Keine Prüfung der Images auf bekannte Schwachstellen. Verbesserung: Trivy oder Grype im Build (`make images`).
- Grafana spricht HTTP. Der Zugang liegt im eigenen Out-of-Band-Netz der VM (E-15), TLS wäre die nächste Stufe.
- Kein User-Namespace-Remapping für Docker. Es würde den Ausbruch aus den weiterhin privilegierten Knoten erschweren, verlangt aber eine Umstellung des Docker-Hosts.
- Die Webanwendung bleibt für die Angriffe im verwundbaren Modus. Der sichere Modus (`APP_MODE=secure`, W-03) ist die Härtung der Anwendung selbst und Teil von `make recover`.

## Quellen

- BSI: IT-Grundschutz-Kompendium, Baustein SYS.1.6 Containerisierung. https://www.bsi.bund.de/DE/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/IT-Grundschutz/IT-Grundschutz-Kompendium/it-grundschutz-kompendium_node.html
- Center for Internet Security: CIS Docker Benchmark. https://www.cisecurity.org/benchmark/docker
- Containerlab 0.82: Knotenparameter `privileged`, `cap-add`, `security-opts`, `sysctls`, `groups`. https://containerlab.dev/manual/nodes/
- OWASP CRS-Projekt: modsecurity-crs-docker, `nginx/Dockerfile-alpine` (`USER nginx`). https://github.com/coreruleset/modsecurity-crs-docker
- Nginx: Modul `ngx_http_core_module` (`client_header_timeout`, `reset_timedout_connection`) und `ngx_http_limit_conn_module`. https://nginx.org/en/docs/
- Linux-Kernel: Dokumentation `ip-sysctl` (`accept_redirects`, `accept_source_route`, `tcp_syncookies`, `devconf_inherit_init_net`). https://docs.kernel.org/networking/ip-sysctl.html
