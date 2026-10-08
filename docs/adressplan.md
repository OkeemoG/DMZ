# Adressplan – DMZ

Stand: 2026-10-08, Version 0.1 (Entwurf, passend zu `DMZ_Netzplan_0.2.drawio`)

## Regeln

- Das Gateway erhält die erste Adresse des Subnetzes. Hosts beginnen bei `.10`.
- Das dritte Oktett kennzeichnet die Zone: 0 Transit, 10 DMZ, 20 Client, 30 Backend.
- `eth0` gehört dem Management-Netz von Containerlab. Eigene Links beginnen bei `eth1`.
- Jeder Link verbindet genau zwei Knoten .
- Die Internet-Adressen stammen aus den Dokumentationsbereichen nach RFC 5737.

## Subnetze

| Netz | Subnetz | Knoten |
|---|---|---|
| Internet, Angreifer | 192.0.2.0/24 | `inet` – `attacker` |
| Internet, Uplink Firma | 203.0.113.0/30 | `inet` – `fw-edge` |
| Internet, Uplink Remote Office 1 | 198.51.100.0/30 | `inet` – `ro-client1` |
| Internet, Uplink Remote Office 2 | 198.51.100.4/30 | `inet` – `ro-client2` |
| Transit DMZ | 10.10.0.0/30 | `fw-edge` – `fw-dmz` |
| Transit Client | 10.10.0.4/30 | `fw-edge` – `router-int` |
| Transit Backend | 10.10.0.8/30 | `fw-edge` – `fw-backend` |
| DMZ, Reverse-Proxy | 10.10.10.0/30 | `fw-dmz` – `proxy` |
| DMZ, WAF | 10.10.10.4/30 | `fw-dmz` – `waf` |
| DMZ, Webserver | 10.10.10.8/30 | `fw-dmz` – `web` |
| DMZ, IDS | 10.10.10.12/30 | `fw-dmz` – `ids` |
| DMZ, Spiegelport | ohne Adresse | `fw-dmz` – `ids` |
| Client-Netz | 10.10.20.0/24 | `router-int` – `client1` |
| Backend-Netz | 10.10.30.0/24 | `fw-backend` – `siem` |
| VPN-Tunnel | 10.99.0.0/24 | `fw-edge` – `ro-client1`, `ro-client2` |
| Management (reserviert) | 172.20.20.0/24 | von Containerlab vergeben, alle Knoten |

Die gesamte DMZ ist als 10.10.10.0/24 zusammenfassbar. Das gesamte Firmennetz ist als 10.10.0.0/16 zusammenfassbar.

## Schnittstellen

### Internet und Remote Office

| Knoten | Schnittstelle | Adresse | Gegenstelle |
|---|---|---|---|
| `inet` | eth1 | 203.0.113.1/30 | `fw-edge` eth1 |
| `inet` | eth2 | 198.51.100.1/30 | `ro-client1` eth1 |
| `inet` | eth3 | 192.0.2.1/24 | `attacker` eth1 |
| `inet` | eth4 | 198.51.100.5/30 | `ro-client2` eth1 |
| `attacker` | eth1 | 192.0.2.10/24 | `inet` eth3 |
| `ro-client1` | eth1 | 198.51.100.2/30 | `inet` eth2 |
| `ro-client1` | Tunnel | 10.99.0.2/24 | `fw-edge` Tunnel |
| `ro-client2` | eth1 | 198.51.100.6/30 | `inet` eth4 |
| `ro-client2` | Tunnel | 10.99.0.3/24 | `fw-edge` Tunnel |

### Firmennetz, Übergänge

| Knoten | Schnittstelle | Adresse | Gegenstelle |
|---|---|---|---|
| `fw-edge` | eth1 | 203.0.113.2/30 | `inet` eth1 |
| `fw-edge` | eth2 | 10.10.0.1/30 | `fw-dmz` eth1 |
| `fw-edge` | eth3 | 10.10.0.5/30 | `router-int` eth1 |
| `fw-edge` | eth4 | 10.10.0.9/30 | `fw-backend` eth1 |
| `fw-edge` | Tunnel | 10.99.0.1/24 | `ro-client1`, `ro-client2` Tunnel |

### DMZ

| Knoten | Schnittstelle | Adresse | Gegenstelle |
|---|---|---|---|
| `fw-dmz` | eth1 | 10.10.0.2/30 | `fw-edge` eth2 |
| `fw-dmz` | eth2 | 10.10.10.1/30 | `proxy` eth1 |
| `fw-dmz` | eth3 | 10.10.10.5/30 | `waf` eth1 |
| `fw-dmz` | eth4 | 10.10.10.9/30 | `web` eth1 |
| `fw-dmz` | eth5 | 10.10.10.13/30 | `ids` eth1 |
| `fw-dmz` | eth6 | ohne Adresse (Spiegelausgang) | `ids` eth2 |
| `proxy` | eth1 | 10.10.10.2/30 | `fw-dmz` eth2 |
| `waf` | eth1 | 10.10.10.6/30 | `fw-dmz` eth3 |
| `web` | eth1 | 10.10.10.10/30 | `fw-dmz` eth4 |
| `ids` | eth1 | 10.10.10.14/30 | `fw-dmz` eth5 |
| `ids` | eth2 | ohne Adresse (Mitschnitt) | `fw-dmz` eth6 |

### Client-Netz

| Knoten | Schnittstelle | Adresse | Gegenstelle |
|---|---|---|---|
| `router-int` | eth1 | 10.10.0.6/30 | `fw-edge` eth3 |
| `router-int` | eth2 | 10.10.20.1/24 | `client1` eth1 |
| `client1` | eth1 | 10.10.20.10/24 | `router-int` eth2 |

### Backend-Netz

| Knoten | Schnittstelle | Adresse | Gegenstelle |
|---|---|---|---|
| `fw-backend` | eth1 | 10.10.0.10/30 | `fw-edge` eth4 |
| `fw-backend` | eth2 | 10.10.30.1/24 | `siem` eth1 |
| `siem` | eth1 | 10.10.30.10/24 | `fw-backend` eth2 |

## Routen

| Knoten | Ziel | Nächster Hop |
|---|---|---|
| `attacker` | Standard | 192.0.2.1 |
| `inet` | keine Routen in 10.0.0.0/8 | – |
| `ro-client1` | Standard | 198.51.100.1 |
| `ro-client2` | Standard | 198.51.100.5 |
| `ro-client1`, `ro-client2` | 10.10.0.0/16 | Tunnel |
| `fw-edge` | Standard | 203.0.113.1 |
| `fw-edge` | 10.10.10.0/24 | 10.10.0.2 |
| `fw-edge` | 10.10.20.0/24 | 10.10.0.6 |
| `fw-edge` | 10.10.30.0/24 | 10.10.0.10 |
| `fw-dmz` | Standard | 10.10.0.1 |
| `router-int` | Standard | 10.10.0.5 |
| `fw-backend` | Standard | 10.10.0.9 |
| `proxy`, `waf`, `web`, `ids` | Standard | Gateway des eigenen /30 |
| `client1` | Standard | 10.10.20.1 |
| `siem` | Standard | 10.10.30.1 |

Die Clients des Remote Office schicken nur Verkehr für das Firmennetz durch den Tunnel. Der übrige Verkehr geht direkt ins Internet.

## Adressumsetzung an `fw-edge`

| Richtung | Umsetzung |
|---|---|
| Internet → Webanwendung | Ziel 203.0.113.2 wird auf `proxy` 10.10.10.2 umgesetzt |
| Client-Netz → Internet | Quelle wird auf 203.0.113.2 umgesetzt |

Grund: `inet` kennt keine privaten Netze. Ohne Umsetzung findet keine Antwort den Rückweg.