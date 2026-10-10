# Obliguard

**Self-hosted, agent-based intrusion prevention: detect a brute-force attack once, ban it everywhere.**

Obliguard agents read the authentication logs of your servers (SSH, RDP, web servers, mail, databases and more). The server decides which IPs to ban and pushes the bans to the firewall of every agent at once. It is built for administrators and MSPs who protect fleets of internet-exposed servers.

Website: [guard.obli.tools](https://guard.obli.tools)

## Key features

- **Ban engine**: per-template thresholds and time windows, automatic or manual bans scoped globally, per tenant, group or agent, escalating ban durations, and safeguards against banning your own addresses.
- **Built-in log parsers**: SSH, RDP, Nginx, Apache, IIS, FTP, mail, MySQL, MikroTik and OPNsense, plus custom regex templates.
- **Firewall enforcement on the agent**: nftables, firewalld, ufw or iptables on Linux; WFP or netsh on Windows; pf on macOS, FreeBSD and OPNsense. Host firewall rules can also be managed from the panel.
- **IP reputation**: GeoIP, attempted usernames, history and CSV exports.
- **Whitelist and blocklists**: CIDR whitelist and remote blocklists from URLs.
- **Live views**: 2D and 3D network maps and a live event stream.
- **Integrations**: MikroTik syslog ingest and address-list sync, Microsoft 365 sign-in protection, network rate-limit policies (nftables / iptables / ufw).
- **Platform**: multi-tenancy, permission sets, step-up confirmation for destructive actions, audit log, paced agent updates, 10 notification channels, 18 UI languages.

## Quick install

```sh
curl -fsSL https://raw.githubusercontent.com/obli-tools/Obliguard/main/install.sh | sh
```

The installer runs on Linux, or on macOS with Docker Desktop. It:

- checks Docker and Docker Compose; on Linux it offers to install them with Docker's official script, only after you confirm;
- downloads `docker-compose.yml` and `.env.example` into `./obliguard`;
- creates `.env` with unique random secrets (`DB_PASSWORD`, `SESSION_SECRET`, initial admin password);
- pulls the images, starts the stack and prints the panel URL and the initial admin password (shown only once).

Running it again upgrades an existing install; `.env` is never modified.

Options (pass them after `sh -s --`):

| Option | Description |
|--------|-------------|
| `-y`, `--yes` | Non-interactive: accept the defaults and install Docker if it is missing |
| `--dir PATH` | Install directory (default `./obliguard`) |
| `--port PORT` | Host port of the web interface (default `3001`, first install only) |
| `--url URL` | Public URL of the panel, e.g. `https://obliguard.example.com` (first install only) |

```sh
curl -fsSL https://raw.githubusercontent.com/obli-tools/Obliguard/main/install.sh | sh -s -- -y --dir /opt/obliguard --url https://obliguard.example.com
```

`--help` lists every option.

## Manual install (Docker Compose)

```sh
mkdir obliguard && cd obliguard
curl -fsSLO https://raw.githubusercontent.com/obli-tools/Obliguard/main/docker-compose.yml
curl -fsSLO https://raw.githubusercontent.com/obli-tools/Obliguard/main/.env.example
cp .env.example .env
mkdir -p custom
# Edit .env: set DB_PASSWORD, SESSION_SECRET (required, 32+ characters),
# DEFAULT_ADMIN_PASSWORD and CLIENT_ORIGIN (the public URL of the panel).
docker compose up -d
```

The panel answers on port `3001` (`LISTEN_PORT`). The stack runs PostgreSQL 16, the server (`meejay/obliguard-server`) and the web client (`meejay/obliguard-client`). To use an existing PostgreSQL server instead, see `docker-compose.external-db.yml`.

## Update

```sh
docker compose pull && docker compose up -d
```

Or run the installer again from the same directory.

## Installing agents

Agents are installed from the panel: install commands for Linux, macOS and FreeBSD / OPNsense, and an MSI for Windows. New agents wait for approval.

## Requirements

- A Linux host (or macOS with Docker Desktop) with Docker Engine and Docker Compose v2.
- **HTTPS is required for sign-in**: production session cookies are HTTPS-only, so a sign-in over plain HTTP does not stick. Put a TLS reverse proxy in front (sending `X-Forwarded-Proto: https`), set `CLIENT_ORIGIN` in `.env` to its `https://` address and `TRUSTED_PROXY_HOPS=2`, then run `docker compose up -d` again.
- Add your own public addresses (NAT, reverse proxy, SSO server) to `BAN_PROTECTED_IPS` in `.env` so they can never be banned.

## Single sign-on

Obliguard supports single sign-on with [Obligate](https://github.com/obli-tools/Obligate): register Obliguard as an app in Obligate, then enter the Obligate URL and API key in the Obliguard settings. Local accounts keep working alongside SSO.

## Part of the Obli suite

| Tool | Purpose |
|------|---------|
| [Obliance](https://ance.obli.tools) | Remote monitoring and management (RMM) |
| [Oblireach](https://reach.obli.tools) | Remote screen access and remote support |
| [Obliview](https://view.obli.tools) | Uptime and infrastructure monitoring |
| [Oblimap](https://map.obli.tools) | IPAM and network discovery |
| **[Obliguard](https://guard.obli.tools)** | Agent-based intrusion prevention |
| [Obligate](https://gate.obli.tools) | Single sign-on and access management for the suite |
| [Oblihub](https://hub.obli.tools) | Docker control panel |
| [Obliwan](https://github.com/obli-tools/Obliwan) | WAN router fleet management |
| [ObliDesk](https://github.com/obli-tools/ObliDesk) | Ticketing and service desk |
| [Obliplan](https://github.com/obli-tools/Obliplan) | Workforce scheduling and working-time tracking |
| [Oblifield](https://field.obli.tools) | Field intervention management |

Suite home: [obli.tools](https://obli.tools)

## License

Obliguard is source-available under the [Elastic License 2.0](LICENSE) (ELv2). You may use, modify and self-host it, including for commercial use inside your organization; you may not provide it to others as a hosted or managed service. See [LICENSE](LICENSE) for the full terms and the obli.tools clarifications.
