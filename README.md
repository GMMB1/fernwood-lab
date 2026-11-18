# Fernwood Lab - a hands-on bug bounty training lab

Fernwood Travel is a **fictional company** with a deliberately vulnerable website,
login server, partner tools and internal network. You attack it on your own computer
to practise real bug classes, step by step. Each station gives you a **flag** only when
you reach the real impact, not when you merely spot the bug.

> ⚠️ **Intentionally vulnerable.** Run it only on your own computer or a classroom
> network you control. Never expose it to the internet. By default it listens on
> `localhost` only.

> 🙈 **Spoiler warning:** the source code contains the answers and the flags. Solve the
> stations in the browser first, and read the code afterwards.

## What you can practise

| Station | Bug class |
|---|---|
| R0 | Recon: a hidden API route in the JavaScript bundle |
| A1 | Open redirect |
| A2 | SSRF past a URL filter |
| A3 | SSRF through an API gateway (stretch) |
| B1 | IDOR / broken access control |
| B2 | Web cache deception |
| B3 | OAuth authorization-code theft |
| C1 | Chain: open redirect to XSS |

Goals and hints for every station are on the lab dashboard.

## Requirements

- **Windows 10/11, macOS or Linux** with **Docker**:
  - Windows / macOS: install **Docker Desktop** - https://www.docker.com/products/docker-desktop/
    (on Windows it uses WSL 2; accept its setup steps and restart if asked).
  - Linux: Docker Engine with the Compose plugin.
- About **4 GB of free RAM** and **1 GB of disk**.
- Internet for the first start only (it downloads the base images).

Check Docker works (in PowerShell, CMD or a terminal):

```
docker --version
docker compose version
```

## Install and start

1. Download the lab - either:
   - `git clone https://github.com/GMMB1/fernwood-lab.git`, or
   - on GitHub click **Code → Download ZIP** and unzip it.
2. Open a terminal **inside the `fernwood-lab` folder** and run:

   ```
   docker compose up -d --build
   ```

   The first start takes a few minutes.
3. Open the dashboard in your browser: **http://localhost:8088**

## Everyday commands

Run them inside the `fernwood-lab` folder.

| What | Command |
|---|---|
| Start | `docker compose up -d --build` |
| Stop (keeps your accounts and flags) | `docker compose down` |
| Reset everything (deletes accounts, bookings and scores) | `docker compose down -v` then `docker compose up -d --build` |
| See if everything runs | `docker compose ps` |
| See the logs | `docker compose logs -f --tail=50` |

## The lab's addresses

| Address | What it is |
|---|---|
| http://localhost:8088 | **Dashboard**: stations, hints, victim simulator, flag submission, scoreboard |
| http://localhost:8080 | Fernwood website |
| http://localhost:8081 | Fernwood ID (login server) |
| http://localhost:8082 | Partner link checker |
| http://localhost:8083 | Partner API gateway |
| http://localhost:9000 | **Your attacker box** (dark red pages) |

Rules inside the lab:
- Register your own accounts with **fake data**.
- **alice** is a simulated victim. Send her links from the dashboard's *Victim simulator*.
  On a real bug bounty program the victim is always **your own second account**, never a
  real user.
- Dark red pages are the attacker's side. Fernwood's own pages never look like that.

## Hosting the lab for a whole class (instructors)

Run it on one laptop and let everyone connect over the classroom network:

- Linux / macOS: `LAB_BIND=0.0.0.0 docker compose up -d --build`
- Windows PowerShell: `$env:LAB_BIND="0.0.0.0"; docker compose up -d --build`

Trainees then open `http://<instructor-laptop-IP>:8088`. Allow ports 8080-8083, 8088 and
9000 in the laptop's firewall. The vulnerable services sit on internal-only Docker
networks; only the nginx edge publishes ports.

## Troubleshooting

| Problem | Fix |
|---|---|
| `docker` is not recognized | Install Docker Desktop and start it (wait until it says "running"). |
| `port is already allocated` | Another program uses that port. Stop it, or close other labs. |
| A page shows an old version | Hard reload: **Ctrl + Shift + R**. |
| Everything is messy | Reset: `docker compose down -v`, then `docker compose up -d --build`. |
| Windows: WSL 2 error | Run `wsl --update` in an admin PowerShell, then restart Docker Desktop. |
