# scopesniffer

⚡ Passive subnet discovery + fast TCP sweep for internal penetration testing

This tool helps you **quickly identify internal scope** on client networks without running intrusive vulnerability scans. It works in two phases:

1. **Passive Harvesting**  
   Uses `tcpdump` to watch live traffic and extract candidate subnets in use (aggregates into `/24`s, then merges into `/23`/`/22` when dense).  
   It can also seed scope from the host’s assigned private subnets and user-supplied hints.

2. **Fast TCP Sweep**  
   Runs aggressive async TCP `connect()` probes (no raw sockets) across discovered ranges to identify responsive hosts on common internal ports.  
   Think of it as a lightweight `masscan`/`nmap -sn` replacement, tuned for large internal ranges.

---

## Features

- 🔎 **Passive scope discovery** via `tcpdump` (requires root or `cap_net_admin`)
- 🖧 **Host subnet seeding** (reads `ip addr` to include locally assigned private ranges)
- 🧾 **Manual hints** (`--hint 10.0.0.0/8`)
- ⚡ **Async TCP connect sweep** (no raw sockets, no vuln checks, safe to run unprivileged)
- 🎛️ **Tunable concurrency & timeouts** (`--concurrency`, `--timeout`)
- 📊 **Live CLI interface**  
  - During tcpdump: time remaining, packets seen, private IP hits, hot `/24`s, merged CIDRs preview  
  - During sweep: IPs processed, responsive hosts, mode
- 📦 **JSON output** (`--json-out alive.json`) for pipeline integration
- 🛡️ **No vulnerability scanning** – strictly scope discovery

---

## Installation

Clone this repo and drop the script:

```bash
git clone https://github.com/yourname/scope-harvester.git
cd scope-harvester
chmod +x scope_harvester.py
