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
```
Requires:

- Python 3.9+
- tcpdump in PATH (for passive harvesting)
- rich (optional, for nicer CLI)

## Usage
Discover only (passive harvest + host subnets, no sweep)
```sudo python3 scope_harvester.py --iface eth0 --watch-seconds 30 --include-host-subnets --only-harvest```

Full flow: harvest + sweep (emit JSON results)
```sudo python3 scope_harvester.py --iface eth0 --include-host-subnets --json-out alive.json```

No packet capture (restricted environments)
```python3 scope_harvester.py --no-tcpdump --include-host-subnets --hint 10.0.0.0/8 --hint 172.16.0.0/12```

Gentler sweep (NIC/VM safe mode)
```python3 scope_harvester.py --timeout 0.5 --concurrency 512```

## Key Options
```
Flag	Description
--iface eth0	Interface for tcpdump (default: auto)
--watch-seconds 20	Passive watch duration (default 20s)
--min-hits 3	Minimum sightings per /24 before keeping (default 3)
--include-host-subnets	Add directly-connected private subnets
--hint 10.0.0.0/8	Add manual CIDR hint (repeatable)
--only-harvest	Print discovered CIDRs and exit (skip sweep)
--ports 445,3389,135,80,443	Ports to test (default common set)
--all-ports	Report all responsive ports (default: stop on first hit)
--concurrency 2048	Concurrent TCP connects (default 2048)
--timeout 0.35	Per-port timeout in seconds (default 0.35s)
--json-out alive.json	Write results to JSON file
```
## Example Output
### During tcpdump watch (rich enabled):
```
┌───────────────────────────────┐
│ Passive Watch (tcpdump)       │
├───────────────┬───────────────┤
│ Time remaining │ 18s           │
│ Packets seen   │ 1021          │
│ Private IP hits│ 354           │
│ Unique /24s≥3  │ 12            │
│ Merged CIDRs   │ 10.50.12.0/23 │
│                │ 10.8.20.0/22  │
└───────────────┴───────────────┘
```

### During sweep:
```
┌──────────────────────────────┐
│ TCP Connect Sweep            │
├───────────────┬──────────────┤
│ Targets (IPs) │ 16384        │
│ Processed     │ 8320         │
│ Responsive    │ 112          │
│ Mode          │ stop-on-first│
└───────────────┴──────────────┘
```

### Final results:
```
10.50.12.22
10.50.12.34
10.8.21.77  445 3389
```
## License
This project is released under the MIT License.
⚠️ Use only on networks you are authorized to test.
