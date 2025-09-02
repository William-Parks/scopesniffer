# scopesniffer

⚡ Passive subnet discovery + fast TCP sweep for internal penetration testing

This tool helps penetration testers **quickly identify internal scope** on client networks without running intrusive vulnerability scans. It works in two phases:

1. **Passive Harvesting**  
   Uses `tcpdump` to watch live traffic and extract candidate subnets in use (aggregates into `/24`s, then merges into `/23`/`/22` when dense).  
   It can also seed scope from the host’s assigned private subnets and user-supplied hints.

2. **Fast TCP Sweep**  
   Runs aggressive async TCP `connect()` probes (no raw sockets) across discovered ranges to identify responsive hosts on common internal ports.  
   Think of it as a lightweight `masscan`/`nmap -sn` replacement, tuned for large internal ranges.

---

## ✨ Features

- 🔎 **Passive scope discovery** via `tcpdump` (requires root or `cap_net_admin`)
- 🖧 **Host subnet seeding** (reads `ip addr` to include locally assigned private ranges)
- 🧾 **Manual hints** (`--hint 10.0.0.0/8`)
- ⚡ **Async TCP connect sweep** (no raw sockets, no vuln checks, safe to run unprivileged)
- 🎛️ **Tunable concurrency & timeouts** (`--concurrency`, `--timeout`)
- 📊 **Live CLI interface**  
  - During tcpdump: time remaining, packets seen, private IP hits, hot `/24`s, merged CIDRs preview  
  - During sweep: IPs processed, responsive hosts, mode
- 📂 **Output files**  
  - `--cidrs-out cidrs.txt` → discovered CIDR ranges  
  - `--alive-out alive.txt` → responsive IPs  
  - `--json-out alive.json` → full JSON results (`{ip: [ports]}`)

---

## ⚙️ Installation

Clone this repo and drop the script:

```bash
git clone https://github.com/yourname/scope-harvester.git
cd scope-harvester
chmod +x scope_harvester.py
```
###Requires:
- Python 3.9+
- tcpdump in PATH (for passive harvesting)
- rich (optional, for nicer CLI output)

## Usage Examples
### Passive Harvest Only
Watch traffic and print discovered subnets:

```sudo python3 scope_harvester.py --iface eth0 --watch-seconds 30 --only-harvest```

Watch + include host’s connected subnets:

```sudo python3 scope_harvester.py --iface eth0 --watch-seconds 20 --include-host-subnets --only-harvest --cidrs-out cidrs.txt```

### Harvest + Sweep
Passive watch, then sweep discovered subnets for responsive hosts:

```sudo python3 scope_harvester.py --iface eth0 --watch-seconds 20 --include-host-subnets --cidrs-out cidrs.txt --alive-out alive.txt```

Passive watch 10s, sweep, and save JSON:

```sudo python3 scope_harvester.py --iface eth0 --watch-seconds 10 --include-host-subnets --json-out alive.json```

### Manual Hints / No Tcpdump
Skip tcpdump, seed with host subnets + hints:

```python3 scope_harvester.py --no-tcpdump --include-host-subnets --hint 10.0.0.0/8 --hint 172.16.0.0/12 --cidrs-out cidrs.txt --alive-out alive.txt```

### Sweep Customization
Scan specific ports (range + list allowed):

```python3 scope_harvester.py --no-tcpdump --hint 192.168.0.0/24 --ports 21,22,80,443,445,3389,8000-8100```

Gentle sweep (good for VMs/NICs prone to crashing):

```python3 scope_harvester.py --no-tcpdump --hint 192.168.0.0/16 --concurrency 512 --timeout 0.5```

Scan all responsive ports per host (not just first found):

```python3 scope_harvester.py --no-tcpdump --hint 10.20.0.0/16 --all-ports```

## Example Output
During tcpdump watch (rich enabled):
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

During sweep:
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

## Example Output Files
### cidrs.txt (discovered CIDR ranges)
```
10.50.12.0/23
10.8.20.0/22
192.168.1.0/24
```
### alive.txt (list of responsive IPs)
```
10.50.12.22
10.50.12.34
10.8.21.77
192.168.1.15
```
### alive.json (optional JSON results)
```
{
  "10.50.12.22": [445],
  "10.50.12.34": [3389],
  "10.8.21.77": [445, 3389],
  "192.168.1.15": [80, 443]
}
```



⚠️ Notes
- **⚠️ Use only on networks you are explicitly authorized to test.**

- This is **not** a vulnerability scanner. It only identifies _responsive IPs/ports_.
- Run tcpdump with care — some environments may log or alert on promiscuous captures.
- Start with conservative settings (--timeout 0.5, --concurrency 512) if you’re testing in a sensitive or unstable environment.

📜 License
This project is released under the MIT License.
