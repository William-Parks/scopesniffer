#!/usr/bin/env python3
"""
scope_harvester.py
Passive subnet harvester (tcpdump) + fast TCP-connect sweep with live status.

New:
  --cidrs-out FILE  -> write discovered CIDR ranges (one per line)
  --alive-out FILE  -> write responsive IPs (one per line)
"""

import argparse
import asyncio
import collections
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from typing import Dict, Iterable, List, Optional, Tuple

# Optional pretty UI with 'rich'
try:
    from rich.live import Live
    from rich.table import Table
    from rich.panel import Panel
    from rich.console import Console
    RICH = True
    console = Console()
except Exception:
    RICH = False

PRIVATE_BLOCKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
]
COMMON_PORTS = [445, 3389, 135, 443, 80, 22, 53, 139, 1433, 3306, 8080, 8443]
IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

# ---------------- utils ----------------

def is_private_ip(ip: str) -> bool:
    try:
        obj = ipaddress.ip_address(ip)
        return obj.version == 4 and any(obj in blk for blk in PRIVATE_BLOCKS)
    except Exception:
        return False

def to_prefix(ip: str, mask: int) -> str:
    n = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
    return f"{n.network_address}/{mask}"

def run_cmd(cmd: List[str]) -> str:
    try:
        return subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True)
    except Exception:
        return ""

def get_host_connected_subnets() -> List[str]:
    out = run_cmd(["sh", "-c", "ip -o -f inet addr show | awk '{print $4}'"])
    cidrs = []
    for line in out.splitlines():
        s = line.strip()
        if not s:
            continue
        try:
            net = ipaddress.ip_network(s, strict=False)
            if net.version == 4 and any(net.network_address in blk for blk in PRIVATE_BLOCKS):
                cidrs.append(str(net))
        except Exception:
            pass
    return sorted(set(cidrs))

def tcpdump_available() -> bool:
    return shutil.which("tcpdump") is not None

# --------------- harvesting ---------------

def _merge_dense_blocks(nets: List[ipaddress.IPv4Network]) -> List[ipaddress.IPv4Network]:
    if not nets:
        return []
    nets = sorted(nets, key=lambda x: (int(x.network_address), x.prefixlen))
    cur = nets

    def merge_step(blocks: List[ipaddress.IPv4Network], new_prefix: int) -> List[ipaddress.IPv4Network]:
        by_super: Dict[ipaddress.IPv4Network, List[ipaddress.IPv4Network]] = collections.defaultdict(list)
        for n in blocks:
            if n.prefixlen != new_prefix + 1:
                by_super[n].append(n)
                continue
            supernet = n.supernet(new_prefix=new_prefix)
            by_super[supernet].append(n)
        merged: List[ipaddress.IPv4Network] = []
        for supernet, kids in by_super.items():
            if all(k.prefixlen == new_prefix + 1 for k in kids) and len(kids) == 2 and supernet.prefixlen == new_prefix:
                merged.append(supernet)
            else:
                merged.extend(kids)
        uniq, seen = [], set()
        for n in sorted(merged, key=lambda x: (int(x.network_address), x.prefixlen)):
            key = (int(n.network_address), n.prefixlen)
            if key in seen:
                continue
            seen.add(key)
            uniq.append(n)
        return uniq

    for new_pfx in (23, 22):
        cur = merge_step(cur, new_pfx)
    return cur

def harvest_with_tcpdump(iface: Optional[str], seconds: int, pkt_limit: int,
                         min_hits: int, status: bool = True) -> Tuple[List[str], Dict[str, int]]:
    cmd = ["tcpdump", "-n", "-l", "-q", "ip"]
    if iface:
        cmd.extend(["-i", iface])
    if seconds > 0:
        cmd.extend(["-G", str(seconds), "-W", "1"])
    if pkt_limit > 0:
        cmd.extend(["-c", str(pkt_limit)])

    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)

    start = time.time()
    deadline = start + seconds if seconds > 0 else None
    pkts_seen = 0
    private_ips = 0
    c24 = collections.Counter()

    def snapshot():
        active_24 = [cidr for cidr, cnt in c24.items() if cnt >= min_hits]
        nets = [ipaddress.ip_network(c) for c in active_24]
        merged = _merge_dense_blocks(nets)
        return [str(n) for n in merged]

    try:
        if RICH and status:
            with Live(auto_refresh=False, console=console, transient=True) as live:
                last = 0.0
                while True:
                    line = proc.stdout.readline()
                    now = time.time()
                    if line:
                        pkts_seen += 1
                        for ip in IP_RE.findall(line):
                            if is_private_ip(ip):
                                private_ips += 1
                                c24[to_prefix(ip, 24)] += 1
                    if proc.poll() is not None and not line:
                        break
                    if deadline and now >= deadline:
                        try: proc.terminate()
                        except Exception: pass
                        break
                    if now - last >= 0.1 and status:
                        remaining = max(0, int((deadline - now))) if deadline else 0
                        uniq_24 = sum(1 for _, v in c24.items() if v >= min_hits)
                        merged_now = snapshot()
                        table = Table(title="Passive Watch (tcpdump)", expand=True)
                        table.add_column("Metric", justify="right"); table.add_column("Value", justify="left")
                        table.add_row("Time remaining", f"{remaining}s")
                        table.add_row("Packets seen", f"{pkts_seen}")
                        table.add_row("Private IP hits", f"{private_ips}")
                        table.add_row(f"Unique /24 (≥{min_hits})", f"{uniq_24}")
                        table.add_row("Merged CIDRs (preview)", "\n".join(merged_now[:10]) + ("" if len(merged_now)<=10 else "\n…"))
                        live.update(Panel(table, padding=(1,2)), refresh=True)
                        last = now
        else:
            last_print = 0.0
            while True:
                line = proc.stdout.readline()
                now = time.time()
                if line:
                    pkts_seen += 1
                    for ip in IP_RE.findall(line):
                        if is_private_ip(ip):
                            private_ips += 1
                            c24[to_prefix(ip, 24)] += 1
                if proc.poll() is not None and not line:
                    break
                if deadline and now >= deadline:
                    try: proc.terminate()
                    except Exception: pass
                    break
                if now - last_print >= 0.2 and status:
                    remaining = max(0, int((deadline - now))) if deadline else 0
                    uniq_24 = sum(1 for _, v in c24.items() if v >= min_hits)
                    sys.stdout.write(f"\r[watch] T-{remaining:>3}s | pkts={pkts_seen} | private_hits={private_ips} | /24s≥{min_hits}={uniq_24}")
                    sys.stdout.flush()
                    last_print = now
            if status:
                sys.stdout.write("\n"); sys.stdout.flush()
    finally:
        try: proc.terminate()
        except Exception: pass

    active_24 = [cidr for cidr, cnt in c24.items() if cnt >= min_hits]
    nets = [ipaddress.ip_network(c) for c in active_24]
    merged = _merge_dense_blocks(nets)
    cidrs = [str(n) for n in merged]
    stats = {
        "packets_seen": pkts_seen,
        "private_ip_hits": private_ips,
        "unique_24_min_hits": sum(1 for _, v in c24.items() if v >= min_hits),
        "candidate_cidrs": len(cidrs),
    }
    return cidrs, stats

# --------------- sweeper ---------------

async def _tcp_connect(ip: str, port: int, timeout: float) -> bool:
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(ip, port, family=socket.AF_INET), timeout=timeout)
        w.close()
        try: await w.wait_closed()
        except Exception: pass
        return True
    except Exception:
        return False

async def _probe_host(ip: str, ports: List[int], timeout: float, stop_on_first: bool) -> Tuple[str, List[int]]:
    hits = []
    for p in ports:
        if await _tcp_connect(ip, p, timeout):
            hits.append(p)
            if stop_on_first: break
    return ip, hits

def _iter_ips(cidr: str) -> Iterable[str]:
    net = ipaddress.ip_network(cidr, strict=False)
    hosts = net.hosts() if net.num_addresses > 2 else net
    for ip in hosts:
        yield str(ip)

async def sweep(cidrs: List[str], ports: List[int], concurrency: int, timeout: float, stop_on_first: bool,
                live: bool = True) -> Dict[str, List[int]]:
    ip_q: asyncio.Queue = asyncio.Queue(maxsize=concurrency * 4)
    res_q: asyncio.Queue = asyncio.Queue()
    total_ips = 0

    async def feeder():
        nonlocal total_ips
        for c in cidrs:
            for ip in _iter_ips(c):
                await ip_q.put(ip)
                total_ips += 1
        for _ in range(concurrency):
            await ip_q.put(None)

    async def worker():
        while True:
            ip = await ip_q.get()
            if ip is None:
                ip_q.task_done()
                return
            ip, openp = await _probe_host(ip, ports, timeout, stop_on_first)
            if openp:
                await res_q.put((ip, openp))
            ip_q.task_done()

    workers = [asyncio.create_task(worker()) for _ in range(concurrency)]
    feeder_task = asyncio.create_task(feeder())

    results: Dict[str, List[int]] = {}
    processed = 0
    last_display = 0.0

    if RICH and live:
        with Live(auto_refresh=False, console=console, transient=False) as live_ui:
            while True:
                if feeder_task.done() and all(w.done() for w in workers) and res_q.empty():
                    break
                try:
                    ip, openp = await asyncio.wait_for(res_q.get(), timeout=0.1)
                    results[ip] = openp
                except asyncio.TimeoutError:
                    pass
                now = time.time()
                in_q = ip_q.qsize()
                processed = max(0, total_ips - in_q)
                if now - last_display >= 0.1:
                    table = Table(title="TCP Connect Sweep", expand=True)
                    table.add_column("Metric", justify="right"); table.add_column("Value", justify="left")
                    table.add_row("Targets (IPs)", f"{total_ips}")
                    table.add_row("Processed", f"{processed}")
                    table.add_row("Responsive hosts", f"{len(results)}")
                    table.add_row("Mode", "stop-on-first" if stop_on_first else "all-ports")
                    live_ui.update(Panel(table, padding=(1,2)), refresh=True)
                    last_display = now
    else:
        while True:
            if feeder_task.done() and all(w.done() for w in workers) and res_q.empty():
                break
            try:
                ip, openp = await asyncio.wait_for(res_q.get(), timeout=0.1)
                results[ip] = openp
                print(ip if stop_on_first else f"{ip} {' '.join(map(str, openp))}")
            except asyncio.TimeoutError:
                pass

    await feeder_task
    await asyncio.gather(*workers, return_exceptions=True)
    return results

def parse_ports(s: str) -> List[int]:
    out = set()
    for tok in s.split(','):
        tok = tok.strip()
        if not tok: continue
        if '-' in tok:
            a, b = tok.split('-', 1)
            a, b = int(a), int(b)
            if a > b: a, b = b, a
            out.update(range(a, b+1))
        else:
            out.add(int(tok))
    return sorted(out)

# --------------- main ---------------

def main():
    ap = argparse.ArgumentParser(description="Passive subnet harvester (tcpdump) + fast TCP sweep (no vuln checks).")
    ap.add_argument("--iface", help="Interface for tcpdump (e.g., eth0).")
    ap.add_argument("--watch-seconds", type=int, default=20, help="Passive watch duration (seconds).")
    ap.add_argument("--watch-pkts", type=int, default=0, help="Stop after N packets (0=disabled).")
    ap.add_argument("--min-hits", type=int, default=3, help="Keep /24s seen at least this many times.")
    ap.add_argument("--no-tcpdump", action="store_true", help="Skip tcpdump; only use host subnets and hints.")
    ap.add_argument("--include-host-subnets", action="store_true", help="Seed with host's connected private subnets.")
    ap.add_argument("--hint", action="append", default=[], help="Additional CIDR hints (repeatable).")
    ap.add_argument("--only-harvest", action="store_true", help="Just print candidate CIDRs and exit.")
    ap.add_argument("--ports", default=",".join(map(str, COMMON_PORTS)), help="Ports for sweep.")
    ap.add_argument("--timeout", type=float, default=0.35, help="Per-port TCP connect timeout.")
    ap.add_argument("--concurrency", type=int, default=2048, help="Concurrent TCP checks.")
    ap.add_argument("--all-ports", action="store_true", help="List all responsive ports per host (otherwise stop on first).")
    ap.add_argument("--json-out", help="Write JSON {ip:[ports]} after sweep.")
    # NEW OUTPUTS
    ap.add_argument("--cidrs-out", help="Write discovered CIDR ranges (one per line).")
    ap.add_argument("--alive-out", help="Write responsive IPs (one per line).")
    ap.add_argument("--quiet", action="store_true", help="Reduce chatter.")
    args = ap.parse_args()

    # Collect candidate CIDRs
    candidate: List[str] = []
    if args.include_host_subnets:
        host_nets = get_host_connected_subnets()
        if not args.quiet:
            print(f"[*] Host-connected private subnets: {', '.join(host_nets) if host_nets else '(none)'}", file=sys.stderr)
        candidate.extend(host_nets)

    for h in args.hint:
        try:
            n = ipaddress.ip_network(h, strict=False)
            if n.version == 4:
                candidate.append(str(n))
        except Exception:
            print(f"[!] Ignoring invalid --hint: {h}", file=sys.stderr)

    if not args.no_tcpdump:
        if not tcpdump_available():
            print("[!] tcpdump not found; skipping passive capture.", file=sys.stderr)
        else:
            if not args.quiet:
                print(f"[*] Passive watch via tcpdump for {args.watch_seconds}s (or {args.watch_pkts} pkts)…", file=sys.stderr)
            found, stats = harvest_with_tcpdump(
                iface=args.iface,
                seconds=args.watch_seconds,
                pkt_limit=args.watch_pkts,
                min_hits=args.min_hits,
                status=True,
            )
            if not args.quiet:
                print(f"[*] Watch stats: pkts={stats['packets_seen']}, private_hits={stats['private_ip_hits']}, "
                      f"/24s≥{args.min_hits}={stats['unique_24_min_hits']}", file=sys.stderr)
            candidate.extend(found)

    # Normalize + collapse
    nets = []
    for c in set(candidate):
        try:
            n = ipaddress.ip_network(c, strict=False)
            if n.version == 4 and any(n.network_address in blk for blk in PRIVATE_BLOCKS):
                nets.append(n)
        except Exception:
            continue
    cidrs = [str(n) for n in ipaddress.collapse_addresses(sorted(nets, key=lambda x: (int(x.network_address), x.prefixlen)))]

    if not cidrs:
        print("[!] No candidate internal CIDRs discovered. Add --hint, --include-host-subnets, or disable --no-tcpdump.", file=sys.stderr)
        sys.exit(1)

    # Always show on stderr for operator; write to file if requested
    print("[*] Candidate internal CIDRs:", file=sys.stderr)
    for c in cidrs:
        print(f"  {c}", file=sys.stderr)
    if args.cidrs_out:
        with open(args.cidrs_out, "w", encoding="utf-8") as f:
            f.write("\n".join(cidrs) + "\n")

    if args.only_harvest:
        return

    # Sweep
    ports = parse_ports(args.ports)
    stop_on_first = not args.all_ports
    if not args.quiet:
        print(f"[*] Sweeping discovered ranges (TCP connect) | ports={','.join(map(str, ports))} | "
              f"concurrency={args.concurrency} | timeout={args.timeout:.2f}s | "
              f"mode={'stop-on-first' if stop_on_first else 'all-ports'}", file=sys.stderr)

    results = asyncio.run(sweep(cidrs, ports, args.concurrency, args.timeout, stop_on_first, live=True))

    # Print to stdout
    for ip, openp in sorted(results.items(), key=lambda kv: tuple(map(int, kv[0].split('.')))):
        if stop_on_first:
            print(ip)
        else:
            print(f"{ip} {' '.join(map(str, openp))}")

    # Write alive IP list if requested (one IP per line)
    if args.alive_out:
        alive_ips = sorted(results.keys(), key=lambda s: tuple(map(int, s.split("."))))
        with open(args.alive_out, "w", encoding="utf-8") as f:
            f.write("\n".join(alive_ips) + ("\n" if alive_ips else ""))

    # JSON (ip -> [ports])
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, sort_keys=True)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted.", file=sys.stderr)
        sys.exit(130)

