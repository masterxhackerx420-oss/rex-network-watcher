#!/usr/bin/env python3
"""Rex's Network Watcher — defensive census of a network you own.

Sweeps your local IPv4 subnet with ICMP echo, reads the OS ARP table,
reverse-resolves names, and diffs against a baseline that never leaves
this machine.

  python3 rex-network-watcher.py sweep
  python3 rex-network-watcher.py sweep --json
  python3 rex-network-watcher.py accept
  python3 rex-network-watcher.py diff
  python3 rex-network-watcher.py router 192.168.1.1
  python3 rex-network-watcher.py selftest

The first sweep reads the private LAN on this machine. It does not use
anyone else's gateway. Change it with `router` only when this computer
should watch a different private /24 you own. A saved router that is
not on this machine is ignored. Only private prefixes of /24 or smaller
are allowed. There is no port scan, no credential use, and no upload.
"""

from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import json
import platform
import shutil
import socket
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path.home() / ".local" / "share" / "rex-network-watcher"
DAYS = ROOT / "days"
KNOWN = ROOT / "known.json"
ROUTER = ROOT / "router"


def norm_mac(value: str) -> str | None:
    hex_chars = "".join(ch for ch in value if ch in "0123456789abcdefABCDEF")
    if len(hex_chars) != 12:
        return None
    hex_chars = hex_chars.upper()
    return ":".join(hex_chars[i : i + 2] for i in range(0, 12, 2))


def local_ipv4() -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # UDP connect does not transmit; it only selects a route.
        sock.connect(("192.0.2.1", 9))
        return sock.getsockname()[0]
    finally:
        sock.close()


def assert_private(net: ipaddress.IPv4Network) -> None:
    if not net.network_address.is_private or net.is_loopback:
        raise SystemExit(f"Refusing {net}. This tool only sweeps private local subnets.")
    if net.prefixlen < 24:
        raise SystemExit(f"Refusing {net}. The sweep limit is a /24 on your own LAN.")


def network_for_router(value: str) -> ipaddress.IPv4Network:
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError as exc:
        raise SystemExit(f"Not an IPv4 router address: {value}") from exc
    if not isinstance(ip, ipaddress.IPv4Address):
        raise SystemExit("IPv6 routers are not swept.")
    if ip.is_loopback or not ip.is_private or ip.packed[-1] in {0, 255}:
        raise SystemExit(f"Refusing {ip}. Set the private address of your own gateway.")
    net = ipaddress.ip_network(f"{ip}/24", strict=False)
    assert_private(net)
    return net


def saved_router() -> str | None:
    if not ROUTER.exists():
        return None
    text = ROUTER.read_text().strip()
    return text or None


def save_router(ip: str) -> None:
    ROOT.mkdir(parents=True, exist_ok=True)
    ROUTER.write_text(ip + "\n")


def detect_subnet() -> ipaddress.IPv4Network:
    preferred: str | None
    try:
        preferred = local_ipv4()
    except OSError:
        preferred = None

    candidates: list[ipaddress.IPv4Network] = []
    if shutil.which("ip"):
        out = subprocess.check_output(
            ["ip", "-4", "-o", "addr", "show", "scope", "global"],
            text=True,
            timeout=5,
        )
        for line in out.splitlines():
            parts = line.split()
            if "inet" not in parts:
                continue
            cidr = parts[parts.index("inet") + 1]
            try:
                iface = ipaddress.ip_interface(cidr)
            except ValueError:
                continue
            net = iface.network
            if net.is_loopback or not isinstance(net, ipaddress.IPv4Network):
                continue
            if not net.network_address.is_private:
                continue
            if preferred and iface.ip == ipaddress.ip_address(preferred):
                assert_private(net)
                return net
            candidates.append(net)
    if candidates:
        assert_private(candidates[0])
        return candidates[0]
    if preferred:
        net = ipaddress.ip_network(f"{preferred}/24", strict=False)
        assert_private(net)
        return net
    raise SystemExit("Could not find a private IPv4 address on this machine.")


def parse_subnet(value: str) -> ipaddress.IPv4Network:
    try:
        net = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise SystemExit(f"Not a subnet: {value}") from exc
    if not isinstance(net, ipaddress.IPv4Network):
        raise SystemExit("IPv6 subnets are not swept.")
    assert_private(net)
    return net


def ping_one(ip: str) -> None:
    if platform.system() == "Darwin":
        cmd = ["ping", "-c", "1", "-W", "1000", ip]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", ip]
    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3)


def ping_sweep(net: ipaddress.IPv4Network) -> None:
    hosts = [str(ip) for ip in net.hosts()]
    if not hosts:
        return
    with ThreadPoolExecutor(max_workers=32) as pool:
        list(pool.map(ping_one, hosts))


def read_neighbors() -> dict[str, str]:
    found: dict[str, str] = {}
    if shutil.which("ip"):
        out = subprocess.check_output(["ip", "-4", "neigh", "show"], text=True, timeout=5)
        for line in out.splitlines():
            parts = line.split()
            if "lladdr" not in parts:
                continue
            ip = parts[0]
            mac = norm_mac(parts[parts.index("lladdr") + 1])
            state = parts[-1]
            if not mac or state in {"FAILED", "INCOMPLETE"}:
                continue
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                continue
            found[ip] = mac
        return found
    if shutil.which("arp"):
        out = subprocess.check_output(["arp", "-an"], text=True, timeout=5)
        for line in out.splitlines():
            if " at " not in line or "(" not in line:
                continue
            ip = line.split("(", 1)[1].split(")", 1)[0]
            mac_raw = line.split(" at ", 1)[1].split()[0]
            mac = norm_mac(mac_raw)
            if not mac or mac_raw.lower() == "(incomplete)":
                continue
            found[ip] = mac
        return found
    raise SystemExit("Need `ip neigh` or `arp` to read the local address table.")


def hostname_for(ip: str) -> str:
    socket.setdefaulttimeout(0.4)
    try:
        name = socket.getfqdn(ip)
    except OSError:
        return ""
    if not name or name == ip:
        return ""
    return name.split(".")[0][:64]


def census(net: ipaddress.IPv4Network) -> list[dict[str, str]]:
    ping_sweep(net)
    neighbors = read_neighbors()
    hosts: list[dict[str, str]] = []
    for ip, mac in sorted(neighbors.items(), key=lambda item: ipaddress.ip_address(item[0])):
        addr = ipaddress.ip_address(ip)
        if addr not in net:
            continue
        hosts.append(
            {
                "ip": ip,
                "mac": mac,
                "hostname": hostname_for(ip),
                "vendor": "",
                "kind": "unknown",
            }
        )
    return hosts


def load_known() -> set[str]:
    if not KNOWN.exists():
        return set()
    data = json.loads(KNOWN.read_text())
    return {mac for mac in data.get("macs", []) if isinstance(mac, str)}


def save_known(macs: set[str]) -> None:
    ROOT.mkdir(parents=True, exist_ok=True)
    payload = {
        "tool": "rex-network-watcher",
        "updatedAt": dt.datetime.now(dt.timezone.utc).isoformat(),
        "macs": sorted(macs),
    }
    KNOWN.write_text(json.dumps(payload, indent=2) + "\n")


def today_key() -> str:
    return dt.date.today().isoformat()


def save_day(day: str, subnet: str, hosts: list[dict[str, str]]) -> Path:
    DAYS.mkdir(parents=True, exist_ok=True)
    path = DAYS / f"{day}.json"
    payload = {
        "tool": "rex-network-watcher",
        "day": day,
        "subnet": subnet,
        "scannedAt": dt.datetime.now(dt.timezone.utc).isoformat(),
        "hosts": hosts,
    }
    path.write_text(json.dumps(payload, indent=2) + "\n")
    return path


def previous_census(day: str) -> dict | None:
    if not DAYS.exists():
        return None
    prior = sorted(path for path in DAYS.glob("*.json") if path.stem < day)
    if not prior:
        return None
    return json.loads(prior[-1].read_text())


def diff_hosts(before: list[dict[str, str]], after: list[dict[str, str]]) -> list[dict[str, str]]:
    prev = {row["mac"]: row for row in before if row.get("mac")}
    cur = {row["mac"]: row for row in after if row.get("mac")}
    changes: list[dict[str, str]] = []
    for mac, row in cur.items():
        name = row.get("hostname") or mac
        if mac not in prev:
            changes.append(
                {
                    "kind": "new",
                    "mac": mac,
                    "hostname": name,
                    "detail": f"{row.get('ip', '')} was not here yesterday",
                }
            )
        elif prev[mac].get("ip") != row.get("ip"):
            changes.append(
                {
                    "kind": "ip",
                    "mac": mac,
                    "hostname": name,
                    "detail": f"{prev[mac].get('ip', '')} -> {row.get('ip', '')}",
                }
            )
    for mac, row in prev.items():
        if mac in cur:
            continue
        changes.append(
            {
                "kind": "gone",
                "mac": mac,
                "hostname": row.get("hostname") or mac,
                "detail": f"silent today, was {row.get('ip', '')}",
            }
        )
    return changes


def print_changes(changes: list[dict[str, str]], sink) -> None:
    if not changes:
        print("No change since yesterday.", file=sink)
        return
    print("Since yesterday:", file=sink)
    for row in changes:
        print(f"  {row['kind'].upper():8} {row['hostname']:<24} {row['detail']}", file=sink)


def report(subnet: str, hosts: list[dict[str, str]], known: set[str], changes: list[dict[str, str]], sink) -> None:
    print("Rex's Network Watcher — this machine only", file=sink)
    print(f"subnet {subnet}   {len(hosts)} hosts   baseline {len(known)}", file=sink)
    if not hosts:
        print("Nobody answered.", file=sink)
    for row in hosts:
        flag = "OK" if row["mac"] in known else "NEW"
        name = row["hostname"] or "(no dns)"
        print(f"  {flag:4} {name:<24} {row['ip']:<16} {row['mac']}", file=sink)
    if not known and hosts:
        print("Nothing is trusted yet. Run: python3 rex-network-watcher.py accept", file=sink)
    print_changes(changes, sink)


def router_on_this_machine(ip: str) -> bool:
    try:
        here = detect_subnet()
    except SystemExit:
        return False
    return ipaddress.ip_address(ip) in here


def cmd_sweep(args: argparse.Namespace) -> int:
    if args.router and args.subnet:
        raise SystemExit("Pass either --router or --subnet, not both.")
    if args.router:
        gateway = str(ipaddress.ip_address(args.router.strip()))
        net = network_for_router(gateway)
        save_router(gateway)
    elif args.subnet:
        net = parse_subnet(args.subnet)
    else:
        remembered = saved_router()
        if remembered and router_on_this_machine(remembered):
            net = network_for_router(remembered)
        else:
            if remembered:
                print(
                    f"Saved router {remembered} is not on this machine. Sweeping the LAN that is.",
                    file=sys.stderr,
                )
            net = detect_subnet()
    hosts = census(net)
    day = today_key()
    path = save_day(day, str(net), hosts)
    known = load_known()
    prior = previous_census(day)
    changes = diff_hosts(prior.get("hosts", []) if prior else [], hosts) if prior else []
    payload = {
        "tool": "rex-network-watcher",
        "subnet": str(net),
        "scannedAt": dt.datetime.now(dt.timezone.utc).isoformat(),
        "hosts": hosts,
    }
    sink = sys.stderr if args.json else sys.stdout
    report(str(net), hosts, known, changes, sink)
    print(f"census {path}", file=sink)
    if args.json:
        json.dump(payload, sys.stdout, indent=2)
        sys.stdout.write("\n")
    return 0


def cmd_accept(_args: argparse.Namespace) -> int:
    day = today_key()
    path = DAYS / f"{day}.json"
    if not path.exists():
        prior = sorted(DAYS.glob("*.json")) if DAYS.exists() else []
        if not prior:
            raise SystemExit("No census yet. Run sweep first.")
        path = prior[-1]
    data = json.loads(path.read_text())
    macs = load_known()
    for row in data.get("hosts", []):
        mac = row.get("mac")
        if isinstance(mac, str):
            macs.add(mac)
    save_known(macs)
    print(f"Baseline now holds {len(macs)} hosts ({path.name}).")
    return 0


def cmd_router(args: argparse.Namespace) -> int:
    if args.clear:
        if ROUTER.exists():
            ROUTER.unlink()
        print("Router cleared. Set one before the next sweep.")
        return 0
    if args.address:
        net = network_for_router(args.address)
        gateway = str(ipaddress.ip_address(args.address.strip()))
        save_router(gateway)
        print(f"Router {gateway}  subnet {net}")
        return 0
    remembered = saved_router()
    if not remembered:
        raise SystemExit("No router set. Example: python3 rex-network-watcher.py router 192.168.1.1")
    print(f"Router {remembered}  subnet {network_for_router(remembered)}")
    return 0


def cmd_diff(_args: argparse.Namespace) -> int:
    day = today_key()
    path = DAYS / f"{day}.json"
    if not path.exists():
        raise SystemExit("No census for today. Run sweep first.")
    today = json.loads(path.read_text())
    prior = previous_census(day)
    if not prior:
        print("No earlier census. Tomorrow's run will print only what changed.")
        return 0
    changes = diff_hosts(prior.get("hosts", []), today.get("hosts", []))
    print_changes(changes, sys.stdout)
    return 0


def selftest() -> int:
    assert norm_mac("b8-27-eb-4c-11-02") == "B8:27:EB:4C:11:02"
    assert norm_mac("nope") is None
    quiet = [{"mac": "AA:BB:CC:DD:EE:01", "ip": "192.168.0.1", "hostname": "gw"}]
    assert diff_hosts(quiet, quiet) == []
    added = quiet + [{"mac": "AA:BB:CC:DD:EE:02", "ip": "192.168.0.50", "hostname": "phone"}]
    changes = diff_hosts(quiet, added)
    assert [row["kind"] for row in changes] == ["new"]
    moved = [{"mac": "AA:BB:CC:DD:EE:01", "ip": "192.168.0.9", "hostname": "gw"}]
    assert diff_hosts(quiet, moved)[0]["kind"] == "ip"
    assert diff_hosts(added, quiet)[0]["kind"] == "gone"
    try:
        assert_private(ipaddress.ip_network("8.8.8.8/32"))
    except SystemExit:
        pass
    else:
        raise AssertionError("public address was allowed")
    try:
        assert_private(ipaddress.ip_network("10.0.0.0/16"))
    except SystemExit:
        pass
    else:
        raise AssertionError("oversized prefix was allowed")
    assert_private(ipaddress.ip_network("192.168.0.0/24"))
    assert str(network_for_router("192.168.1.1")) == "192.168.1.0/24"
    try:
        network_for_router("8.8.8.8")
    except SystemExit:
        pass
    else:
        raise AssertionError("public router was allowed")
    try:
        network_for_router("192.168.0.0")
    except SystemExit:
        pass
    else:
        raise AssertionError("network address was allowed as a router")
    print("selftest ok")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Defensive census of your own local network.")
    sub = parser.add_subparsers(dest="command", required=True)
    sweep = sub.add_parser("sweep", help="Ping your subnet, read ARP, save today's census")
    sweep.add_argument("--router", help="Private IPv4 gateway. Saved and reused until you change it.")
    sweep.add_argument("--subnet", help="Private IPv4 subnet, /24 or smaller, if you already know the prefix")
    sweep.add_argument("--json", action="store_true", help="Write sweep JSON to stdout for the desk import")
    sweep.set_defaults(func=cmd_sweep)
    router = sub.add_parser("router", help="Set or show this machine's gateway address")
    router.add_argument("address", nargs="?", help="Private IPv4 address of your router")
    router.add_argument("--clear", action="store_true", help="Forget the saved router")
    router.set_defaults(func=cmd_router)
    accept = sub.add_parser("accept", help="Trust every host in the latest census")
    accept.set_defaults(func=cmd_accept)
    diff = sub.add_parser("diff", help="Print only what changed since the previous census")
    diff.set_defaults(func=cmd_diff)
    test = sub.add_parser("selftest", help="Check the diff logic without touching the network")
    test.set_defaults(func=lambda _args: selftest())
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
