# Rex's Network Watcher

Defensive census of a network you own.

It ping-sweeps your private IPv4 LAN, reads the ARP table, reverse-resolves hostnames, and stores a baseline on that machine. The next day's run prints only what changed. Nothing is uploaded. There is no port scan and no credential use.

Use it only on a network you are allowed to inventory.

## Run

Python 3.9+ and the system `ping` plus `ip` (Linux) or `arp` (macOS). No third-party packages.

```bash
python3 rex-network-watcher.py selftest
python3 rex-network-watcher.py sweep
python3 rex-network-watcher.py accept
python3 rex-network-watcher.py diff
```

`sweep --json` prints a census the desk can import. Files land in `~/.local/share/rex-network-watcher/`.

Only private prefixes of /24 or smaller are swept. Pass `--subnet 192.168.1.0/24` when you want a specific one you are on.

## What the flags mean

- **NEW** — answered, and the MAC is not in the baseline yet
- **OK** — MAC is in the baseline
- **Since yesterday** — new, gone, or a changed IP versus the previous census

`accept` trusts every host in the latest census. Run that once you recognize the wire, then let `diff` be the daily alarm.

## The desk

The visual watch (cabin lab, new-host alert, trust list, daily delta) is the standalone Rex's Network Watcher page. A browser cannot ARP a house, so the cabin wire is a local lab. Import `sweep --json` from this script when you want the real census in that desk. The baseline in the page stays in the browser. This script's baseline stays on the machine.
