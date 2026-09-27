# dnspath

Trace a DNS lookup hop by hop and find exactly where it breaks.

`dnspath` is a small Rust CLI for debugging DNS over VPNs, especially split DNS into cloud networks. Instead of guessing, it walks the path a query takes (your OS resolver, the VPN tunnel, the DNS server, the answer) and reports the first checkpoint that fails.

> **Status:** early and experimental. Built in the open while learning Rust. Expect breaking changes.

## Why

"DNS doesn't work on the VPN" can mean many different things:

- the OS never sends the query to the VPN's DNS server
- the DNS server isn't routed through the tunnel
- a firewall drops UDP or TCP port 53
- the server answers, but with a public IP instead of a private one

Each of these has a different fix. `dnspath` tells you which one you have.

## What it checks

```
[✓] os resolver  uses 10.20.0.4 via utun4
[✓] tunnel       10.20.0.4 via utun4
[✗] dns udp      no reply from 10.20.0.4:53
```

| Checkpoint | Question it answers |
|---|---|
| OS resolver | Will the OS send this name to the DNS server you expect? (split-DNS domain match) |
| Tunnel | Is traffic to that DNS server routed through the VPN interface? |
| DNS over UDP | Does the server reply, and with a private IP? |
| DNS over TCP | Is TCP port 53 reachable too? |

## Usage

```bash
dnspath <name> <dns-server-ip>
```

Example:

```bash
dnspath myapp.internal.example.com 10.20.0.4
```

## Install

From source (requires Rust):

```bash
git clone https://github.com/<your-username>/dnspath
cd dnspath
cargo run -- <name> <dns-server-ip>
```

## Platform support

| Platform | Status |
|---|---|
| macOS | Supported (`scutil --dns`, `route get`) |
| Linux | Planned (`resolvectl`, `ip route get`) |
| Windows | Not planned yet |

## Roadmap

- [x] Query a specific DNS server directly over UDP and TCP
- [x] Classify answers as private or public
- [x] Inspect the macOS resolver configuration and match split-DNS domains
- [x] Check that the DNS server is routed through the VPN tunnel
- [ ] Run checks in order and stop at the first failure
- [ ] Compare against a public resolver to explain failures
- [ ] Azure correlation via `az` CLI (VPN gateway DNS, DNS resolver endpoints, NSG rules, private DNS zone links, private endpoints)
- [ ] Linux support
- [ ] `--json` output
- [ ] `--watch` mode for flaky connections

## Safety

- Read-only: `dnspath` sends ordinary DNS queries and reads local network configuration. It does not change any settings.
- The planned Azure integration shells out to your existing `az` login and only reads resource configuration. No credentials are stored.
- Check your organization's policy before running diagnostics against corporate networks.

## License

MIT