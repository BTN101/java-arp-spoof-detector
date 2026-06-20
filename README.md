# java-arp-spoof-detector

A real-time ARP spoofing detector written in Java. Monitors the local ARP cache for suspicious IP-to-MAC mapping changes and fires tiered alerts — from informational notices to high-priority gateway compromise warnings.

Built as the second project in a deliberate security portfolio sequence: [java-port-scanner](https://github.com/BTN101/java-port-scanner) → **ARP spoof detector** → network traffic analyzer → honeypot → firewall.

---

## What it does

The detector captures a baseline snapshot of the ARP table at startup, then polls it every 3 seconds. On each poll, it compares the current state against the baseline and fires alerts based on what changed:

| Alert | Trigger | What it means |
|-------|---------|---------------|
| `[INFO]` | New IP appeared | A new device joined the network — could be innocent or attacker reconnaissance |
| `[INFO]` | IP disappeared | A device left the network or its ARP entry expired |
| `[WARNING]` | Non-gateway MAC changed | A device's hardware address changed — possible NIC replacement or low-value spoofing |
| `[HIGH]` | Gateway MAC changed | The router's identity changed — textbook ARP poisoning / MITM setup |

---

## Why ARP spoofing matters

ARP has zero authentication. Any device on a local network can send a fake ARP reply claiming "this IP belongs to my MAC address" — and every other device will blindly accept and cache it. An attacker who poisons both the victim's and the router's ARP caches can silently relay all traffic between them (man-in-the-middle), with neither side knowing.

The gateway IP is the highest-value target: poison it and you intercept everything leaving the network.

---

## How it works

```
Startup
  └── getArpTable()  →  baseline Map<IP, MAC>

Every 3 seconds
  └── getArpTable()  →  current Map<IP, MAC>
  └── compare(baseline, current, gatewayIp)
        ├── Check 1: IP in current, not in baseline  →  [INFO] new device
        ├── Check 2: IP in baseline, not in current  →  [INFO] device gone
        └── Check 3: same IP, different MAC
              ├── gateway IP?  →  [HIGH]
              └── other IP?    →  [WARNING]
```

### The parsing pipeline

`arp -a` output is unstructured text. Each line goes through three independent checks before being treated as real data:

1. **`tokens.length == 3`** — filters header lines (they produce 4-5 tokens when split on whitespace)
2. **`tokens[1].matches(macPattern)`** — validates the middle token is structurally a MAC address (6 hex pairs, hyphen-separated)
3. **`tokens[2].equals("dynamic")`** — filters out static/multicast/broadcast entries that can never meaningfully change

Only lines passing all three checks are stored. On a typical home network this leaves just the real, spoofable device mappings.

---

## Running it

```bash
# Compile
javac ARPspoofdetector.java

# Run with your gateway IP as an argument
java ARPspoofdetector 192.168.1.1

# No argument defaults to 192.168.1.1
java ARPspoofdetector
```

Find your gateway IP:
- **Windows:** `ipconfig` → look for "Default Gateway"
- **macOS/Linux:** `ip route | grep default`

**Note:** The detector reads the ARP table — it does not require elevated privileges to run. However, testing with `netsh` (to simulate fake entries) does require admin access.

---

## Sample output

```
[STARTUP] Baseline captured: 2 entries
  192.168.1.1  -> aa:bb:cc:dd:ee:ff
  192.168.1.45 -> 11:22:33:44:55:66

[INFO] New device detected: 192.168.1.72 -> 77:88:99:aa:bb:cc
[WARNING] MAC changed: 192.168.1.45 was 11:22:33:44:55:66 now ff:ee:dd:cc:bb:aa
[HIGH] Gateway MAC changed: 192.168.1.1 was aa:bb:cc:dd:ee:ff now 00:11:22:33:44:55
```

---

## Testing

Since a real ARP spoofing attack requires a second device and specialized tooling, detection logic was validated by manually injecting fake ARP entries using `netsh` on Windows (admin terminal required):

```bash
# Overwrite a device's MAC with a fake one
netsh interface ip add neighbors "Ethernet" 192.168.1.45 aa-bb-cc-dd-ee-ff

# Clean up afterward
netsh interface ip delete neighbors "Ethernet" 192.168.1.45
```

This simulates the *symptom* an ARP poisoning attack produces (a changed IP-to-MAC mapping in the cache) without needing live attack tooling. The detector fires correctly on injected entries within one poll cycle (≤3 seconds).

**Important:** `netsh add` creates static entries. The detector's `dynamic`-only filter will ignore these unless temporarily disabled for testing. See [Known Limitations](#known-limitations).

---

## What I discovered building this

**The "dynamic only" filter was non-obvious.** My first implementation returned 7 entries per poll, including multicast addresses (`224.0.0.x`), broadcast (`255.255.255.255`), and the subnet broadcast (`192.168.x.255`). These are all `static` entries that will never change — including them would cause noise in detection and could never produce a meaningful alert. Filtering to `dynamic` only left exactly the entries that matter: real devices with real, changeable MAC mappings.

**Testing ARP spoofing without a real attacker is harder than expected.** Windows actively defends gateway ARP entries — repeated attempts to overwrite `192.168.x.1` via `netsh` were either rejected or immediately overwritten by real ARP traffic from the router. The final testing approach (overwriting a non-gateway device entry) confirmed detection logic correctness without fighting OS-level protections.

**The gateway IP hardcoding problem led to a better design.** The original design used a `private static final String GATEWAY_IP` constant, which meant changing networks required recompiling. Switching to a command-line argument (`args[0]`) with a sensible default made the tool actually portable — a cleaner solution that also removed any personal network information from the source code.

---

## Known limitations

| Limitation | Impact | Planned fix |
|------------|--------|-------------|
| Gateway IP from CLI only | Must pass correct IP per network — no auto-detection | **v1.5:** parse `ipconfig` output via ProcessBuilder to detect gateway automatically |
| Windows-only MAC format | Regex expects hyphens (`aa-bb-cc`) — Linux/macOS use colons (`aa:bb:cc`) | **v1.5:** update regex separator to `[-:]` |
| Polling-based (not real-time) | 3-second blind spot between polls — a fast attack could poison and clean up undetected | **v3:** migrate to pcap4j packet capture for real-time ARP packet interception |
| No repeated-change detection | Can't distinguish "changed once, stable" from "changing every poll" (active attack signature) | **v2:** sliding window counter — gateway MAC changing N times within M polls → `[CRITICAL]` |
| Baseline never updates | A legitimate device change (new NIC) causes permanent WARNING alerts until restart | **v2:** accept command to update baseline for a specific IP |

The v2 sliding window design was reasoned through during development: a simple "consecutive changes" counter fails because ARP poisoning doesn't cause the value to change on *every* poll — the attacker re-poisons periodically, not continuously. A sliding window of recent poll results correctly captures "changed multiple times within a short window" while letting single one-off changes age out naturally.

---

## Stack

- **Language:** Java (no external dependencies)
- **OS interaction:** `ProcessBuilder` → `arp -a`
- **Data structures:** `HashMap<String, String>` for IP→MAC snapshots
- **Tested on:** Windows 10/11

---

## Portfolio context

This is project 2 of 4 in a deliberate security tooling sequence, each building on the concepts and Java skills from the previous:

1. [java-port-scanner](https://github.com/BTN101/java-port-scanner) — TCP socket fundamentals, threading, ExecutorService (54x speedup: 108s → 2s)
2. **java-arp-spoof-detector** — ProcessBuilder, ARP protocol, detection tier design ← *you are here*
3. Network traffic analyzer / lightweight IDS — pcap4j, real-time packet capture, rule-based detection
4. Honeypot — fake services, attacker behavior logging, perspective inversion

MIT License
