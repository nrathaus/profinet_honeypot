# PROFINET Soft Target & Read Client

A Python-based PROFINET soft target (honeypot) and test client for security research and protocol testing. Built with [Scapy](https://scapy.net/) and [profinet-py](https://pypi.org/project/profinet-py/).

> ⚠️ **Legal notice:** Only use these tools against devices and networks you own or have explicit written authorization to test.

---

## Components

| File | Description |
|---|---|
| `profinet_target.py` | Soft target that receives and responds to PROFINET requests |
| `profinet_read_client.py` | Test client that reads records from the soft target |

---

## Requirements

```bash
pip install scapy profinet-py
```

Raw socket access requires root or `CAP_NET_RAW`:

```bash
sudo python3 profinet_target.py ...
```

---

## `profinet_target.py` - Soft Target / Honeypot

A spec-plausible PROFINET device that responds to incoming requests.

### Supported protocols

| Protocol | Transport | Description |
|---|---|---|
| DCP Identify | EtherType 0x8892 | Responds with device info (IP, name, vendor/device ID, role) |
| DCP Set | EtherType 0x8892 | Acknowledges set requests |
| DCP Get | EtherType 0x8892 | Returns device info block |
| RT Cyclic | EtherType 0x8892 | Echoes frames with incremented cycle counter |
| RT Alarm | EtherType 0x8892 | Sends alarm acknowledgement |
| PN-IO Connect | UDP :34964 | Accepts DeviceAccess AR and standard IO ARs |
| PN-IO Read | UDP :34964 | Returns records from the record store |
| PN-IO Write | UDP :34964 | Acknowledges writes |
| PN-IO Release | UDP :34964 | Confirms AR teardown |
| PN-IO ImplicitRead | UDP :34964 | Returns records without an established AR |

### Pre-populated records

| Slot | Subslot | Index | Description |
|---|---|---|---|
| 0 | 1 | 0xF830 | I&M0 (vendor, order ID, serial, HW/SW revision) |
| 0 | 1 | 0xF000 | SubmoduleState placeholder |

### Usage

```bash
sudo python3 profinet_target.py -i eth0
```

```
options:
  -i, --iface       Network interface (required)
  --ip              IP for PN-IO RPC binding (default: interface IP)
  --station-name    PROFINET station name advertised in DCP (default: pn-soft-target)
  --http-port       Stats HTTP API port (default: 8080)
  -v, --verbose     Show debug-level RT frame logs
```

### Stats API

```bash
# Live stats + last 50 log lines
curl http://localhost:8080/stats

# Reset counters
curl http://localhost:8080/reset
```

---

## `profinet_read_client.py`

Reads records from the soft target using `profinet-py` to verify correct responses.

### Usage

```bash
# Read I&M0 record
sudo python3 profinet_read_client.py \
  -i enp5s0 \
  -m e8:9c:25:76:7f:a3 \
  --slot 0 --subslot 1 --index 0xF830

# Read all pre-populated records
sudo python3 profinet_read_client.py \
  -i enp5s0 \
  -m e8:9c:25:76:7f:a3
```

```
options:
  -i, --iface         Network interface (required)
  -m, --mac           Target MAC address (required)
  --station-name      PROFINET station name (default: pn-soft-target)
  --slot              Slot number (hex or decimal)
  --subslot           Subslot number (hex or decimal)
  --index             Record index (hex or decimal)
```

### Example output

```
[*] Discovering e8:9c:25:76:7f:a3 (pn-soft-target)...
[+] Found: PROFINET Device: pn-soft-target
  IP: 10.20.0.126  Vendor: SIEMENS AG (0x002A)

[*] Connecting...
[+] Connected

[>] Read I&M0  slot=0 subslot=1 index=0xF830
    73 bytes received
    Parsed I&M0:
      vendor_name        = SoftTarget GmbH
      order_id           = SoftDevice01
      serial_number      = SN-00000001
      hw_revision        = 0
      sw_revision        = V1.0
      profile_id         = 0x001E

[*] Disconnected
```

---

## Recommended test workflow

```bash
# Terminal 1 - start the soft target
sudo python3 profinet_target.py -i eth0 --station-name pn-soft-target

# Terminal 2 - verify with the read client
sudo python3 profinet_read_client.py -i eth0 -m <target-MAC>

# Monitor stats
watch -n1 'curl -s http://localhost:8080/stats | python3 -m json.tool'
```

---

## Architecture notes

- **DCP** frames are handled via Scapy raw Ethernet sniffing (EtherType 0x8892).
- **PN-IO** frames use DCE/RPC connectionless protocol over UDP port 34964, with big-endian NDR encoding (`drep=0x00`).
- The soft target echoes RPC header fields (UUIDs, call_id, opnum) verbatim from the request to ensure correct session correlation.
- All handlers are wrapped in `try/except` so malformed frames are counted and logged rather than crashing the target.