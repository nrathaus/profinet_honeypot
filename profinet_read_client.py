"""
PROFINET Read Client
--------------------
Reads records from the PROFINET soft target (profinet_honeypot.py)
using profinet-py.

Pre-populated records in the honeypot:
  slot=0, subslot=1, index=0xF830  -> I&M0 record
  slot=0, subslot=1, index=0xF000  -> SubmoduleState placeholder

Requirements:
    pip install profinet-py

Usage:
    sudo python3 profinet_read_client.py -i enp5s0 -m e8:9c:25:76:7f:a3
"""

import argparse
import struct

from profinet import ProfinetDevice, ethernet_socket, get_mac, get_station_info

DEVICE_STATION_NAME = "pn-soft-target"  # must match --station-name on the honeypot

KNOWN_RECORDS = [
    {"slot": 0, "subslot": 1, "index": 0xF830, "label": "I&M0"},
    {"slot": 0, "subslot": 1, "index": 0xF000, "label": "SubmoduleState"},
]


def parse_im0(data: bytes) -> dict:
    if len(data) < 40:
        return {"raw": data.hex()}
    r = {
        "vendor_name": data[0:20].rstrip(b"\x00 ").decode(errors="replace"),
        "order_id": data[20:40].rstrip(b"\x00 ").decode(errors="replace"),
    }
    if len(data) >= 56:
        r["serial_number"] = data[40:56].rstrip(b"\x00 ").decode(errors="replace")
    if len(data) >= 58:
        r["hw_revision"] = struct.unpack_from(">H", data, 56)[0]
    # SW revision: prefix(1) + functional_enhancement(1) + bug_fix(1) + internal_change(1)
    # Encoded as: b"V" + pack(">HH", major, minor) — 5 bytes total at offset 58
    if len(data) >= 63:
        sw_prefix = chr(data[58])
        sw_major = struct.unpack_from(">H", data, 59)[0]
        sw_minor = struct.unpack_from(">H", data, 61)[0]
        r["sw_revision"] = f"{sw_prefix}{sw_major}.{sw_minor}"
    if len(data) >= 65:
        r["revision_counter"] = struct.unpack_from(">H", data, 63)[0]
    if len(data) >= 67:
        r["profile_id"] = f"0x{struct.unpack_from('>H', data, 65)[0]:04X}"
    return r


def hexdump(data: bytes, indent: int = 6):
    pad = " " * indent
    for off in range(0, len(data), 16):
        chunk = data[off : off + 16]
        print(
            f"{pad}{off:04X}  {chunk.hex(' '):<47}  "
            f"{''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)}"
        )


def main():
    ap = argparse.ArgumentParser(description="PROFINET read client for soft target")
    ap.add_argument(
        "-i", "--iface", required=True, help="Network interface (e.g. enp5s0)"
    )
    ap.add_argument("-m", "--mac", required=True, help="Target MAC address")
    ap.add_argument(
        "--station-name",
        default=DEVICE_STATION_NAME,
        help=f"PROFINET station name (default: {DEVICE_STATION_NAME})",
    )
    ap.add_argument("--slot", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--subslot", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--index", type=lambda x: int(x, 0), default=None)
    args = ap.parse_args()

    reads = KNOWN_RECORDS
    if any(v is not None for v in (args.slot, args.index)):
        reads = [
            {
                "slot": args.slot if args.slot is not None else 0,
                "subslot": args.subslot if args.subslot is not None else 1,
                "index": args.index if args.index is not None else 0xF830,
                "label": "custom",
            }
        ]

    print(f"[*] Opening socket on {args.iface}...")
    try:
        sock = ethernet_socket(args.iface)
        src_mac = get_mac(args.iface)
    except Exception as e:
        print(f"[-] Socket error: {e}")
        return

    print(f"[*] Discovering {args.mac} ({args.station_name})...")
    try:
        info = get_station_info(sock, src_mac, args.station_name)
        print(f"[+] Found: {info}\n")
    except Exception as e:
        print(f"[-] Discovery failed: {e}")
        return

    print(f"[*] Connecting...")
    try:
        device = ProfinetDevice.from_dcp_info(info, args.iface)
        device.connect()
        print(f"[+] Connected\n")
    except Exception as e:
        print(f"[-] Connect failed: {e}")
        return

    for r in reads:
        print(
            f"[>] Read {r['label']}  slot={r['slot']} subslot={r['subslot']} index=0x{r['index']:04X}"
        )
        try:
            data = device.read(slot=r["slot"], subslot=r["subslot"], index=r["index"])
            print(f"    {len(data)} bytes received")
            if r["index"] == 0xF830 and len(data) >= 40:
                print("    Parsed I&M0:")
                for k, v in parse_im0(data).items():
                    print(f"      {k:<18} = {v}")
            else:
                hexdump(data)
        except Exception as e:
            print(f"    [-] Read failed: {e}")
        print()

    try:
        device.disconnect()
        print("[*] Disconnected")
    except Exception as e:
        print(f"[!] Disconnect failed: {e}")


if __name__ == "__main__":
    main()
