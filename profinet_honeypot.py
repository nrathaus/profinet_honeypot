"""
PROFINET Soft Target / Honeypot
================================
Listens for and responds to:
  - PROFINET DCP  (EtherType 0x8892) - Identify, Set
  - PROFINET RT   (EtherType 0x8892) - Cyclic frames, Alarms
  - PROFINET I/O  (DCE/RPC over UDP port 34964) - Connect, Read, Write,
                                                    Release, ImplicitRead

Requirements:
    pip install scapy

Usage:
    sudo python profinet_target.py -i eth0 --ip 192.168.1.10
"""

import argparse
import datetime
import json
import socket
import struct
import threading
import time
import traceback

from collections import defaultdict
from http.server import BaseHTTPRequestHandler, HTTPServer

from scapy.all import Ether, conf, get_if_addr, get_if_hwaddr, sendp, sniff

# -- Constants -----------------------------------------------------------------
PROFINET_ETHERTYPE = 0x8892
PROFINET_MCAST_DCP = "01:0e:cf:00:00:00"
PNIO_RPC_PORT = 34964

FRAMEID_DCP_IDENTIFY = 0xFEFE
FRAMEID_DCP_HELLO = 0xFEFF
FRAMEID_RT_MIN = 0x8000
FRAMEID_RT_MAX = 0xBFFF
FRAMEID_ALARM_HIGH = 0xFC01
FRAMEID_ALARM_LOW = 0xFE01

DCP_SRV_IDENTIFY = 0x05
DCP_SRV_SET = 0x04
DCP_SRV_GET = 0x03
DCP_REQ = 0x00
DCP_RSP = 0x01

RPC_PKT_REQUEST = 0x00
RPC_PKT_RESPONSE = 0x02
RPC_PKT_REJECT = 0x04

OPNUM_CONNECT = 0
OPNUM_RELEASE = 1
OPNUM_READ = 2
OPNUM_WRITE = 3
OPNUM_CONTROL = 4
OPNUM_READ_IMPLICIT = 5

AR_TYPE_DEVICE_ACCESS = 0x0006

# -- Shared state --------------------------------------------------------------
stats = {
    "started": datetime.datetime.now(datetime.UTC),
    "total_received": 0,
    "total_replied": 0,
    "errors": 0,
    "by_type": defaultdict(int),
    "malformed": 0,
    "last_frame_at": None,
}
stats_lock = threading.Lock()
log_lines = []
LOG_MAX = 500

DEVICE_CONFIG = {
    "station_name": "pn-soft-target",
    "vendor_id": 0x002A,
    "device_id": 0x0001,
    "device_role": 0x01,
    "ip": "192.168.1.10",
    "mask": "255.255.255.0",
    "gw": "192.168.1.1",
}

# Record store: (slot, subslot, index) -> bytes
RECORD_STORE: dict[tuple, bytes] = {}


def _make_im0() -> bytes:
    data = b"SoftTarget GmbH     "[:20]
    data += b"SoftDevice01        "[:20]
    data += b"SN-00000001     "[:16]
    data += struct.pack(">H", 0x0000)
    data += b"V" + struct.pack(">HH", 1, 0)
    data += struct.pack(">HHHH", 0x0000, 0x001E, 0x0003, 0x0101)
    data += struct.pack(">H", 0x0000)
    return data


RECORD_STORE[(0, 1, 0xF830)] = _make_im0()
RECORD_STORE[(0, 1, 0xF000)] = b"\x00" * 4

# -- Logging -------------------------------------------------------------------


def log(level: str, msg: str):
    """Log"""
    ts = datetime.datetime.now(datetime.UTC).strftime("%H:%M:%S.%f")[:-3]
    line = f"[{ts}] [{level}] {msg}"
    print(line)
    log_lines.append(line)
    if len(log_lines) > LOG_MAX:
        log_lines.pop(0)


def bump(key: str):
    """Increase by one the message type"""
    with stats_lock:
        stats["by_type"][key] += 1
        stats["total_received"] += 1
        stats["last_frame_at"] = datetime.datetime.now(datetime.UTC).isoformat()


def bump_reply():
    """Increase by one how many messages we replied to"""
    with stats_lock:
        stats["total_replied"] += 1


def bump_error():
    """Increase by one how many errors we sent"""
    with stats_lock:
        stats["errors"] += 1


def bump_malformed():
    """Increase by one how many malformed messages we saw"""
    with stats_lock:
        stats["malformed"] += 1


# -- DCE/RPC -------------------------------------------------------------------


def parse_rpc_header(data: bytes) -> dict:
    """Parse 80-byte DCE/RPC connectionless header.
    Stores raw bytes for fields that must be echoed verbatim.
    All integer fields are big-endian (drep=0x00).
    """
    if len(data) < 80:
        raise ValueError(f"RPC header too short: {len(data)}")
    little_endian = (data[4] & 0x0F) == 0x01
    e = "<" if little_endian else ">"
    return {
        "version": data[0],
        "pkt_type": data[1],
        "flags1": data[2],
        "flags2": data[3],
        "little_endian": little_endian,
        "data_rep": data[4:8],
        "obj_uuid": data[8:24],
        "if_uuid": data[24:40],
        "act_uuid": data[40:56],
        "boot_time_raw": data[56:60],
        "if_version_raw": data[60:64],
        "call_id_raw": data[64:68],
        "opnum_raw": data[68:70],
        "call_id": struct.unpack_from(f"{e}I", data, 64)[0],
        "opnum": struct.unpack_from(f"{e}H", data, 68)[0],
        "frag_len": struct.unpack_from(f"{e}H", data, 74)[0],
        "body": data[80:],
    }


def build_rpc_response(
    req_hdr: dict, body: bytes, pkt_type: int = RPC_PKT_RESPONSE
) -> bytes:
    """Build DCE/RPC response header.

    - Echoes obj/if/act UUIDs, call_id, opnum, data_rep verbatim from request.
    - length_of_body = len(body), big-endian (profinet-py uses Int16ub).
    - All header fields big-endian to match drep=0x00.
    """
    hdr = bytearray(80)
    hdr[0] = 4
    hdr[1] = pkt_type
    hdr[2] = 0x20  # idempotent
    hdr[3] = 0x00
    hdr[4:8] = req_hdr["data_rep"]
    hdr[8:24] = req_hdr["obj_uuid"]
    hdr[24:40] = req_hdr["if_uuid"]
    hdr[40:56] = req_hdr["act_uuid"]
    hdr[56:60] = req_hdr["boot_time_raw"]
    hdr[60:64] = req_hdr["if_version_raw"]
    hdr[64:68] = req_hdr["call_id_raw"]
    hdr[68:70] = req_hdr["opnum_raw"]
    # All header integers big-endian (matching profinet-py's Int16ub/Int32ub)
    struct.pack_into(">H", hdr, 70, 0xFFFF)  # interface_hint
    struct.pack_into(">H", hdr, 72, 0xFFFF)  # activity_hint
    struct.pack_into(">H", hdr, 74, len(body))  # length_of_body
    struct.pack_into(">H", hdr, 76, 0)  # fragment_number
    hdr[78] = 0  # auth_proto
    hdr[79] = 0  # serial_lo
    return bytes(hdr) + body


def pnio_block(btype: int, version: int, data: bytes) -> bytes:
    blen = len(data) + 2
    return (
        struct.pack(">HHbb", btype, blen, (version >> 8) & 0xFF, version & 0xFF) + data
    )


def make_nrd(payload: bytes) -> bytes:
    """Build NRD wrapper (profinet-py PNNRDData, big-endian):
    args_maximum_status(4)=0 + args_length(4) + maximum_count(4) + offset(4) + actual_count(4)
    """
    n = len(payload)
    return struct.pack(">IIIII", 0, n, n, 0, n) + payload


# -- DCP response builders -----------------------------------------------------


def build_dcp_response(src_mac: str, dst_mac: str, xid: int, frame_id: int) -> bytes:
    ip_bytes = socket.inet_aton(DEVICE_CONFIG["ip"])
    mask_bytes = socket.inet_aton(DEVICE_CONFIG["mask"])
    gw_bytes = socket.inet_aton(DEVICE_CONFIG["gw"])

    def dcp_block(opt, subopt, block_info, data):
        payload = struct.pack(">H", block_info) + data
        pad = b"\x00" if len(payload) % 2 else b""
        return struct.pack(">BBH", opt, subopt, len(payload)) + payload + pad

    dcp_payload = (
        dcp_block(0x01, 0x02, 0x0000, ip_bytes + mask_bytes + gw_bytes)
        + dcp_block(0x02, 0x02, 0x0000, DEVICE_CONFIG["station_name"].encode())
        + dcp_block(0x02, 0x01, 0x0000, b"SoftTarget GmbH")
        + dcp_block(
            0x02,
            0x03,
            0x0000,
            struct.pack(">HH", DEVICE_CONFIG["vendor_id"], DEVICE_CONFIG["device_id"]),
        )
        + dcp_block(0x02, 0x04, 0x0000, bytes([DEVICE_CONFIG["device_role"], 0x00]))
    )
    hdr = bytes(
        [
            (frame_id >> 8) & 0xFF,
            frame_id & 0xFF,
            DCP_SRV_IDENTIFY,
            DCP_RSP,
        ]
    ) + struct.pack(">IHH", xid, 0x0000, len(dcp_payload))
    return bytes(
        Ether(src=src_mac, dst=dst_mac, type=PROFINET_ETHERTYPE) / (hdr + dcp_payload)
    )


def build_dcp_set_response(src_mac: str, dst_mac: str, xid: int) -> bytes:
    block = struct.pack(">BBHH", 0x05, 0x01, 0x0002, 0x0000)
    hdr = bytes(
        [
            (FRAMEID_DCP_HELLO >> 8) & 0xFF,
            FRAMEID_DCP_HELLO & 0xFF,
            DCP_SRV_SET,
            DCP_RSP,
        ]
    ) + struct.pack(">IHH", xid, 0x0000, len(block))
    return bytes(
        Ether(src=src_mac, dst=dst_mac, type=PROFINET_ETHERTYPE) / (hdr + block)
    )


# -- PN-IO connect -------------------------------------------------------------


def parse_connect_request(body: bytes) -> dict:
    """Parse ARBlockReq. Request NRD is 20 bytes, block header is 6 bytes."""
    ar = {}
    offset = 20 + 6  # NRD(20) + block type(2)+len(2)+version(2)
    if len(body) < offset + 20:
        log("WARN", f"  Connect body too short: {len(body)}")
        return ar
    block_type = struct.unpack_from(">H", body, 20)[0]
    block_len = struct.unpack_from(">H", body, 22)[0]
    log("INFO", f"  ARBlockReq block_type=0x{block_type:04X} block_len={block_len}")
    if block_type == 0x0101:
        ar["ar_type"] = struct.unpack_from(">H", body, offset)[0]
        offset += 2
        ar["ar_uuid"] = body[offset : offset + 16]
        offset += 16
        ar["session_key"] = struct.unpack_from(">H", body, offset)[0]
        log("INFO", f"  ar_type=0x{ar['ar_type']:04X} session_key={ar['session_key']}")
    else:
        log("WARN", f"  Unexpected block_type=0x{block_type:04X}")
    return ar


def build_connect_response(req_hdr: dict) -> bytes:
    ar = parse_connect_request(req_hdr["body"])
    ar_type = ar.get("ar_type", 0x0001)
    ar_uuid = ar.get("ar_uuid", b"\x00" * 16)
    session_key = ar.get("session_key", 0x0001)

    # ARBlockRes: ar_type(2) + ar_uuid(16) + session_key(2) +
    #             ActivityTimeoutFactor(2) + CMResponderUDPRTPort(2) + CMResponderMACAdd(6)
    ar_block = pnio_block(
        0x8101,
        0x0100,
        struct.pack(">H", ar_type)
        + ar_uuid
        + struct.pack(">HHH", session_key, 100, PNIO_RPC_PORT)
        + bytes(6),
    )

    if ar_type == AR_TYPE_DEVICE_ACCESS:
        resp_blocks = ar_block
    else:
        iocr_block = pnio_block(
            0x8102, 0x0100, struct.pack(">HHH", 0x0001, 0x0001, 0xC000)
        )
        mod_body = struct.pack(">HI", 1, 0)
        mod_body += struct.pack(">HH", 1, 0)
        mod_body += struct.pack(">IHH", 0x00000001, 0, 1)
        mod_body += struct.pack(">HIHHH", 0x00000001, 1, 0, 0, 0)
        mod_block = pnio_block(0x8104, 0x0100, mod_body)
        resp_blocks = ar_block + iocr_block + mod_block

    return build_rpc_response(req_hdr, make_nrd(resp_blocks))


# -- PN-IO read/write/release/implicit -----------------------------------------


def parse_read_request(body: bytes) -> dict:
    """Parse PN-IO Read request body.
    Layout: NRD(20) + PNIODHeader:
      block_header(6) + sequence_number(2) + ar_uuid(16) +
      api(4) + slot(2) + subslot(2) + padding(2) + index(2) + length(4)
    """
    req = {
        "ar_uuid": b"\x00" * 16,
        "api": 0,
        "slot": 0,
        "subslot": 0,
        "index": 0,
        "length": 0x400,
    }
    try:
        off = 20 + 6 + 2  # NRD + block_header + seq_num
        req["ar_uuid"] = body[off : off + 16]
        off += 16
        (req["api"],) = struct.unpack_from(">I", body, off)
        off += 4
        (req["slot"],) = struct.unpack_from(">H", body, off)
        off += 2
        (req["subslot"],) = struct.unpack_from(">H", body, off)
        off += 2
        off += 2  # padding
        (req["index"],) = struct.unpack_from(">H", body, off)
        off += 2
        (req["length"],) = struct.unpack_from(">I", body, off)
    except Exception:
        pass
    return req


def build_read_response(req_hdr: dict) -> bytes:
    req = parse_read_request(req_hdr["body"])
    key = (req["slot"], req["subslot"], req["index"])
    record = RECORD_STORE.get(key, bytes(min(req["length"], 64)))
    log(
        "INFO",
        f"  Read slot={req['slot']} subslot={req['subslot']} "
        f"index=0x{req['index']:04X} -> {len(record)} bytes "
        f"({'hit' if key in RECORD_STORE else 'miss'})",
    )

    # PNIODHeader response (80 bytes):
    # block_header(6) + seq(2) + ar_uuid(16) + api(4) + slot(2) + subslot(2) +
    # padding(2) + index(2) + length(4) + target_ar_uuid(16) + padding2(8)
    blk_hdr = struct.pack(">HHbb", 0x8009, 60, 0x01, 0x00)
    iod_hdr = (
        blk_hdr
        + struct.pack(">H", 0)
        + req["ar_uuid"]
        + struct.pack(
            ">IHHHHI",
            req["api"],
            req["slot"],
            req["subslot"],
            0,
            req["index"],
            len(record),
        )
        + b"\x00" * 16
        + b"\x00" * 8
    )

    nrd_payload = iod_hdr + record
    log(
        "INFO",
        f"  ReadRSP ndr_first4={struct.pack('>I', 0).hex()} "
        f"nrd_payload={len(nrd_payload)} bytes",
    )
    return build_rpc_response(req_hdr, make_nrd(nrd_payload))


def build_write_response(req_hdr: dict) -> bytes:
    body = req_hdr["body"]
    ar_uuid = body[28:44] if len(body) >= 44 else b"\x00" * 16
    resp_body = ar_uuid + struct.pack(">IHHIHH", 0, 0, 0, 0, 0, 0)
    resp_body += b"\x00" * 10
    return build_rpc_response(req_hdr, make_nrd(resp_body))


def build_release_response(req_hdr: dict) -> bytes:
    body = req_hdr["body"]
    ar_uuid = body[28:44] if len(body) >= 44 else b"\x00" * 16
    return build_rpc_response(req_hdr, make_nrd(ar_uuid + b"\x00" * 4))


def build_implicit_read_response(req_hdr: dict) -> bytes:
    return build_read_response(req_hdr)


# -- Frame handlers ------------------------------------------------------------


def handle_dcp(pkt, iface: str, src_mac: str):
    """Handle DCP"""
    raw = bytes(pkt)
    sender_mac = pkt[Ether].src
    payload = raw[14:]
    if len(payload) < 10:
        bump_malformed()
        log("WARN", f"DCP frame too short ({len(payload)} bytes) from {sender_mac}")
        return
    try:
        svc_id = payload[2]
        svc_type = payload[3]
        xid = struct.unpack_from(">I", payload, 4)[0]
        if svc_type != DCP_REQ:
            return

        if svc_id == DCP_SRV_IDENTIFY:
            bump("dcp_identify")
            log("INFO", f"DCP Identify REQ  xid=0x{xid:08X} from {sender_mac}")
            time.sleep(0.002)
            sendp(
                build_dcp_response(src_mac, sender_mac, xid, FRAMEID_DCP_IDENTIFY),
                iface=iface,
                verbose=False,
            )
            bump_reply()
            log("INFO", f"DCP Identify RSP  xid=0x{xid:08X} -> {sender_mac}")
        elif svc_id == DCP_SRV_SET:
            bump("dcp_set")
            log("INFO", f"DCP Set REQ       xid=0x{xid:08X} from {sender_mac}")
            sendp(
                build_dcp_set_response(src_mac, sender_mac, xid),
                iface=iface,
                verbose=False,
            )
            bump_reply()
            log("INFO", f"DCP Set RSP       xid=0x{xid:08X} -> {sender_mac}")
        elif svc_id == DCP_SRV_GET:
            bump("dcp_get")
            log("INFO", f"DCP Get REQ       xid=0x{xid:08X} from {sender_mac}")
            sendp(
                build_dcp_response(src_mac, sender_mac, xid, FRAMEID_DCP_IDENTIFY),
                iface=iface,
                verbose=False,
            )
            bump_reply()
        else:
            bump("dcp_unknown")
            log("WARN", f"DCP unknown svc_id=0x{svc_id:02X} from {sender_mac}")
    except Exception as e:
        bump_malformed()
        log("ERROR", f"DCP parse error: {e} | raw={payload[:32].hex()}")


def handle_rt(pkt, iface: str, src_mac: str):
    """Handle RT packets"""
    raw = bytes(pkt)
    payload = raw[14:]
    src = pkt[Ether].src
    try:
        if len(payload) < 4:
            raise ValueError("RT frame too short")

        frame_id = struct.unpack_from(">H", payload, 0)[0]
        if FRAMEID_RT_MIN <= frame_id <= FRAMEID_RT_MAX:
            bump("rt_cyclic")
            echo_data = b"\x00" * max(0, len(payload) - 6)
            cycle = struct.unpack_from(">H", payload, len(payload) - 4)[0] + 1
            reply_pl = (
                struct.pack(">H", frame_id)
                + echo_data
                + struct.pack(">HBB", cycle & 0xFFFF, 0x35, 0x00)
            )
            sendp(
                bytes(Ether(src=src_mac, dst=src, type=PROFINET_ETHERTYPE) / reply_pl),
                iface=iface,
                verbose=False,
            )
            bump_reply()
        elif frame_id in (FRAMEID_ALARM_HIGH, FRAMEID_ALARM_LOW):
            bump("rt_alarm")
            log("WARN", f"RT Alarm fid=0x{frame_id:04X} from {src}")
            ack_pl = struct.pack(">H", frame_id) + b"\x00" * 8
            sendp(
                bytes(Ether(src=src_mac, dst=src, type=PROFINET_ETHERTYPE) / ack_pl),
                iface=iface,
                verbose=False,
            )
            bump_reply()
        else:
            bump("rt_other")
    except Exception as e:
        bump_malformed()
        log("ERROR", f"RT parse error: {e} | raw={payload[:32].hex()}")


def handle_pnio_rpc(data: bytes, addr: tuple, sock: socket.socket):
    src_addr, src_port = addr
    try:
        rpc = parse_rpc_header(data)
    except ValueError as e:
        bump_malformed()
        log("WARN", f"RPC bad header from {src_addr}: {e}")
        return
    opnum = rpc["opnum"]
    cid = rpc["call_id"]
    try:
        if opnum == OPNUM_CONNECT:
            bump("pnio_connect")
            log("INFO", f"PN-IO Connect    cid={cid} from {src_addr}:{src_port}")
            resp = build_connect_response(rpc)
            sock.sendto(resp, addr)
            bump_reply()
            log("INFO", f"PN-IO ConnectRSP cid={cid} -> {src_addr}")
        elif opnum == OPNUM_READ:
            bump("pnio_read")
            log("INFO", f"PN-IO Read       cid={cid} from {src_addr}:{src_port}")
            resp = build_read_response(rpc)
            sock.sendto(resp, addr)
            bump_reply()
        elif opnum == OPNUM_WRITE:
            bump("pnio_write")
            log("INFO", f"PN-IO Write      cid={cid} from {src_addr}:{src_port}")
            sock.sendto(build_write_response(rpc), addr)
            bump_reply()
        elif opnum == OPNUM_RELEASE:
            bump("pnio_release")
            log("INFO", f"PN-IO Release    cid={cid} from {src_addr}:{src_port}")
            sock.sendto(build_release_response(rpc), addr)
            bump_reply()
        elif opnum == OPNUM_READ_IMPLICIT:
            bump("pnio_implicit_read")
            log("INFO", f"PN-IO ImplRead   cid={cid} from {src_addr}:{src_port}")
            sock.sendto(build_implicit_read_response(rpc), addr)
            bump_reply()
        else:
            bump("pnio_unknown")
            log("WARN", f"PN-IO unknown opnum={opnum} cid={cid} from {src_addr}")
            sock.sendto(
                build_rpc_response(rpc, b"\x00" * 4, pkt_type=RPC_PKT_REJECT), addr
            )
    except Exception as e:
        bump_error()
        log("ERROR", f"PN-IO handler opnum={opnum}: {e}\n{traceback.format_exc()}")


def make_pn_handler(iface: str, src_mac: str, own_mac: str, skip_our_packets: bool):
    def handler(pkt):
        try:
            if not pkt.haslayer(Ether):
                return
            if skip_our_packets and pkt[Ether].src.lower() == own_mac.lower():
                return
            if pkt[Ether].type != PROFINET_ETHERTYPE:
                return
            raw = bytes(pkt)
            payload = raw[14:]
            if len(payload) < 2:
                bump_malformed()
                return
            frame_id = struct.unpack_from(">H", payload, 0)[0]
            if frame_id in (FRAMEID_DCP_IDENTIFY, FRAMEID_DCP_HELLO):
                handle_dcp(pkt, iface, src_mac)
            else:
                handle_rt(pkt, iface, src_mac)
        except Exception as e:
            bump_error()
            log("ERROR", f"Dispatcher: {e}")

    return handler


def pnio_udp_server(bind_ip: str):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((bind_ip, PNIO_RPC_PORT))
    except OSError as e:
        log("ERROR", f"Cannot bind UDP {bind_ip}:{PNIO_RPC_PORT}: {e}")
        return
    log("INFO", f"PN-IO RPC listener on udp {bind_ip}:{PNIO_RPC_PORT}")
    while True:
        try:
            data, addr = sock.recvfrom(65535)
            threading.Thread(
                target=handle_pnio_rpc, args=(data, addr, sock), daemon=True
            ).start()
        except Exception as e:
            log("ERROR", f"UDP recv: {e}")


# -- HTTP stats API ------------------------------------------------------------


class StatsHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        if self.path in ("/stats", "/stats/"):
            with stats_lock:
                payload = json.dumps(
                    {
                        **stats,
                        "by_type": dict(stats["by_type"]),
                        "log_tail": log_lines[-50:],
                    },
                    default=str,
                    indent=2,
                ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", len(payload))
            self.end_headers()
            self.wfile.write(payload)
        elif self.path in ("/reset", "/reset/"):
            with stats_lock:
                stats["total_received"] = 0
                stats["total_replied"] = 0
                stats["errors"] = 0
                stats["malformed"] = 0
                stats["by_type"] = defaultdict(int)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"status":"reset"}')
        else:
            self.send_response(404)
            self.end_headers()


def run_http(port: int):
    srv = HTTPServer(("0.0.0.0", port), StatsHandler)
    log("INFO", f"Stats API on http://0.0.0.0:{port}/stats")
    srv.serve_forever()


# -- Main ----------------------------------------------------------------------


def main():
    ap = argparse.ArgumentParser(
        description="PROFINET Soft Target - DCP + RT + PN-IO responder"
    )
    ap.add_argument(
        "-i", "--iface", required=True, help="Network interface (e.g. eth0)"
    )
    ap.add_argument(
        "--ip", default="", help="IP for PN-IO RPC binding (defaults to interface IP)"
    )
    ap.add_argument(
        "--station-name",
        default="pn-soft-target",
        help="PROFINET station name advertised in DCP",
    )
    ap.add_argument(
        "--http-port", type=int, default=8080, help="Stats HTTP API port (default 8080)"
    )
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    DEVICE_CONFIG["ip"] = args.ip or get_if_addr(args.iface)
    DEVICE_CONFIG["station_name"] = args.station_name
    conf.verb = 0

    src_mac = get_if_hwaddr(args.iface)
    log("INFO", "PROFINET Soft Target starting")
    log("INFO", f"  Interface    : {args.iface}  MAC={src_mac}")
    log("INFO", f"  Station name : {DEVICE_CONFIG['station_name']}")
    log("INFO", f"  IP (PN-IO)   : {DEVICE_CONFIG['ip']}")

    threading.Thread(
        target=pnio_udp_server, args=(DEVICE_CONFIG["ip"],), daemon=True
    ).start()
    threading.Thread(target=run_http, args=(args.http_port,), daemon=True).start()

    handler = make_pn_handler(args.iface, src_mac, src_mac, skip_our_packets=False)
    log("INFO", f"Listening for PROFINET frames on {args.iface}  (Ctrl+C to stop)\n")
    try:
        sniff(iface=args.iface, filter="ether proto 0x8892", prn=handler, store=False)
    except KeyboardInterrupt:
        pass
    log("INFO", "Target stopped.")


if __name__ == "__main__":
    main()
