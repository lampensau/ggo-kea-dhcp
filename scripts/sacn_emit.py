#!/usr/bin/env python3
"""Emit valid E1.31 (sACN) traffic to exercise the netmon sACN detector.

The detector keys "senders" on the 16-byte CID in the root layer, not on the
source IP - so multiple senders are just multiple CIDs from one ordinary UDP
multicast socket. No root, no raw sockets, no IP spoofing needed.

Scenarios (--scenario):
  normal     one sender on the universe (baseline, priority set)
  conflict   two senders, SAME universe + SAME priority -> "universe conflict"
  backup     two senders, SAME universe, DIFFERENT priority -> backed-up (info)
  multi      several universes, one sender each
  dupcid     two senders sharing ONE CID, different names -> "duplicate CID"
  terminate  conflict pair; sender B cleanly terminates -> conflict clears
  badvector  non-data framing vector -> detector should IGNORE it

Examples:
  ./sacn_emit.py                         # normal, universe 1, prio 100
  ./sacn_emit.py --scenario conflict     # trip the conflict warning
  ./sacn_emit.py --scenario dupcid       # the duplicate-CID doublette
  ./sacn_emit.py --scenario terminate    # watch a conflict clear cleanly
  ./sacn_emit.py --self-test             # build+parse a packet, no network
"""
import argparse
import socket
import struct
import sys
import time

SACN_PORT = 5568
ACN_PID = b"ASC-E1.17\x00\x00\x00"


STREAM_TERMINATED = 0x40   # E1.31 Options bit: source cleanly stops the universe


def build_packet(cid: bytes, source_name: str, priority: int, universe: int,
                 sequence: int, dmx: bytes, options: int = 0,
                 vector: int = 0x00000002) -> bytes:
    """Build a full E1.31 data packet (root + framing + DMP layers).

    Layout matches the detector's hard-coded offsets: CID@22, priority@108,
    options@112, universe@113. dmx is 512 slot bytes. vector defaults to
    VECTOR_E131_DATA_PACKET; override to emit a non-data (e.g. sync) packet.
    """
    assert len(cid) == 16
    assert len(dmx) == 512
    name = source_name.encode()[:63].ljust(64, b"\x00")

    # DMP layer: vector, addr+data type, first addr, increment, count, start+slots
    dmp = struct.pack("!BB HH H", 0x02, 0xa1, 0x0000, 0x0001, 1 + 512)
    dmp += b"\x00" + dmx                       # DMX start code (0) + 512 slots
    dmp = flags_len(len(dmp) + 2) + dmp        # +2 for the flags/len field itself

    # Framing layer
    framing = struct.pack("!I", vector)
    framing += name
    framing += struct.pack("!B", priority & 0xff)
    framing += struct.pack("!H", 0)            # sync universe
    framing += struct.pack("!B", sequence & 0xff)
    framing += struct.pack("!B", options & 0xff)
    framing += struct.pack("!H", universe & 0xffff)
    framing += dmp
    framing = flags_len(len(framing) + 2) + framing

    # Root layer
    root = struct.pack("!H", 0x0010)           # preamble size
    root += struct.pack("!H", 0x0000)          # post-amble size
    root += ACN_PID
    body = struct.pack("!I", 0x00000004) + cid + framing  # VECTOR_ROOT_E131_DATA
    root += flags_len(len(body) + 2) + body
    return root


def flags_len(length: int) -> bytes:
    """2-byte field: top nibble 0x7 (flags), low 12 bits = PDU length."""
    return struct.pack("!H", 0x7000 | (length & 0x0fff))


def cid_for(n: int) -> bytes:
    # ponytail: deterministic fake CID per sender index; real sources use a UUID.
    return (bytes([(0xa0 + n) & 0xff]) + b"-ggo-netmon-test")[:16].ljust(16, b"\x00")


def mcast_addr(universe: int) -> str:
    return f"239.255.{(universe >> 8) & 0xff}.{universe & 0xff}"


def senders_for(scenario: str, universe: int):
    """Return list of (universe, priority, name, cid) to transmit each tick."""
    if scenario == "normal":
        return [(universe, 100, "ggo-normal", cid_for(0))]
    if scenario == "conflict":
        return [(universe, 100, "ggo-A", cid_for(0)),
                (universe, 100, "ggo-B", cid_for(1))]
    if scenario == "backup":
        return [(universe, 100, "ggo-primary", cid_for(0)),
                (universe, 80, "ggo-backup", cid_for(1))]
    if scenario == "multi":
        return [(universe + i, 100, f"ggo-u{universe + i}", cid_for(i))
                for i in range(3)]
    if scenario == "dupcid":
        # SAME CID, different source names = two devices misconfigured alike.
        shared = cid_for(0)
        return [(universe, 100, "ggo-Console-A", shared),
                (universe, 100, "ggo-Console-B", shared)]
    if scenario == "terminate":
        # Conflict pair; sender B cleanly terminates mid-run (see run()).
        return [(universe, 100, "ggo-A", cid_for(0)),
                (universe, 100, "ggo-B", cid_for(1))]
    if scenario == "badvector":
        return [(universe, 100, "ggo-sync", cid_for(0))]
    raise SystemExit(f"unknown scenario: {scenario}")


def run(args):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, args.ttl)
    if args.iface:
        # ip_mreqn{multiaddr, address, ifindex}; selecting by ifindex is the
        # reliable Linux way (a bare in_addr gives EADDRNOTAVAIL on some hosts).
        mreqn = struct.pack("@4s4si", b"\x00\x00\x00\x00", b"\x00\x00\x00\x00",
                            socket.if_nametoindex(args.iface))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, mreqn)

    plan = senders_for(args.scenario, args.universe)
    print(f"scenario={args.scenario} senders={len(plan)} rate={args.rate}Hz "
          f"ttl={args.ttl} iface={args.iface or 'default'} (ctrl-c to stop)")
    for u, prio, name, _ in plan:
        print(f"  -> universe {u} prio {prio} '{name}' via {mcast_addr(u)}:{SACN_PORT}")

    vector = 0x00000008 if args.scenario == "badvector" else 0x00000002
    if vector != 0x00000002:
        print("  (non-data framing vector - detector should IGNORE these)")

    seq = {}  # per-CID sequence counter
    level = 0
    start = time.monotonic()
    terminated = False
    try:
        while True:
            elapsed = time.monotonic() - start
            level = (level + 8) & 0xff
            dmx = bytes([level]) * 512   # all channels at a slow ramp - "live" data

            # terminate scenario: after N seconds, sender B sends 3 clean-shutdown
            # packets (E1.31 sends the terminated bit 3x) then drops off the air.
            if args.scenario == "terminate" and not terminated and elapsed >= args.terminate_after:
                u, prio, name, cid = plan[1]
                for _ in range(3):
                    sock.sendto(build_packet(cid, name, prio, u, 0, dmx,
                                             options=STREAM_TERMINATED),
                                (mcast_addr(u), SACN_PORT))
                print(f"  sender '{name}' terminated stream on universe {u}")
                plan = plan[:1]
                terminated = True

            for u, prio, name, cid in plan:
                seq[cid] = (seq.get(cid, 0) + 1) & 0xff
                pkt = build_packet(cid, name, prio, u, seq[cid], dmx, vector=vector)
                sock.sendto(pkt, (mcast_addr(u), SACN_PORT))
            time.sleep(1.0 / args.rate)
    except KeyboardInterrupt:
        print("\nstopped")


def self_test():
    """Build a packet and parse it back at the detector's offsets."""
    cid = cid_for(3)
    pkt = build_packet(cid, "test", priority=123, universe=4660, sequence=7,
                       dmx=bytes(512))
    assert len(pkt) == 638, len(pkt)
    assert pkt[22:38] == cid
    assert pkt[108] == 123
    assert struct.unpack("!H", pkt[113:115])[0] == 4660
    assert pkt[40:44] == b"\x00\x00\x00\x02"   # framing vector
    assert pkt[18:22] == b"\x00\x00\x00\x04"   # root vector
    # two senders, same prio -> two distinct CIDs (the conflict condition)
    a, b = senders_for("conflict", 1)
    assert a[1] == b[1] and a[3] != b[3]
    # dupcid -> SAME CID, different source names
    a, b = senders_for("dupcid", 1)
    assert a[3] == b[3] and a[2] != b[2]
    # terminated bit lands in the Options byte @112
    t = build_packet(cid, "x", 100, 1, 1, bytes(512), options=STREAM_TERMINATED)
    assert t[112] == STREAM_TERMINATED
    # non-data vector is emittable for the ignore-path test
    v = build_packet(cid, "x", 100, 1, 1, bytes(512), vector=0x00000008)
    assert v[40:44] == b"\x00\x00\x00\x08"
    print("self-test ok (638-byte packet, offsets match detector)")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--scenario", default="normal",
                    choices=["normal", "conflict", "backup", "multi",
                             "dupcid", "terminate", "badvector"])
    ap.add_argument("--universe", type=int, default=1)
    ap.add_argument("--rate", type=float, default=10.0, help="packets/sec per sender")
    ap.add_argument("--terminate-after", type=float, default=8.0,
                    help="seconds before sender B terminates (terminate scenario)")
    ap.add_argument("--ttl", type=int, default=16)
    ap.add_argument("--iface", help="egress interface NAME for multicast (e.g. eno1, eth0)")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    if args.self_test:
        self_test()
        return
    run(args)


if __name__ == "__main__":
    main()
