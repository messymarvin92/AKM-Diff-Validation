#!/usr/bin/env python3
"""
ssid_akm_checker.py

Reads a single pcap/pcapng file or a directory of captures using Scapy,
extracts beacon frames, and reports SSIDs that are broadcast with DIFFERENT
AKM (Authentication and Key Management) suite sets. SSIDs whose beacons all
carry the same AKM set are not reported.

Equivalent Wireshark display filter logic:
    wlan.fc.type_subtype == 0x0008 && wlan.ssid
    fields: wlan.ssid, wlan.bssid, wlan.rsn.akms.type, wlan.wfa.ie.wpa.akms.type

Requirements:
    pip install scapy        (no tshark/Wireshark needed)

Examples:
    python3 ssid_akm_checker.py capture.pcap
    python3 ssid_akm_checker.py /path/to/pcaps/
    python3 ssid_akm_checker.py /path/to/pcaps/ -r --include-probe-resp
    python3 ssid_akm_checker.py capture.pcapng --exclude-open --csv out.csv
"""

import argparse
import csv
import os
import sys
from collections import defaultdict

try:
    from scapy.all import PcapReader, Dot11, Dot11Beacon, Dot11ProbeResp
except ImportError:
    sys.exit("ERROR: scapy is required. Install it with: pip install scapy")

PCAP_EXTENSIONS = (".pcap", ".pcapng", ".cap")

# 802.11 information element IDs
EID_SSID = 0
EID_RSN = 48
EID_VENDOR = 221

IEEE_OUI = b"\x00\x0f\xac"      # RSN (WPA2/WPA3) suite selector OUI
WPA1_VENDOR_PREFIX = b"\x00\x50\xf2\x01"  # Microsoft OUI + type 1 = WPA IE

AKM_NAMES = {
    1: "802.1X",
    2: "PSK",
    3: "FT-802.1X",
    4: "FT-PSK",
    5: "802.1X-SHA256",
    6: "PSK-SHA256",
    7: "TDLS",
    8: "SAE",
    9: "FT-SAE",
    10: "APPeerKey",
    11: "802.1X-SuiteB",
    12: "802.1X-SuiteB-192",
    13: "FT-802.1X-SHA384",
    14: "FILS-SHA256",
    15: "FILS-SHA384",
    16: "FT-FILS-SHA256",
    17: "FT-FILS-SHA384",
    18: "OWE",
    19: "FT-PSK-SHA384",
    20: "PSK-SHA384",
    24: "SAE-EXT-KEY",
    25: "FT-SAE-EXT-KEY",
}
WPA1_AKM_NAMES = {1: "802.1X", 2: "PSK"}


# --------------------------------------------------------------------------
# File discovery
# --------------------------------------------------------------------------
def collect_files(target, recursive):
    if os.path.isfile(target):
        return [target]
    if not os.path.isdir(target):
        sys.exit(f"ERROR: '{target}' is not a file or directory.")
    files = []
    if recursive:
        for root, _, names in os.walk(target):
            for n in names:
                if n.lower().endswith(PCAP_EXTENSIONS):
                    files.append(os.path.join(root, n))
    else:
        for n in os.listdir(target):
            p = os.path.join(target, n)
            if os.path.isfile(p) and n.lower().endswith(PCAP_EXTENSIONS):
                files.append(p)
    return sorted(files)


# --------------------------------------------------------------------------
# 802.11 information element parsing
# --------------------------------------------------------------------------
def iter_elements(raw):
    """Yield (element_id, body_bytes) from a tagged-parameter byte string."""
    i = 0
    n = len(raw)
    while i + 2 <= n:
        eid = raw[i]
        length = raw[i + 1]
        body = raw[i + 2:i + 2 + length]
        if len(body) < length:   # truncated / trailing FCS bytes
            break
        yield eid, body
        i += 2 + length


def parse_akm_list(data):
    """
    Parse the RSN / WPA information element body structure:
        version(2) group_cipher(4) pairwise_count(2) pairwise[4*n]
        akm_count(2) akm[4*n] ...
    Returns a list of (oui_bytes, akm_type_int) or None if malformed.
    """
    try:
        if len(data) < 8:
            return None
        pcount = int.from_bytes(data[6:8], "little")
        off = 8 + 4 * pcount
        if len(data) < off + 2:
            return None
        acount = int.from_bytes(data[off:off + 2], "little")
        off += 2
        if len(data) < off + 4 * acount:
            return None
        return [(data[o:o + 3], data[o + 3])
                for o in range(off, off + 4 * acount, 4)]
    except Exception:
        return None


def extract_ssid_and_akms(raw):
    """
    Walk the tagged parameters of a beacon/probe response.
    Returns (ssid_str_or_None, frozenset_of_akm_labels).
    """
    ssid = None
    akms = set()

    for eid, body in iter_elements(raw):
        if eid == EID_SSID and ssid is None:
            if body and any(b != 0 for b in body):   # skip hidden / null SSIDs
                ssid = body.decode("utf-8", errors="replace")
            else:
                ssid = ""
        elif eid == EID_RSN:
            parsed = parse_akm_list(body)
            if parsed is None:
                akms.add("RSN-Malformed")
                continue
            for oui, atype in parsed:
                name = AKM_NAMES.get(atype, f"Type{atype}")
                if oui != IEEE_OUI:
                    name += f"[OUI {oui.hex('-')}]"
                akms.add(name)
        elif eid == EID_VENDOR and body.startswith(WPA1_VENDOR_PREFIX):
            parsed = parse_akm_list(body[4:])
            if parsed is None:
                akms.add("WPA1-Malformed")
                continue
            for _, atype in parsed:
                akms.add(f"WPA1-{WPA1_AKM_NAMES.get(atype, f'Type{atype}')}")

    if not akms:
        akms.add("OPEN/No-AKM")
    return ssid, frozenset(akms)


# --------------------------------------------------------------------------
# Analysis
# --------------------------------------------------------------------------
def analyze(files, include_probe_resp, exclude_open):
    # ssid -> akm_set -> {"bssids": set, "files": set, "count": int}
    data = defaultdict(lambda: defaultdict(
        lambda: {"bssids": set(), "files": set(), "count": 0}))
    open_set = frozenset({"OPEN/No-AKM"})

    for path in files:
        print(f"[*] Processing {path}", file=sys.stderr)
        base = os.path.basename(path)
        try:
            reader = PcapReader(path)
        except Exception as e:
            print(f"[!] Cannot open {path}: {e}", file=sys.stderr)
            continue

        try:
            for pkt in reader:
                # Frame filter: beacons (and optionally probe responses)
                if pkt.haslayer(Dot11Beacon):
                    layer = pkt[Dot11Beacon]
                elif include_probe_resp and pkt.haslayer(Dot11ProbeResp):
                    layer = pkt[Dot11ProbeResp]
                else:
                    continue

                try:
                    ssid, akm_set = extract_ssid_and_akms(bytes(layer.payload))
                except Exception:
                    continue

                if not ssid:           # hidden / wildcard SSID
                    continue
                if exclude_open and akm_set == open_set:
                    continue

                bssid = (pkt[Dot11].addr3 or "").lower()
                entry = data[ssid][akm_set]
                entry["bssids"].add(bssid)
                entry["files"].add(base)
                entry["count"] += 1
        except Exception as e:
            print(f"[!] Error while reading {path}: {e}", file=sys.stderr)
        finally:
            try:
                reader.close()
            except Exception:
                pass
    return data


def fmt(akm_set):
    return ", ".join(sorted(akm_set))


def report(data, csv_path):
    mismatches = {s: sets for s, sets in data.items() if len(sets) > 1}

    if not mismatches:
        print("\nNo SSIDs found broadcasting different AKM suite sets.")
        return 0

    print("\n" + "=" * 78)
    print(f"SSIDs broadcast with DIFFERENT AKM suites: {len(mismatches)}")
    print("=" * 78)

    rows = []
    for ssid in sorted(mismatches):
        sets = mismatches[ssid]
        print(f"\nSSID: {ssid!r}  ({len(sets)} different AKM sets)")
        for akm_set, info in sorted(sets.items(), key=lambda kv: fmt(kv[0])):
            bssids = sorted(info["bssids"])
            files = sorted(info["files"])
            print(f"  AKM: {fmt(akm_set)}")
            print(f"    BSSIDs ({len(bssids)}): {', '.join(bssids)}")
            print(f"    Beacons: {info['count']}   Files: {', '.join(files)}")
            rows.append([ssid, fmt(akm_set), ";".join(bssids),
                         info["count"], ";".join(files)])

    if csv_path:
        with open(csv_path, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["SSID", "AKM_Suites", "BSSIDs", "Beacon_Count", "Files"])
            w.writerows(rows)
        print(f"\n[+] CSV written to {csv_path}")
    return len(mismatches)


def main():
    ap = argparse.ArgumentParser(
        description="Find SSIDs whose beacons advertise different AKM suites (Scapy-based).")
    ap.add_argument("path", help="pcap/pcapng file or directory of captures")
    ap.add_argument("-r", "--recursive", action="store_true",
                    help="recurse into subdirectories")
    ap.add_argument("--include-probe-resp", action="store_true",
                    help="also analyze probe responses (default: beacons only)")
    ap.add_argument("--exclude-open", action="store_true",
                    help="ignore beacons with no AKM (open networks)")
    ap.add_argument("--csv", metavar="FILE", help="also write results to a CSV file")
    args = ap.parse_args()

    files = collect_files(args.path, args.recursive)
    if not files:
        sys.exit("ERROR: no pcap/pcapng/cap files found.")

    data = analyze(files, args.include_probe_resp, args.exclude_open)
    sys.exit(1 if report(data, args.csv) else 0)


if __name__ == "__main__":
    main()
