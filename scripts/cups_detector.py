#!/usr/bin/env python3

import argparse
import csv
import json
import logging
import re
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from scapy.all import IP, TCP, UDP, Raw, rdpcap, sniff, conf

LOG_FORMAT = "%(asctime)s [%(levelname)s] %(message)s"
logging.basicConfig(format=LOG_FORMAT, datefmt="%H:%M:%S", level=logging.INFO)
log = logging.getLogger("cups_detector")


CUPS_PAYLOAD_RE = re.compile(
    r'^([0-9a-f]+)\s+([0-9a-f]+)\s+(\S+)\s+"([^"]*)"\s+"([^"]*)"',
    re.IGNORECASE,
)

VALID_PRINTER_STATES = {0x03, 0x04, 0x05}   # idle, processing, stopped

# Alert type constants
ALERT_UNAUTHORIZED_AD  = "UNAUTHORIZED_ADVERTISEMENT"
ALERT_SUSPICIOUS_IPP   = "SUSPICIOUS_IPP_CONNECTION"
ALERT_REPEATED         = "REPEATED_DISCOVERY"
ALERT_MALFORMED        = "MALFORMED_PAYLOAD"


def make_alert(alert_type: str, src_ip: str, dst_ip: str,
               details: str, pkt_summary: str = "") -> dict:
    return {
        "timestamp":   datetime.now().isoformat(),
        "alert_type":  alert_type,
        "src_ip":      src_ip,
        "dst_ip":      dst_ip,
        "details":     details,
        "pkt_summary": pkt_summary,
    }

def parse_cups_payload(raw: bytes) -> dict | None:
    try:
        text = raw.decode("utf-8", errors="ignore").strip()
    except Exception:
        return None

    m = CUPS_PAYLOAD_RE.match(text)
    if not m:
        return None

    return {
        "raw":              text,
        "printer_type":     int(m.group(1), 16),
        "printer_state":    int(m.group(2), 16),
        "printer_uri":      m.group(3),
        "printer_location": m.group(4),
        "printer_info":     m.group(5),
    }


class CUPSDetector:
    def __init__(
        self,
        ad_allowlist:    set,   # IPs authorised to send printer advertisements
        ipp_allowlist:   set,   # IPs authorised to initiate IPP connections
        cups_port:       int   = 631,
        printer_port:    int   = 8631,
        rate_threshold:  int   = 3,
        rate_window:     float = 10.0,
    ):

        self.ad_allowlist   = ad_allowlist
        self.ipp_allowlist  = ipp_allowlist
        self.cups_port      = cups_port
        self.printer_port   = printer_port
        self.rate_threshold = rate_threshold
        self.rate_window    = rate_window

        self.alerts: list                    = []
        self._rate: dict                     = defaultdict(list)


    def _check_unauthorized_advertisement(self, pkt, parsed: dict):

        src = pkt[IP].src
        if src not in self.ad_allowlist:
            alert = make_alert(
                alert_type  = ALERT_UNAUTHORIZED_AD,
                src_ip      = src,
                dst_ip      = pkt[IP].dst,
                details     = (
                    f"Printer advertisement from unlisted source. "
                    f"URI: {parsed['printer_uri']}"
                ),
                pkt_summary = pkt.summary(),
            )
            self.alerts.append(alert)
            log.warning("[!] %s — %s → %s | %s",
                        ALERT_UNAUTHORIZED_AD, src, pkt[IP].dst,
                        parsed["printer_uri"])

    def _check_suspicious_ipp_connection(self, pkt):

        src   = pkt[IP].src
        dst   = pkt[IP].dst
        dport = pkt[TCP].dport
        flags = pkt[TCP].flags

        is_syn = bool(flags & 0x02)
        if not is_syn:
            return

        if src not in self.ipp_allowlist:
            alert = make_alert(
                alert_type  = ALERT_SUSPICIOUS_IPP,
                src_ip      = src,
                dst_ip      = dst,
                details     = (
                    f"TCP SYN to port {dport} from unlisted source."
                ),
                pkt_summary = pkt.summary(),
            )
            self.alerts.append(alert)
            log.warning("[!] %s — %s → %s:%d",
                        ALERT_SUSPICIOUS_IPP, src, dst, dport)

    def _check_repeated_discovery(self, pkt, parsed: dict):

        src = pkt[IP].src
        pkt_ts = float(pkt.time)

        timestamps = self._rate[src]
        timestamps = [t for t in timestamps if pkt_ts - t < self.rate_window]
        timestamps.append(pkt_ts)
        self._rate[src] = timestamps

        if len(timestamps) >= self.rate_threshold:
            # Alert once per burst (when threshold is exactly reached)
            if len(timestamps) == self.rate_threshold:
                alert = make_alert(
                    alert_type  = ALERT_REPEATED,
                    src_ip      = src,
                    dst_ip      = pkt[IP].dst,
                    details     = (
                        f"{len(timestamps)} discovery packets from same source "
                        f"in {self.rate_window}s "
                        f"(threshold: {self.rate_threshold})."
                    ),
                    pkt_summary = pkt.summary(),
                )
                self.alerts.append(alert)
                log.warning("[!] %s — %s sent %d packets in %.0fs",
                            ALERT_REPEATED, src,
                            len(timestamps), self.rate_window)

    def _check_malformed_payload(self, pkt, raw: bytes):

        src  = pkt[IP].src
        dst  = pkt[IP].dst
        text = raw.decode("utf-8", errors="ignore").strip()

        parsed = parse_cups_payload(raw)

        # 4a — payload does not match the protocol format at all
        if parsed is None:
            alert = make_alert(
                alert_type  = ALERT_MALFORMED,
                src_ip      = src,
                dst_ip      = dst,
                details     = (
                    f"UDP/631 payload does not match CUPS browsing format. "
                    f"Raw: {text[:80]}"
                ),
                pkt_summary = pkt.summary(),
            )
            self.alerts.append(alert)
            log.warning("[!] %s (bad format) — %s | raw: %s",
                        ALERT_MALFORMED, src, text[:60])
            return

        # 4b — printer_state is outside the valid range
        if parsed["printer_state"] not in VALID_PRINTER_STATES:
            alert = make_alert(
                alert_type  = ALERT_MALFORMED,
                src_ip      = src,
                dst_ip      = dst,
                details     = (
                    f"Unexpected printer-state value: "
                    f"0x{parsed['printer_state']:02x} "
                    f"(valid: 0x03 idle, 0x04 processing, 0x05 stopped)."
                ),
                pkt_summary = pkt.summary(),
            )
            self.alerts.append(alert)
            log.warning("[!] %s (bad state 0x%02x) — %s",
                        ALERT_MALFORMED, parsed["printer_state"], src)

        # 4c — URI scheme is not ipp:// or ipps://
        uri = parsed["printer_uri"]
        if not (uri.startswith("ipp://") or uri.startswith("ipps://")):
            alert = make_alert(
                alert_type  = ALERT_MALFORMED,
                src_ip      = src,
                dst_ip      = dst,
                details     = (
                    f"Unexpected URI scheme in advertisement: {uri}"
                ),
                pkt_summary = pkt.summary(),
            )
            self.alerts.append(alert)
            log.warning("[!] %s (bad URI scheme) — %s | %s",
                        ALERT_MALFORMED, src, uri)


    def analyze(self, pkt):
        if not pkt.haslayer(IP):
            return

        # --- UDP/631: CUPS browsing announcement ---
        if pkt.haslayer(UDP) and pkt[UDP].dport == self.cups_port:
            src = pkt[IP].src

            if pkt.haslayer(Raw):
                raw    = pkt[Raw].load
                parsed = parse_cups_payload(raw)

                if parsed:
                    self._check_unauthorized_advertisement(pkt, parsed)
                    self._check_repeated_discovery(pkt, parsed)
                self._check_malformed_payload(pkt, raw)
            else:
                alert = make_alert(
                    alert_type  = ALERT_MALFORMED,
                    src_ip      = src,
                    dst_ip      = pkt[IP].dst,
                    details     = "UDP/631 packet with empty payload.",
                    pkt_summary = pkt.summary(),
                )
                self.alerts.append(alert)
                log.warning("[!] %s (empty payload) — %s", ALERT_MALFORMED, src)

        # --- TCP: IPP connection ---
        if pkt.haslayer(TCP):
            dport = pkt[TCP].dport
            if dport in (self.cups_port, self.printer_port):
                self._check_suspicious_ipp_connection(pkt)


    def run_live(self, iface, timeout):
        bpf = (
            f"(udp and port {self.cups_port}) or "
            f"(tcp and (port {self.cups_port} or port {self.printer_port}))"
        )
        log.info("Live monitoring — iface=%s  BPF: %s",
                 iface or "auto", bpf)
        log.info("Press Ctrl+C to stop.")

        kwargs = {
            "filter":  bpf,
            "prn":     self.analyze,
            "store":   False,
        }
        if iface:
            kwargs["iface"] = iface
        if timeout:
            kwargs["timeout"] = timeout

        try:
            sniff(**kwargs)
        except KeyboardInterrupt:
            log.info("Stopped by user.")

    
    def run_offline(self, pcap_path: str):
        log.info("Offline analysis — file: %s", pcap_path)
        packets = rdpcap(pcap_path)
        log.info("Loaded %d packets.", len(packets))
        for pkt in packets:
            self.analyze(pkt)
        log.info("Analysis complete — %d alert(s) generated.", len(self.alerts))


    def export_json(self, path: str):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(self.alerts, f, indent=2)
        log.info("Alerts exported → %s (%d alerts)", path, len(self.alerts))

    def export_csv(self, path: str):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        fields = ["timestamp", "alert_type", "src_ip",
                  "dst_ip", "details", "pkt_summary"]
        with open(path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fields)
            writer.writeheader()
            writer.writerows(self.alerts)
        log.info("Alerts exported → %s (%d alerts)", path, len(self.alerts))

    def print_summary(self):
        if not self.alerts:
            log.info("No alerts generated.")
            return
        log.info("=" * 60)
        log.info("SUMMARY — %d alert(s)", len(self.alerts))
        log.info("=" * 60)
        counts: dict = defaultdict(int)
        for a in self.alerts:
            counts[a["alert_type"]] += 1
        for alert_type, count in sorted(counts.items()):
            log.info("  %-35s %d", alert_type, count)
        log.info("=" * 60)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def parse_args():
    parser = argparse.ArgumentParser(
        prog="cups_detector.py",
        description=(
            "CUPS attack detection tool.\n"
            "Identifies suspicious CUPS network activity using Scapy.\n"
            "Supports live interface monitoring and offline PCAP analysis.\n\n"
            "ETHICAL USE ONLY — isolated lab environments only."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    mode = parser.add_argument_group("Mode (required — pick one)")
    group = mode.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--live", metavar="IFACE",
        help="Live monitoring on this interface (e.g. br-xxxx). "
             "Use 'any' to listen on all interfaces."
    )
    group.add_argument(
        "--offline", metavar="PCAP",
        help="Offline analysis of a PCAP file."
    )

    net = parser.add_argument_group("Network")
    net.add_argument(
        "--ad-allowlist", default="",
        help=(
            "Comma-separated IPs authorised to send printer advertisements "
            "(UDP/631 source).\n"
            "Example: --ad-allowlist 172.18.0.3\n"
            "Leave empty to flag every advertisement."
        )
    )
    net.add_argument(
        "--ipp-allowlist", default="",
        help=(
            "Comma-separated IPs authorised to initiate IPP connections "
            "(TCP source).\n"
            "Should include the CUPS container IP (e.g. 172.18.0.2) so that "
            "legitimate callbacks from cups-browsed are not flagged.\n"
            "Example: --ipp-allowlist 172.18.0.2,172.18.0.1"
        )
    )
    net.add_argument("--cups-port",    type=int, default=631,
                     help="UDP port cups-browsed listens on (default: 631)")
    net.add_argument("--printer-port", type=int, default=8631,
                     help="TCP port of the legitimate IPP server (default: 8631)")

    det = parser.add_argument_group("Detection thresholds")
    det.add_argument(
        "--rate-threshold", type=int, default=3,
        help="UDP/631 packets from the same source within --rate-window "
             "seconds that triggers REPEATED_DISCOVERY (default: 3)"
    )
    det.add_argument(
        "--rate-window", type=float, default=10.0,
        help="Time window in seconds for rate detection (default: 10). "
             "Uses original packet timestamps (pkt.time) for offline analysis."
    )

    out = parser.add_argument_group("Output")
    out.add_argument(
        "--output-json", default="evidence/alerts.json",
        help="JSON output file (default: evidence/alerts.json)"
    )
    out.add_argument(
        "--output-csv",  default="evidence/alerts.csv",
        help="CSV output file (default: evidence/alerts.csv)"
    )

    beh = parser.add_argument_group("Behaviour")
    beh.add_argument(
        "--timeout", type=int, default=None,
        help="Stop live capture after this many seconds (default: run until Ctrl+C)"
    )
    beh.add_argument("--debug", action="store_true",
                     help="Set log level to DEBUG")

    return parser.parse_args()


def main():
    args = parse_args()

    if args.debug:
        log.setLevel(logging.DEBUG)

    conf.verb = 0

    ad_allowlist  = set(ip.strip() for ip in args.ad_allowlist.split(",")
                        if ip.strip())
    ipp_allowlist = set(ip.strip() for ip in args.ipp_allowlist.split(",")
                        if ip.strip())

    log.info("=" * 60)
    log.info("CUPS Attack Detection Tool")
    log.info("Ad allowlist:     %s",
             ad_allowlist  or "empty (flag all advertisement sources)")
    log.info("IPP allowlist:    %s",
             ipp_allowlist or "empty (flag all IPP connection sources)")
    log.info("Rate threshold:   %d packets / %.0fs",
             args.rate_threshold, args.rate_window)
    log.info("=" * 60)

    detector = CUPSDetector(
        ad_allowlist   = ad_allowlist,
        ipp_allowlist  = ipp_allowlist,
        cups_port      = args.cups_port,
        printer_port   = args.printer_port,
        rate_threshold = args.rate_threshold,
        rate_window    = args.rate_window,
    )

    try:
        if args.live:
            iface = None if args.live == "any" else args.live
            detector.run_live(iface=iface, timeout=args.timeout)
        else:
            detector.run_offline(args.offline)
    except PermissionError:
        log.error("Permission denied — run with sudo (Scapy needs raw sockets).")
        sys.exit(1)

    detector.print_summary()
    detector.export_json(args.output_json)
    detector.export_csv(args.output_csv)


if __name__ == "__main__":
    main()
