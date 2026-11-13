
#!/usr/bin/env python3

import argparse
import subprocess
import sys

# Lab network configuration
CUPS_IP = "172.18.0.2"
ALLOWED_IP = "172.18.0.3"
IFACE = "br-e6da70cc1ff0"

CHAIN = "OUTPUT"


def run_command(command, check=True):
    return subprocess.run(
        command,
        check=check,
        text=True,
        capture_output=True
    )


def firewall_rule():
    return [
        "sudo", "iptables",
        "-o", IFACE,
        "-d", CUPS_IP,
        "-p", "udp",
        "--dport", "631",
        "!", "-s", ALLOWED_IP,
        "-j", "DROP"
    ]


def check_environment():
    try:
        run_command(["ip", "link", "show", IFACE])
    except subprocess.CalledProcessError:
        print(f"[ERROR] Interface {IFACE} does not exist.")
        sys.exit(1)

    route = run_command(["ip", "route", "get", CUPS_IP])
    if f"dev {IFACE}" not in route.stdout:
        print("[ERROR] The route to the CUPS container does not use")
        print(f"        the expected interface {IFACE}.")
        print(route.stdout.strip())
        sys.exit(1)


def apply():
    check_environment()

    rule = ["sudo", "iptables", "-C", CHAIN] + firewall_rule()[2:]

    result = run_command(rule, check=False)

    if result.returncode == 0:
        print("[INFO] Firewall mitigation is already active.")
        return

    insert_rule = (
        ["sudo", "iptables", "-I", CHAIN, "1"]
        + firewall_rule()[2:]
    )

    run_command(insert_rule)
    print("[OK] Firewall mitigation applied.")
    print(f"[INFO] Only source {ALLOWED_IP} is allowed to send")
    print(f"       UDP announcements to {CUPS_IP}:631.")


def remove():
    rule = ["sudo", "iptables", "-D", CHAIN] + firewall_rule()[2:]
    result = run_command(rule, check=False)

    if result.returncode == 0:
        print("[OK] Firewall mitigation removed.")
    else:
        print("[INFO] The firewall rule was not present.")


def main():
    parser = argparse.ArgumentParser(
        description="Firewall mitigation for CUPS UDP browsing."
    )

    parser.add_argument(
        "action",
        choices=["apply", "remove"],
        help="Action to perform."
    )

    args = parser.parse_args()

    try:
        if args.action == "apply":
            apply()
        elif args.action == "remove":
            remove()

    except subprocess.CalledProcessError as error:
        print("[ERROR] Command execution failed.")
        if error.stderr:
            print(error.stderr.strip())
        sys.exit(1)


if __name__ == "__main__":
    main()
