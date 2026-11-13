
#!/usr/bin/env python3

import argparse
import subprocess
import sys
import tempfile
from pathlib import Path

# Lab configuration
CONTAINER = "cve-2024-47177-cups-1"
CONF = "/etc/cups/cups-browsed.conf"

ALLOWED_IP = "172.18.0.3"
MARKER = "# DAT505-MITIGATION"

SCRIPT_DIR = Path(__file__).resolve().parent
EVIDENCE_DIR = SCRIPT_DIR / "evidence"
BACKUP = EVIDENCE_DIR / "cups-browsed.conf.original.bak"


def run_command(command, check=True, input_text=None):
    return subprocess.run(
        command,
        check=check,
        text=True,
        input=input_text,
        capture_output=True
    )


def docker_command(*args, check=True):
    return run_command(
        ["sudo", "docker", *args],
        check=check
    )


def read_container_config():
    result = docker_command(
        "exec", CONTAINER, "cat", CONF
    )
    return result.stdout


def write_container_config(content):
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        delete=False
    ) as temporary_file:
        temporary_file.write(content)
        temporary_path = Path(temporary_file.name)

    try:
        docker_command(
            "cp",
            str(temporary_path),
            f"{CONTAINER}:{CONF}"
        )
    finally:
        temporary_path.unlink(missing_ok=True)


def restart_container():
    print("[INFO] Restarting the CUPS container...")
    docker_command("restart", CONTAINER)
    print("[OK] Container restarted.")


def apply():
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)

    current_config = read_container_config()

    if MARKER in current_config:
        print("[INFO] DAT505 mitigation is already present.")
        return

    active_filters = []
    for line in current_config.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue

        if stripped.startswith(
            ("BrowseAllow", "BrowseDeny", "BrowseOrder")
        ):
            active_filters.append(stripped)

    if active_filters:
        print("[ERROR] Existing active Browse filtering directives found:")
        for directive in active_filters:
            print(f"  {directive}")
        print("[INFO] Review the configuration before applying this script.")
        sys.exit(1)

    if not BACKUP.exists():
        BACKUP.write_text(current_config, encoding="utf-8")
        print(f"[OK] Original configuration backed up to: {BACKUP}")
    else:
        print(f"[INFO] Existing backup preserved: {BACKUP}")

    updated_config = (
        current_config.rstrip()
        + "\n\n"
        + MARKER
        + "\n"
        + f"BrowseAllow {ALLOWED_IP}\n"
    )

    write_container_config(updated_config)
    print(f"[OK] Allowlist rule added: BrowseAllow {ALLOWED_IP}")

    restart_container()


def remove():
    if not BACKUP.exists():
        print("[ERROR] Original configuration backup not found.")
        print(f"Expected location: {BACKUP}")
        sys.exit(1)

    original_config = BACKUP.read_text(encoding="utf-8")

    write_container_config(original_config)
    print("[OK] Original configuration restored.")

    restart_container()


def main():
    parser = argparse.ArgumentParser(
        description="Allowlist mitigation for cups-browsed."
    )

    parser.add_argument(
        "action",
        choices=["apply","remove"],
        help="Action to perform."
    )

    args = parser.parse_args()

    try:
        if args.action == "apply":
            apply()
        elif args.action == "remove":
            remove()

    except subprocess.CalledProcessError as error:
        print("[ERROR] Docker command failed.")
        if error.stderr:
            print(error.stderr.strip())
        sys.exit(1)


if __name__ == "__main__":
    main()
