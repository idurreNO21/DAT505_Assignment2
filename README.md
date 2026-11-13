# Assignment 2: CUPS Printer Discovery Exploitation and Attack Detection

## 1. Project Overview

This project investigates CVE-2024-47176, a vulnerability affecting the `cups-browsed` component of the Common Unix Printing System (CUPS).

The objective is to reproduce the vulnerability in an isolated laboratory environment, develop tools to generate and detect malicious printer discovery announcements, and implement security mitigations.

The project includes the following scripts:

- **Scapy-based attack tool (`cups_attack.py`):** Uses Scapy to craft and send CUPS browsing announcements, including different payload variations and IP spoofing.
- **Socket-based announcement tool (`send_announcement.py`):** Uses Python's standard `socket` library to send CUPS printer discovery announcements without relying on Scapy.
- **Detection tool (`cups_detector.py`):** Analyses PCAP files to identify unauthorized announcements and suspicious payloads.
- **Firewall mitigation (`firewall.py`):** Implements network-level filtering using `iptables` to block unwanted CUPS browsing traffic.
- **Allowlist mitigation (`allowlist.py`):** Implements application-level filtering through the `cups-browsed` configuration, restricting which printer discovery announcements are accepted.
- **Virtual printer (`ipp_server.py`):** Simulates a network printer using IPP without requiring physical hardware.

## 2. Project Structure

- `scripts/`: Python scripts for attack generation, announcement sending, detection, virtual printer simulation and mitigation.
- `evidence/`: Configuration backups and experimental evidence.
- `pcap_files/`: Network traffic captures.
- `requirements.txt`: Python dependencies.

## 3. Requirements

The laboratory requires:

- Kali Linux or another Linux distribution.
- Python 3.13 or compatible version.
- Docker and Docker Compose.
- Vulhub environment with the vulnerable CUPS configuration.
- Scapy.
- Wireshark or tcpdump for network traffic inspection.
- `iptables` for network-level mitigation.

## 4. Installation

Install the dependencies required by the attack and detection tools:

```bash
pip install -r requirements.txt
```

The virtual IPP printer uses a separate Python virtual environment.

Create and activate it:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

## 5. Usage

**Start the virtual IPP printer:**

```bash
source .venv/bin/activate
python3 scripts/ipp_server.py
```

**Run the Scapy-based attack tool:**

```bash
python3 scripts/cups_attack.py --help
```

**Run the detection tool:**

```bash
python3 scripts/cups_detector.py --help
```

**Apply or manage the firewall mitigation:**

```bash
python3 scripts/firewall.py --help
```

**Apply, verify or remove the cups-browsed allowlist mitigation:**

```bash
python3 scripts/allowlist.py --help
```

Refer to each script's command-line arguments and configuration variables before execution. Some mitigation operations require administrator privileges.

## 6. Evidence and Results

Network captures are stored in `pcap_files/` and can be analysed using Wireshark or tcpdump.

The experiments demonstrate the vulnerability, evaluate the detection capabilities and compare the effectiveness of the implemented mitigations.

## 7. Disclaimer

This project was developed for academic and educational purposes only. All experiments should be conducted in an isolated and authorized laboratory environment.
