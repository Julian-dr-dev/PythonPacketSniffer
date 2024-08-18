import socket
import struct
import textwrap

import tkinter as tk
from tkinter import scrolledtext

TAB1 = '\t - '
TAB2 = '\t\t - '
TAB3 = '\t\t\t - '
TAB4 = '\t\t\t\t - '

DATA_TAB1 = '\t '
DATA_TAB2 = '\t\t '
DATA_TAB3 = '\t\t\t '
DATA_TAB4 = '\t\t\t\t '

class PacketSnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Sniffer")

        # Create a scrollable text box for output
        self.output_text = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=100, height=30)
        self.output_text.pack(padx=10, pady=10)

        # Start Capture button
        self.start_button = tk.Button(root, text="Start Capture", command=self.start_capture)
        self.start_button.pack(pady=5)

    def start_capture(self):
        self.output_text.insert(tk.END, "Starting packet capture...\n")
        self.root.update()  # Refresh the GUI

        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

        while True:
            raw_data, addr = conn.recvfrom(65536)
            dest_mac, src_mac, eth_proto, data = self.ethernet_frame(raw_data)
            output = "\nEthernet Frame: \n"
            output += TAB1 + 'Destination: {} Source: {} Protocol: {}\n'.format(dest_mac, src_mac, eth_proto)
            self.output_text.insert(tk.END, output)
            self.root.update()

            if eth_proto == 8:  # IPv4
                (version, header_length, ttl, proto, src, target, data) = self.ipv4_packet(data)
                output = TAB1 + 'IPv4 Packet:\n'
                output += TAB2 + 'Version: {}, Header Length: {}, TTL: {}\n'.format(version, header_length, ttl)
                output += TAB2 + 'Protocol: {}, Source: {}, Target: {}\n'.format(proto, src, target)
                self.output_text.insert(tk.END, output)
                self.root.update()

                if proto == 1:  # ICMP
                    icmp_type, code, checksum, data = self.icmp_packet(data)
                    output = TAB1 + 'ICMP Packet:\n'
                    output += TAB2 + 'Type: {}, Code: {}, Checksum: {}\n'.format(icmp_type, code, checksum)
                    self.output_text.insert(tk.END, output)
                    self.root.update()

    def ethernet_frame(self, data):
        dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
        return self.get_mac_addr(dest_mac), self.get_mac_addr(src_mac), socket.htons(proto), data[14:]

    def get_mac_addr(self, bytes_addr):
        bytes_str = map('{:02x}'.format, bytes_addr)
        return ':'.join(bytes_str).upper()

    def ipv4_packet(self, data):
        version_header_length = data[0]
        version = version_header_length >> 4
        header_length = (version_header_length & 15) * 4
        ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
        return version, header_length, ttl, proto, self.ipv4(src), self.ipv4(target), data[header_length:]

    def ipv4(self, addr):
        return '.'.join(map(str, addr))

    def icmp_packet(self, data):
        icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
        return icmp_type, code, checksum, data[4:]

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.mainloop()






     














