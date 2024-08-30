from scapy.all import sniff, Ether, IP, ICMP, TCP, UDP
import pyfiglet
import textwrap

# Constants for formatting output
TAB_1 = '\t'
TAB_2 = '\t\t'
TAB_3 = '\t\t\t'
TAB_4 = '\t\t\t\t'

DATA_TAB_1 = '\t'
DATA_TAB_2 = '\t\t'
DATA_TAB_3 = '\t\t\t'
DATA_TAB_4 = '\t\t\t\t'

# Create a banner
banner = pyfiglet.figlet_format("DANTICO")
print(banner)

def packet_callback(packet):
    if packet.haslayer(Ether):
        ether_layer = packet[Ether]
        dest_mac = ether_layer.dst
        src_mac = ether_layer.src
        eth_proto = ether_layer.type
        print("\nEthernet frame:")
        print(TAB_1 + f'Destination: {dest_mac}, Source: {src_mac}, Protocol: {eth_proto}')

        if eth_proto == 0x0800 and packet.haslayer(IP):  # IPv4
            ip_layer = packet[IP]
            version = ip_layer.version
            header_length = ip_layer.ihl * 4
            ttl = ip_layer.ttl
            proto = ip_layer.proto
            src_ip = ip_layer.src
            target_ip = ip_layer.dst
            print(TAB_1 + 'IPv4 Packet:')
            print(TAB_2 + f'Version: {version}, Header Length: {header_length}, TTL: {ttl}')
            print(TAB_2 + f'Protocol: {proto}, Source: {src_ip}, Target: {target_ip}')

            if proto == 1 and packet.haslayer(ICMP):  # ICMP
                icmp_layer = packet[ICMP]
                icmp_type = icmp_layer.type
                code = icmp_layer.code
                checksum = icmp_layer.chksum
                print(TAB_1 + 'ICMP Packet:')
                print(TAB_2 + f'Type: {icmp_type}, Code: {code}, Checksum: {checksum}')
                print(TAB_2 + 'Data:')
                print(format_multiline_data(DATA_TAB_3, bytes(packet[ICMP].payload)))

            elif proto == 6 and packet.haslayer(TCP):  # TCP
                tcp_layer = packet[TCP]
                src_port = tcp_layer.sport
                dest_port = tcp_layer.dport
                sequence = tcp_layer.seq
                acknowledgement = tcp_layer.ack
                flags = tcp_layer.flags
                print(TAB_1 + "TCP Segment:")
                print(TAB_2 + f'Source Port: {src_port}, Destination Port: {dest_port}')
                print(TAB_2 + f'Sequence: {sequence}, Acknowledgement: {acknowledgement}')
                print(TAB_2 + "Flags:")
                print(TAB_3 + f'URG: {flags & 0x20}, ACK: {flags & 0x10}, PSH: {flags & 0x08}, RST: {flags & 0x04}, SYN: {flags & 0x02}, FIN: {flags & 0x01}')
                print(TAB_2 + "Data:")
                print(format_multiline_data(DATA_TAB_3, bytes(packet[TCP].payload)))

            elif proto == 17 and packet.haslayer(UDP):  # UDP
                udp_layer = packet[UDP]
                src_port = udp_layer.sport
                dest_port = udp_layer.dport
                length = udp_layer.len
                print(TAB_1 + "UDP Segment:")
                print(TAB_2 + f'Source Port: {src_port}, Destination Port: {dest_port}, Length: {length}')
                print(TAB_2 + "Data:")
                print(format_multiline_data(DATA_TAB_3, bytes(packet[UDP].payload)))

            else:
                print(TAB_1 + 'Data:')
                print(format_multiline_data(DATA_TAB_2, bytes(packet[IP].payload)))

        else:
            print('Data:')
            print(format_multiline_data(DATA_TAB_1, bytes(packet.payload)))

# Format multi-line data
def format_multiline_data(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

def main():
    print("Starting packet sniffing...")
    sniff(prn=packet_callback, store=False)

if __name__ == "__main__":
    main()
