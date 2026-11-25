import struct
import packet_struct
import sys
import math

def parse_global_header(file):
        
        try:
            f = open(file, "rb")
        except FileNotFoundError:
            print(f"Error: Could not find {file}")
            sys.exit(1)

        global_hdr = f.read(24)
        if len(global_hdr) < 24:
            print("Error: File is too small.")
            sys.exit(1)

        magic = struct.unpack('<I', global_hdr[:4])[0]
        is_nano = False

        if magic == 0xd4c3b2a1:
            endian = '>'
        elif magic == 0xa1b2c3d4:
            endian = '<'
        elif magic == 0x4d3cb2a1:
            endian = '>'
            is_nano = True
        elif magic == 0xa1b23c4d:
            endian = '<'
            is_nano = True
        else:
            print(f"Error: Unknown magic number {hex(magic)}")
            sys.exit(1)

        return endian, f, is_nano

def process_packets(file, endian_format, is_nano):

    orig_time = None
    packet_count = 0
    parsed_packets = []
    header_format = endian_format + 'IIII'

    ts_multiplier = 0.000000001 if is_nano else 0.000001

    while True:

        packet_header = file.read(16)

        if len(packet_header) < 16:
            break

        packet_count += 1

        # Unpack header
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(header_format, packet_header)

        abs_time = ts_sec + (ts_usec * ts_multiplier)

        if orig_time is None:
                orig_time = abs_time

        packet_data = file.read(incl_len)

        parsed = parse_traceroute_packet(packet_data, packet_count, packet_header[0:4], packet_header[4:8], orig_time)

        if parsed is not None:
            parsed.timestamp = abs_time
            parsed_packets.append(parsed)

    return parsed_packets

def parse_traceroute_packet(packet_data, packet_count, ts_sec_byte, ts_usec_bytes, orig_time):
    
    if len(packet_data) < 34:
        return None

    eth_type = struct.unpack('>H', packet_data[12:14])[0]
    if eth_type != 0x0800:
        return None

    current_packet = packet_struct.packet()
    current_packet.packet_No_set(packet_count)
    current_packet.timestamp_set(ts_sec_byte, ts_usec_bytes, orig_time)

    ip_start = 14
    current_packet.IP_header.get_header_len(packet_data[ip_start : ip_start + 1])
    ip_len = current_packet.IP_header.ip_header_len

    current_packet.IP_header.get_IP(
    packet_data[ip_start + 12 : ip_start + 16],
    packet_data[ip_start + 16 : ip_start + 20]
    )
    current_packet.IP_header.get_protocol(packet_data[ip_start + 9 : ip_start + 10])
    current_packet.IP_header.get_fragmentation_info(
        packet_data[ip_start + 4 : ip_start + 6],
        packet_data[ip_start + 6 : ip_start + 8]
    )

    protocol = current_packet.IP_header.protocol

    if protocol not in [1, 17]:
        return None

    payload_start = ip_start + ip_len

    if protocol == 17 and len(packet_data) >= payload_start + 4:
        current_packet.UDP_header = packet_struct.UDP_Header()
        current_packet.UDP_header.get_ports(packet_data[payload_start: payload_start + 4])

        if 33434 <= current_packet.UDP_header.dst_port <= 33529:
            current_packet.is_probe = True

    elif protocol == 1 and len(packet_data) >= payload_start + 8:
        current_packet.ICMP_header = packet_struct.ICMP_Header()
        current_packet.ICMP_header.get_type_and_code(packet_data[payload_start: payload_start + 2])

        icmp_type = current_packet.ICMP_header.type

        if icmp_type == 8:
            current_packet.ICMP_header.get_sequence_num(packet_data[payload_start + 6: payload_start + 8])
            current_packet.is_probe = True

        elif icmp_type in [11, 0]:
            current_packet.is_error = True
            orig_ip_start = payload_start + 8

            if len(packet_data) >= orig_ip_start + 20:
                orig_ihl = (packet_data[orig_ip_start] & 0x0F) * 4
                orig_protocol = packet_data[orig_ip_start + 9]
                orig_payload_start = orig_ip_start + orig_ihl

                if orig_protocol == 17 and len(packet_data) >= orig_payload_start + 2:
                    current_packet.embedded_match_key = \
                    struct.unpack('>H', packet_data[orig_payload_start: orig_payload_start + 2])[0]
                elif orig_protocol == 1 and len(packet_data) >= orig_payload_start + 8:
                    current_packet.embedded_match_key = \
                    struct.unpack('>H', packet_data[orig_payload_start + 6: orig_payload_start + 8])[0]

            if icmp_type == 0 and not current_packet.embedded_match_key:
                current_packet.embedded_match_key = \
                struct.unpack('>H', packet_data[payload_start + 6: payload_start + 8])[0]

    return current_packet

def analyze_traceroute(parsed_packets):

    source_node = None
    ultimate_dst = None
    intermediate_nodes = []
    protocols = set()

    frag_count = 0 
    last_frag_offset = 0

    probes_sent = {}
    rtt_measurements = {}
    ult_rtts = []

    for p in parsed_packets:
        protocols.add(p.IP_header.protocol)
        if source_node is None:
            source_node = p.IP_header.src_ip

        if p.is_probe and p.IP_header.src_ip == source_node:
            ultimate_dst = p.IP_header.dst_ip

            offset = p.IP_header.frag_offset
            if p.IP_header.flags == 1 or offset > 0:
                if offset > last_frag_offset: last_frag_offset = offset
                if offset == 0: frag_count = 0 
                frag_count += 1
            elif frag_count == 0:
                frag_count = 1

            match_key = p.UDP_header.src_port if p.IP_header.protocol == 17 else p.ICMP_header.seq_num
            if match_key not in probes_sent: probes_sent[match_key] = []
            probes_sent[match_key].append(p.timestamp)

        elif p.is_error and p.IP_header.dst_ip == source_node:
            router_ip = p.IP_header.src_ip
            if router_ip != ultimate_dst and router_ip not in intermediate_nodes:
                intermediate_nodes.append(router_ip)
                rtt_measurements[router_ip] = []

            if p.embedded_match_key and p.embedded_match_key in probes_sent:
                for sent_time in probes_sent[p.embedded_match_key]:
                    rtt = round((p.timestamp - sent_time) * 1000, 6)
                    if router_ip == ultimate_dst:
                        ult_rtts.append(rtt)
                    else:
                        rtt_measurements[router_ip].append(rtt)
                del probes_sent[p.embedded_match_key]

    if frag_count == 1 and last_frag_offset == 0:
        pass

    return source_node, ultimate_dst, intermediate_nodes, protocols, frag_count, last_frag_offset, rtt_measurements, ult_rtts

def calc_stats(rtt_list):
    if not rtt_list: return 0.0, 0.0
    mean = sum(rtt_list) / len(rtt_list)
    variance = sum((x - mean) ** 2 for x in rtt_list) / (len(rtt_list) - 1) if len(rtt_list) > 1 else 0.0
    return round(mean, 2), round(math.sqrt(variance), 2)

def generate_output(src, dst, routers, protos, fc, f_off, rtts, ult_rtts):
    print(f"The IP address of the source node: {src}")
    print(f"The IP address of the destination node: {dst}")
    print("The IP addresses of the intermediate destination nodes:")
    for i, router in enumerate(routers, 1):
        print(f"router {i}: {router}")

    print('\n')

    print("The values in the protocol field of IP headers:")
    for p in sorted(list(protos)):
        if p == 1: print("1: ICMP")
        if p == 17: print("17: UDP")

    print('\n')
    print(f"The number of fragments created from the original datagram is: {fc}")
    print(f"The offset of the last fragment is: {f_off} bytes")
    
    print('\n')
    for router in routers:
        mean_rtt, sd_rtt = calc_stats(rtts[router])
        mean_str = f"{mean_rtt:g}"
        sd_str = f"{sd_rtt:g}"
        print(f"The avr RTT between {src} and {router} is: {mean_str} ms, the s.d. is: {sd_str} ms")

    if ult_rtts:
        mean_ult, sd_ult = calc_stats(ult_rtts)
        mean_str = f"{mean_ult:g}"
        sd_str = f"{sd_ult:g}"
        print(f"The svg Rtt between {src} and {dst} if: {mean_str} ms, the s.d. is: {sd_str} ms")

def main():
    filename = input("Input the name of the .pcap file to be analyzed: ")
    endian_format, file_obj, is_nano = parse_global_header(filename)
    
    if file_obj:
        parsed_packets = process_packets(file_obj, endian_format, is_nano)
        file_obj.close()

        src,dst, routers, protos, fc, f_off, rtts, ult_rtts = analyze_traceroute(parsed_packets)
        generate_output(src, dst, routers, protos, fc, f_off, rtts, ult_rtts)

if __name__ == '__main__':
    main()
