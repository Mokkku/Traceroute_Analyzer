import struct
import packet_struct
import sys
import math
 
ALL_PROTOCOLS = set()
 
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
    ALL_PROTOCOLS.add(protocol)
 
    if protocol not in [1, 17]:
        return None
 
    current_packet.ttl = packet_data[ip_start + 8]
 
    payload_start = ip_start + ip_len
 
    if protocol == 17 and current_packet.IP_header.frag_offset == 0 and len(packet_data) >= payload_start + 4:
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
 
        elif icmp_type in [11, 3, 0]:
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
 
    frags = {}
    probe_keys = set()
    frag_to_match = {}
 
    probes_sent = {}
    rtt_measurements = {}
    router_ttl = {}
    ult_rtts = []
 
    for p in parsed_packets:
        protocols.add(p.IP_header.protocol)
        if source_node is None and p.is_probe:
            source_node = p.IP_header.src_ip
 
        if p.IP_header.src_ip == source_node and p.IP_header.protocol == 17:
            fkey = (p.IP_header.src_ip, p.IP_header.dst_ip, p.IP_header.identification)
            if p.is_probe:
                probe_keys.add(fkey)
                frag_to_match[fkey] = p.UDP_header.src_port
            elif fkey in probe_keys and frag_to_match[fkey] in probes_sent:
                probes_sent[frag_to_match[fkey]].append((p.timestamp, p.ttl))
            if fkey in probe_keys:
                frags.setdefault(fkey, []).append(p.IP_header.frag_offset)
 
        if p.is_probe and p.IP_header.src_ip == source_node:
            ultimate_dst = p.IP_header.dst_ip
 
            match_key = p.UDP_header.src_port if p.IP_header.protocol == 17 else p.ICMP_header.seq_num
            if match_key not in probes_sent: probes_sent[match_key] = []
            probes_sent[match_key].append((p.timestamp, p.ttl))
 
        elif p.is_error and p.IP_header.dst_ip == source_node:
            router_ip = p.IP_header.src_ip
            if router_ip != ultimate_dst and router_ip not in intermediate_nodes:
                intermediate_nodes.append(router_ip)
                rtt_measurements[router_ip] = []
 
            if p.embedded_match_key and p.embedded_match_key in probes_sent:
                for sent_time, ttl in probes_sent[p.embedded_match_key]:
                    rtt = round((p.timestamp - sent_time) * 1000, 6)
                    if router_ip == ultimate_dst:
                        ult_rtts.append(rtt)
                    else:
                        rtt_measurements[router_ip].append(rtt)
                        router_ttl[router_ip] = min(ttl, router_ttl.get(router_ip, ttl))
                del probes_sent[p.embedded_match_key]
 
 
    intermediate_nodes.sort(key=lambda r: router_ttl.get(r, 999))
 
    frag_info = [(k[2], len(v), max(v)) for k, v in frags.items() if len(v) > 1]

    return source_node, ultimate_dst, intermediate_nodes, protocols, frag_info, rtt_measurements, ult_rtts
 
def calc_stats(rtt_list):
    if not rtt_list: return 0.0, 0.0
    mean = sum(rtt_list) / len(rtt_list)
    variance = sum((x - mean) ** 2 for x in rtt_list) / (len(rtt_list) - 1) if len(rtt_list) > 1 else 0.0
    return round(mean, 2), round(math.sqrt(variance), 2)
 
def generate_output(src, dst, routers, protos, f_info, rtts, ult_rtts):
    print(f"The IP address of the source node: {src}")
    print(f"The IP address of ultimate destination node: {dst}")
    print("The IP addresses of the intermediate destination nodes:")
    for i, router in enumerate(routers, 1):
        end = "." if i == len(routers) else ","
        print(f"router {i}: {router}{end}")
 
    print()
    print("The values in the protocol field of IP headers:")
    names = {1: "ICMP", 6: "TCP", 17: "UDP"}
    for p in sorted(protos):
        print(f"{p}: {names.get(p, 'Unknown')}")
 
    print('\n')
    if f_info:
        for n, (ident, count, last_off) in enumerate(f_info):
            if n:
                print()
            print(f"The number of fragments created from the original datagram {ident} is: {count}")
            print(f"The offset of the last fragment is: {last_off}")
    else:
        print("The number of fragments created from the original datagram is: 0")
        print("The offset of the last fragment is: 0")
 
    print()
    for router in routers:
        mean_rtt, sd_rtt = calc_stats(rtts[router])
        print(f"The avg RTT between {src} and {router} is: {mean_rtt:g} ms, the s.d. is: {sd_rtt:g} ms")
 
    if ult_rtts:
        mean_ult, sd_ult = calc_stats(ult_rtts)
        print(f"The avg RTT between {src} and {dst} is: {mean_ult:g} ms, the s.d. is: {sd_ult:g} ms")
 
def main():
    filename = input("Input the name of the .pcap file to be analyzed: ")
    endian_format, file_obj, is_nano = parse_global_header(filename)
    
    if file_obj:
        parsed_packets = process_packets(file_obj, endian_format, is_nano)
        file_obj.close()
 
        src, dst, routers, protos, f_info, rtts, ult_rtts = analyze_traceroute(parsed_packets)
        generate_output(src, dst, routers, protos, f_info, rtts, ult_rtts)
 
if __name__ == '__main__':
    main()