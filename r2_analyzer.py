import struct
import os

def parse_r2_pcap(filename):

    try:
        f = open(filename, 'rb')
    except FileNotFoundError:
        return None

    global_hdr = f.read(24)
    if len(global_hdr) < 24: return None
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
        return None

    header_format = endian + 'IIII'
    ts_multiplier = 0.000000001 if is_nano else 0.000001

    source_node = None
    ttl_counts = {}
    probes_sent = {}

    hop_routers = {}
    router_rtts = {}

    while True:
        packet_header = f.read(16)
        if len(packet_header) < 16: break

        ts_sec, ts_frac, incl_len, _ = struct.unpack(header_format, packet_header)
        absolute_time = ts_sec + (ts_frac * ts_multiplier)
        packet_data = f.read(incl_len)

        if len(packet_data) < 34: continue
        if struct.unpack('>H', packet_data[12:14])[0] != 0x0800: continue

        ip_start = 14
        ihl = (packet_data[ip_start] & 0x0F) * 4
        ttl = packet_data[ip_start + 8]
        protocol = packet_data[ip_start + 9]
        src_ip = ".".join(map(str, packet_data[ip_start + 12 : ip_start + 16]))
        dst_ip = ".".join(map(str, packet_data[ip_start + 16 : ip_start + 20]))
        payload_start = ip_start + ihl

        if source_node is None and protocol in [1, 17]:
            source_node = src_ip

        if src_ip == source_node:
            ttl_counts[ttl] = ttl_counts.get(ttl, 0) + 1

            if protocol == 17 and len(packet_data) >= payload_start + 4:
                src_port = struct.unpack('>H', packet_data[payload_start: payload_start + 2])[0]
                if 33434 <= struct.unpack('>H', packet_data[payload_start + 2:payload_start + 4])[0] <= 33529:
                    if src_port not in probes_sent: probes_sent[src_port] = {'times': [], 'ttl': ttl}
                    probes_sent[src_port]['times'].append(absolute_time)
            elif protocol == 1 and packet_data[payload_start] == 8:
                seq = struct.unpack('>H', packet_data[payload_start + 6:payload_start + 8])[0]
                if seq not in probes_sent: probes_sent[seq] = {'times': [], 'ttl': ttl}
                probes_sent[seq]['times'].append(absolute_time)

        elif protocol == 1 and dst_ip == source_node:
            icmp_type = packet_data[payload_start]
            if icmp_type in [11, 0]:
                router_ip = src_ip
                if router_ip not in router_rtts:
                    router_rtts[router_ip] = []

                orig_ip_start = payload_start + 8
                if len(packet_data) >= orig_ip_start + 20:
                    orig_ihl = (packet_data[orig_ip_start] & 0x0F) * 4
                    orig_protocol = packet_data[orig_ip_start + 9]
                    orig_payload = orig_ip_start + orig_ihl

                    match_key = None
                    if orig_protocol == 17:
                        match_key = struct.unpack('>H', packet_data[orig_payload:orig_payload + 2])[0]
                    elif orig_protocol == 1:
                        match_key = struct.unpack('>H', packet_data[orig_payload + 6:orig_payload + 8])[0]
                    if icmp_type == 0 and not match_key: match_key = \
                    struct.unpack('>H', packet_data[payload_start + 6:payload_start + 8])[0]

                    if match_key and match_key in probes_sent:
                        probe_info = probes_sent[match_key]
                        probe_ttl = probe_info['ttl']

                        if probe_ttl not in hop_routers:
                            hop_routers[probe_ttl] = router_ip

                        for sent_time in probe_info['times']:
                            router_rtts[router_ip].append((absolute_time - sent_time) * 1000)
                        del probes_sent[match_key]

    sorted_ttls = sorted(hop_routers.keys())
    router_sequence = [hop_routers[t] for t in sorted_ttls]

    hop_rtts = []
    for router in router_sequence:
        rtts = router_rtts.get(router, [])
        hop_rtts.append(sum(rtts) / len(rtts) if rtts else 0.0)
    return ttl_counts, router_sequence, hop_rtts

def print_tabular_format(group_name, file_names, results):

    col_w = 17

    print(f"{group_name} Number of probes for each TTL\n")

    header = f"{'TTL':<5}" + "".join([f"{name:<{col_w}}" for name in file_names])
    print(header)

    max_ttl = 0
    for res in results:
        if res and res[0]:
            max_ttl = max(max_ttl, max(res[0].keys()))

    for ttl in range(1, max_ttl + 1):
        row_str = f"{ttl:<5}"
        for res in results:
            if res:
                count = res[0].get(ttl,0)
                row_str += f"{count:<{col_w}}"
            else:
                row_str += f"{'N/A':<{col_w}}"
        print(row_str)

    print('\n')


    print(f"{group_name} Intermediate Nodes\n")

    header = "".join([f"{name:<{col_w}}" for name in file_names])
    print(header)

    max_hops = max([len(res[1]) for res in results if res], default=0) if results else 0

    for hop_idx in range(max_hops):
        row_str = ""
        for res in results:
            if res and hop_idx < len(res[1]):
                ip = res[1][hop_idx]
                row_str += f"{ip:<{col_w}}"
            else:
                row_str += f"{' ':<{col_w}}"
        print(row_str)

    print('\n')

    print(f"{group_name} Average RTT's\n")

    header = f"{'TTL':<5}" + "".join([F"{name:<{col_w}}" for name in file_names])
    print(header)

    for hop_idx in range(max_hops):
        row_str = f"{hop_idx + 1:<5}"
        for res in results:
            if res and hop_idx < len(res[2]):
                avg_rtt = res[2][hop_idx]
                rtt_str = f"{round(avg_rtt, 2)}ms"
                row_str += f"{rtt_str:<{col_w}}"
            else:
                row_str += f"{' ':<{col_w}}"
        print(row_str)


def analyze_r2_group(group_name, file_list):
    results = [parse_r2_pcap(f) for f in file_list]
    print_tabular_format(group_name,file_list,results)

if __name__ == '__main__':

    group_1_files = ['group1-trace1.pcap', 'group1-trace2.pcap', 'group1-trace3.pcap', 'group1-trace4.pcap', 'group1-trace5.pcap']
    group_2_files = ['group2-trace1.pcap', 'group2-trace2.pcap', 'group2-trace3.pcap', 'group2-trace4.pcap', 'group2-trace5.pcap']

    analyze_r2_group('Group 2', group_1_files)