from scapy.all import sniff
from db import exec_write

def pkt_handler(pkt):
    print("[DEBUG] Packet captured")
    try:
        if not pkt.haslayer('IP'):
            return
        ip = pkt['IP']
        l4 = pkt.getlayer('TCP') or pkt.getlayer('UDP')
        if not l4:
            return

        src_port = getattr(l4, 'sport', None)
        dst_port = getattr(l4, 'dport', None)
        proto = l4.name  # 'TCP' or 'UDP'

        exec_write(
            """INSERT INTO net_events (ts, src_ip, dst_ip, src_port, dst_port, proto, raw)
               VALUES (FROM_UNIXTIME(%s), %s, %s, %s, %s, %s, %s)""",
            (pkt.time, ip.src, ip.dst, src_port, dst_port, proto, str(pkt)),
        )

        print(f"Inserted: {ip.src} -> {ip.dst} ({src_port}->{dst_port}) [{proto}]")

    except Exception as e:
        print(f"[SNIFF_ERR] {e}")

def start_sniffer(iface="enp0s3"):
    print(f"[INFO] Starting sniffer on {iface}...")
    sniff(prn=pkt_handler, store=False, iface=iface, count=0)

if __name__ == "__main__":
    start_sniffer("enp0s3")
 
