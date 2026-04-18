# improved network sniffer (vs code friendly)
# idea: capture packets + detect basic suspicious activity using time window

from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
import time
import sys

WINDOW_SIZE = 10   # seconds → detection window
packet_no = 0      # total packets seen
log_file = None    # file handler (opened once)


class SnifferState:
    def __init__(self):
        # tracking data (reset after every window)
        self.ip_counts = {}       # packets per IP
        self.port_scans = {}      # (ip, port) hit count
        self.multi_scans = {}     # ip -> set of ports
        self.syn_counts = {}      # SYN packets per IP
        self.window_start = time.time()

    def check_reset(self, current_time):
        # reset all counters after fixed time window
        # avoids memory growth + keeps detection rate-based
        if current_time - self.window_start > WINDOW_SIZE:
            self.ip_counts.clear()
            self.port_scans.clear()
            self.multi_scans.clear()
            self.syn_counts.clear()
            self.window_start = current_time


# global state object
state = SnifferState()


def process_packet(packet):
    # this function runs for every captured packet
    global packet_no
    packet_no += 1

    now = time.time()
    time_str = time.strftime("%H:%M:%S")

    # update/reset tracking window if needed
    state.check_reset(now)

    # default values (so code doesn't break)
    src_ip, dst_ip = "-", "-"
    src_port, dst_port = "-", "-"
    protocol = "Other"
    alert = ""

    # ---- IP layer ----
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # count packets from same IP
        state.ip_counts[src_ip] = state.ip_counts.get(src_ip, 0) + 1

        # simple flood detection (rate based)
        if state.ip_counts[src_ip] > 100:
            alert += "FLOOD "

    # ---- TCP layer ----
    if packet.haslayer(TCP):
        protocol = "TCP"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

        # SYN packets → used in scans/floods
        if packet[TCP].flags == "S" and src_ip != "-":
            state.syn_counts[src_ip] = state.syn_counts.get(src_ip, 0) + 1

            if state.syn_counts[src_ip] > 20:
                alert += "SYN_FLOOD "

    # ---- UDP ----
    elif packet.haslayer(UDP):
        protocol = "UDP"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    # ---- ICMP ----
    elif packet.haslayer(ICMP):
        protocol = "ICMP"

    # ---- Port scan detection ----
    if src_ip != "-" and dst_port != "-":

        # same port hit multiple times
        key = (src_ip, dst_port)
        state.port_scans[key] = state.port_scans.get(key, 0) + 1

        if state.port_scans[key] > 20:
            alert += "PORT_FLOOD "

        # multiple ports accessed → possible scan
        if src_ip not in state.multi_scans:
            state.multi_scans[src_ip] = set()

        state.multi_scans[src_ip].add(dst_port)

        if len(state.multi_scans[src_ip]) > 10:
            alert += "MULTI_PORT_SCAN "

    # ---- Payload inspection ----
    if packet.haslayer(Raw):
        try:
            # decode safely (ignore binary junk)
            payload = packet[Raw].load.decode(errors='ignore').lower()

            # basic keyword check
            if "password" in payload:
                alert += "SENSITIVE_DATA "
        except:
            pass  # ignore decode errors

    # ---- format output ----
    alert_str = f"[{alert.strip()}]" if alert else ""

    print(f"{time_str:<10} {packet_no:<5} {src_ip:<18} {src_port:<8} "
          f"{dst_ip:<18} {dst_port:<8} {protocol:<6} {alert_str}")

    # ---- write to log file ----
    if log_file:
        try:
            log_file.write(
                f"{time_str} {src_ip}:{src_port} -> {dst_ip}:{dst_port} {protocol} {alert_str}\n"
            )
        except:
            pass


def start_sniffer(limit=0):
    # main function to start packet capture
    global log_file

    print("\n[+] Sniffer started (CTRL+C to stop)\n")

    # table header (printed once)
    print("=" * 110)
    print(f"{'Time':<10} {'No.':<5} {'Source IP':<18} {'SPort':<8} "
          f"{'Destination IP':<18} {'DPort':<8} {'Proto':<6} {'Alerts'}")
    print("=" * 110)

    try:
        # open log file once (better performance)
        log_file = open("sniffer_log.txt", "a")

        # if limit = 0 → infinite capture
        if limit == 0:
            sniff(prn=process_packet, store=False)
        else:
            sniff(prn=process_packet, store=False, count=limit)

    except KeyboardInterrupt:
        print("\n[+] Stopped by user")

    except Exception as e:
        print("Error:", e)

    finally:
        # always close file properly
        if log_file:
            log_file.close()


def show_help():
    # basic usage info
    print("\nUsage:")
    print("  python sniffer.py           -> ask input")
    print("  python sniffer.py 100       -> capture 100 packets")
    print("  0 = infinite capture")


# ---- main entry ----
if __name__ == "__main__":

    # no argument → ask user input
    if len(sys.argv) == 1:
        try:
            limit = int(input("Enter packet limit (0 = infinite): "))
        except:
            limit = 0

        start_sniffer(limit)

    # help option
    elif sys.argv[1] in ["-h", "--help"]:
        show_help()

    else:
        try:
            limit = int(sys.argv[1])
            start_sniffer(limit)
        except:
            print("Invalid input")