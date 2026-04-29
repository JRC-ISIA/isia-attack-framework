"""Module to capture network traffic"""

import threading, time, datetime, lcm, os, socket, struct
from exlcm.capture_cmd_t import capture_cmd_t
from exlcm.alias_cmd_t import alias_cmd_t
from helper_functions import report_event, request_ntp , get_lc, transfer_file,publish_task_status
from scapy.all import sniff, wrpcap

MULTICAST_GROUP = '239.255.76.67'
MULTICAST_PORT = 7667

CLIENT_ID = socket.gethostname()
CLIENT_IPS = socket.gethostbyname_ex(CLIENT_ID)[2]
CLIENT_ALIAS = "capture_module0"

HOSTNAME = "pi.isia"
USERNAME = "isia"
KEYFILE = "C:/Users/isia-ids/.ssh/id_ed25519"

LOCAL_PATH = None
REMOTE_PATH = "/home/isia/attack-framework/pcap"

def get_local_ip_for_multicast(target="8.8.8.8"):
    """Find local IP address of the active network interface."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((target, 80))
        local_ip = s.getsockname()[0]
    finally:
        s.close()
    return local_ip

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('', MULTICAST_PORT))
local_ip = get_local_ip_for_multicast()
mreq = struct.pack("4s4s", socket.inet_aton(MULTICAST_GROUP), socket.inet_aton(local_ip))
sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)


print(f"Listening to multicast group {MULTICAST_GROUP} on port {MULTICAST_PORT}...")
# request_ntp()

while True:
    try:

        lc = get_lc()
        # request_ntp()

        _state_lock = threading.Lock()
        _capture_thread: threading.Thread | None = None
        _stop_evt = threading.Event()

        CAPTURE_DIR = "captures"
        DEFAULT_BPF = "not (udp and (dst host 239.255.76.67 or src host 239.255.76.67) and port 7667)"

        def _capture_worker(iface: str, bpf_filter: str = DEFAULT_BPF):
            """performs capture until _stop_ect occures"""
            try:
                global LOCAL_PATH
                os.makedirs(CAPTURE_DIR, exist_ok=True)
                ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                pcap_path = os.path.join(CAPTURE_DIR,f"capture_{iface}_{ts}.pcap")
                LOCAL_PATH = pcap_path

                report_event("Capture Module", "INFO", f"_capture_worker started on: {iface}", lc, dest_channel="COORDINATOR_LOG")

                packets = []

                def _check_for_stop(_pkt):
                    """to check after each packet if sniff shall be stopped"""
                    return _stop_evt.is_set()

                def _on_packet(pkt):
                    packets.append(pkt)

                sniff(iface=iface, prn=_on_packet, stop_filter=_check_for_stop, filter=bpf_filter if bpf_filter else None)

                wrpcap(pcap_path, packets)
                report_event("Capture Module", "INFO", f"pcap saved to {pcap_path}", lc, dest_channel="COORDINATOR_LOG")

                report_event("Capture Module", "INFO", "_capture_worker stopped", lc, dest_channel="COORDINATOR_LOG")

            except Exception as e:
                publish_task_status("start_capture","Capture Module", "error", lc=lc)
                report_event("Capture Module", "ERROR", f"_capture_worker exception: {e}", lc, dest_channel="COORDINATOR_LOG")

        def start_capture(iface: str, bpf_filter: str = DEFAULT_BPF):
            """starts capture if not already running"""
            publish_task_status("start_capture", "Capture Module", "running", lc=lc)
            print("capture running")
            global _capture_thread
            with _state_lock:
                if _capture_thread and _capture_thread.is_alive():
                    report_event("Capture Module", "WARN", f"start_capture ignored; already running on thread {_capture_thread.name}", lc, dest_channel="COORDINATOR_LOG")
                    return
                _stop_evt.clear()
                _capture_thread = threading.Thread(target=_capture_worker,args=(iface,bpf_filter), daemon=True)
                _capture_thread.start()
                report_event("Capture Module", "INFO", f"start_capture launched on: {iface}", lc, dest_channel="COORDINATOR_LOG")
                publish_task_status("start_capture", "Capture Module", "finished", LC=lc)

        def stop_capture():
            """stops capture if alive"""
            publish_task_status("stop_capture", "Capture Module", "running", lc=lc)
            print("capture stopped")
            global _capture_thread
            with _state_lock:
                if not _capture_thread or not _capture_thread.is_alive():
                    report_event("Capture Module", "WARN", "stop_capture ignored; no thread running", lc, dest_channel="COORDINATOR_LOG")
                    return
                _stop_evt.set()
                t = _capture_thread
            t.join()
            with _state_lock:
                _capture_thread = None
            report_event("Capture Module", "INFO", "capture thread stopped", lc, dest_channel="COORDINATOR_LOG")
            
            report_event("Capture Module", "INFO", "attempting file transfer", lc, dest_channel="COORDINATOR_LOG")
            if LOCAL_PATH:
                if (transfer_file(hostname=HOSTNAME, username=USERNAME, keyfile=KEYFILE, local_path=LOCAL_PATH, remote_path=REMOTE_PATH)):
                    report_event("Capture Module", "INFO", "file transfer completed", lc, dest_channel="COORDINATOR_LOG")
                else: report_event("Capture Module", "ERROR", "file transfer failed", lc, dest_channel="COORDINATOR_LOG")
            else:
                report_event("Capture Module", "ERROR", "no capture file to transfer", lc, dest_channel="COORDINATOR_LOG")
            publish_task_status("stop_capture", "Capture Module", "finished", lc=lc)

        def on_cmd(channel,data):
            try:
                msg = capture_cmd_t.decode(data)

                if msg.command == "lcm_ping":
                    print(f"Ping received on {channel}")

                elif msg.command == "start_capture":
                    print("start")
                    iface = msg.iface
                    bpf = DEFAULT_BPF
                    if msg.bpf != "":
                        bpf = msg.bpf
                    report_event("Capture Module", "INFO", f"start_capture received: {iface}", lc, dest_channel="COORDINATOR_LOG")
                    start_capture(iface,bpf)

                elif msg.command == "stop_capture":
                    print("stop")
                    report_event("Capture Module", "INFO", "stop_capture received", lc, dest_channel="COORDINATOR_LOG")
                    stop_capture()

                # TODO: implement file transfer command if for specific files (e.g. old pcap), currently file transfer is triggered after stopping the capture
                # elif msg.command == "transfer_file":
                #     print("transfer")
                #     report_event("Capture Module", "INFO", "transfer_file command received", lc, dest_channel="COORDINATOR_LOG")
                #     if LOCAL_PATH:
                #         if (transfer_file(hostname=HOSTNAME, username=USERNAME, keyfile=KEYFILE, local_path=LOCAL_PATH, remote_path=REMOTE_PATH)):
                #             report_event("Capture Module", "INFO", "file transfer completed", lc, dest_channel="COORDINATOR_LOG")
                #         else: report_event("Capture Module", "ERROR", "file transfer failed", lc, dest_channel="COORDINATOR_LOG")
                #     else:
                #         report_event("Capture Module", "ERROR", "no capture file to transfer", lc, dest_channel="COORDINATOR_LOG")

                else:
                    print("error")
                    report_event("Capture Module", "ERROR", f"Unknown command received: {msg.command}", lc, dest_channel="COORDINATOR_LOG")

            except Exception as e:
                report_event("Capture Module", "ERROR", f"handler exception: {e}", lc, dest_channel="COORDINATOR_LOG")

        def set_alias(channel,data):

            global CLIENT_ALIAS

            if channel != "ALIAS_DISTR":
                return

            try:
                msg = alias_cmd_t.decode(data)
                if msg.ip in CLIENT_IPS:
                    CLIENT_ALIAS = msg.alias
                return

            except Exception as e:
                return

        if __name__ == "__main__":
            lc.subscribe("CAPTURE_MDL", on_cmd)
            lc.subscribe("ALIAS_DISTR", set_alias)
            while True:
            
                lc.handle()
                
    except KeyboardInterrupt:
        print(f'Interrupted by User. Exiting...')

    except Exception as e:
        print(f'Error: {e}')
        break

sock.close()