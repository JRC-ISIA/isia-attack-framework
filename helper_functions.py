"""Contains functions that are requiered by multiple modules"""

import os,sys,time,lcm,ntplib,datetime,platform
from exlcm.log_t import log_t
from exlcm.task_status_t import task_status_t
import paramiko
from scp import SCPClient

_lc = None

def get_lc(url: str | None = None) -> lcm.LCM:
    """Singleton-LCM-Instanz"""
    global _lc
    if _lc is None:

        if url:
            _lc = lcm.LCM(url)
            return _lc
        
        uri = os.environ.get("LCM_URI")

        if uri:
            _lc = lcm.LCM(uri)
            return _lc
        
        group = os.environ.get("LCM_GROUP")
        port = os.environ.get("LCM_PORT")
        iface = os.environ.get("LCM_IFACE")

        if group or port or iface:
            group = group or "239.255.76.67"
            port = port or "7667"
            base = f'udpm://{group}:{port}'

            if iface:
                base = f'{base}?iface={iface}'
            _lc = lcm.LCM(base)

            return _lc
        
        _lc = lcm.LCM("udpm://239.255.76.67:7667")
    
    return _lc

def request_ntp(ntp_server="172.17.21.254"):
    """Requests ntp from server"""
#     try: 
#         client = ntplib.NTPClient()
#         resp = client.request(ntp_server, version=3)

#         tx_time = resp.tx_time

#         if platform.system() == "Windows":
#             dt = datetime.datetime.fromtimestamp(tx_time)
#             date_str = dt.strftime('%Y-%m-%d')
#             time_str = dt.strftime('%H:%M:%S')
#             os.system(f'date {date_str} && time {time_str}')

#         elif platform.system() == "Linux":
#             os.system(f"sudo date -s '@{resp.tx_time}'")

#         else:
#             print(f"NTP sync not implemented for platform {platform.system()}")

#     except Exception as e:
#         print("[WARN] ntp sync failed: ", e)
    pass

def publish_task_status(task_type: str, module: str, state: str, target:str = "", info: str = "", lc=None):
    """Publishes a task status update to the TASK_STATUS channel."""
    lc = lc or get_lc()
    msg = task_status_t()
    msg.task_type = task_type
    msg.module = module
    msg.state = state
    msg.target = target
    msg.info = info
    msg.timestamp = int(time.time() * 1000)

    try:
        lc.publish("TASK_STATUS", msg.encode())
    except Exception as e:
        print(f'[publish_task_status] publish failed: {e!r}', file=sys.stderr)

def report_event(module: str, level: str, text: str, lc: lcm.LCM | None = None, dest_channel: str = "LOGGER") -> None:
    """Sende einen Log-Eintrag an den LOGGER-Channel (LCM)."""
    lc = lc or get_lc()
    m = log_t()
    m.module = module
    m.level = level
    m.text = text
    m.timestamp = int(time.time() * 1000)

    try:
        lc.publish(dest_channel, m.encode())
    
    except Exception as e:
        print(f'[report_event] publish failed: {e!r}', file=sys.stderr)

def transfer_file(hostname, username, local_path, remote_path, password=None, keyfile=None):
    try:
        ssh = paramiko.SSHClient()
        ssh.load_system_host_keys()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname, username=username, password=password, key_filename=keyfile)
        with SCPClient(ssh.get_transport()) as scp:
            scp.put(local_path, remote_path)
        print(f"File {local_path} transferred to {hostname}:{remote_path}")
        success = True
    except Exception as e:
        print(f"Error transferring file: {e}")
        success = False
    finally:
        ssh.close()
    return success
