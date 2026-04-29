"""Attack Client"""

import time, json, lcm, tempfile, threading, subprocess, os, time, socket, base64, netifaces
from exlcm.attack_cmd_t import attack_cmd_t
from exlcm.task_status_t import task_status_t
from exlcm.alias_cmd_t import alias_cmd_t
from helper_functions import report_event, request_ntp, get_lc, publish_task_status

lc = get_lc()

CLIENT_ID = socket.gethostname()
CLIENT_IPS = []
CLIENT_ALIAS = "attack_agent0"

# request_ntp()

_current_proc = None
_current_proc_lock = threading.Lock()
_current_proc_meta = {}

def _get_iface_local():
    global CLIENT_IPS
    for iface in netifaces.interfaces():
        addrs = netifaces.ifaddresses(iface)
        if netifaces.AF_INET in addrs:
            for entry in addrs[netifaces.AF_INET]:
                ip = entry.get("addr")
                if ip and not ip.startswith("127."):
                    CLIENT_IPS.append(ip)

def publish_status(task_type: str, state: str, info: str = "", script_id: str | None = None):
# def publish_status(status: str, info: str = "", script_id: str | None = None):
    
    target_id = CLIENT_ALIAS or CLIENT_ID
    publish_task_status(task_type=task_type, module="Attack Client", state=state, target=CLIENT_ALIAS, info=info, lc=lc)

    # payload = {
    #     "targets": [target_id],
    #     "status": status,
    #     "info": info,
    #     "script_id": script_id,
    #     "timestamp": int(time.time() * 1000)
    # }

    # try:
    #     lc.publish("ATTACK_STATUS", json.dumps(payload).encode())
    # except Exception as e:
    #     print(f"Attack Client failed publishing status: {e}")

    report_event("Attack Client", "INFO" if state not in ("error",) else "ERROR", f"{state}: {info}", lc, dest_channel="COORDINATOR_LOG")

def run_script(path: str, args: list, script_id: str | None):

    report_event("Attack Client", "INFO", f"run_script started", lc, dest_channel="COORDINATOR_LOG")

    global _current_proc, _current_proc_meta

    try:
        publish_status(task_type="start_attack", state="running", info=f"Starting {path} {' '.join(args)}", script_id=script_id)
        p = subprocess.Popen(["/bin/bash", path] + args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        with _current_proc_lock:
            _current_proc = p
            _current_proc_meta = {"script_id":script_id, "path":path, "start_ts":int(time.time()*1000)}
        stdout, stderr = p.communicate()
        print('SCRIPT SDTOUT:')
        print(stdout)
        if stderr:
            print('SCRIPT SDTERR:')
            print(stderr)
        rc = p.returncode
        info = f"rc={rc}"
        if stdout:
            info += f"stdout={stdout[:400]}"
        if stderr:
            info += f"stderr={stderr[:400]}"
            publish_status(task_type="start_attack", state="error", info=info, script_id=script_id)
        else:
            publish_status(task_type="start_attack", state="finished", info=info, script_id=script_id)
            report_event("Attack Client", "INFO", f"run_script finished", lc, dest_channel="COORDINATOR_LOG")

    except Exception as e:
        publish_status(task_type="start_attack", state="error", info=f"execution exception: {e}", script_id=script_id)
        report_event("Attack Client", "ERROR", f"run_script ran into error: {e}", lc, dest_channel="COORDINATOR_LOG")
    
    finally:
        with _current_proc_lock:
            _current_proc = None
            _current_proc_meta = {}

def launch_attack_local(msg:attack_cmd_t):

    script_id = getattr(msg, "script_id", "") or ""

    if getattr(msg, "script_inline"):
        
        try:
            raw = base64.b64decode(msg.script_inline)
        
        except Exception as e:
            publish_status(task_type="start_attack", state="error", info=f"Failed to save/launch inline script: {e}", script_id=script_id)
            return

        fd, path = tempfile.mkstemp(suffix=os.path.splitext(msg.script_filename)[1] or "")
        os.close(fd)
        
        with open(path, "wb") as f:
            f.write(raw)
        
        os.chmod(path, 0o755)
        cleanup = True
        run_path = path
    
    else:
        run_path = msg.script_filename
        cleanup = False

        if not run_path or not os.path.isfile(run_path):
            publish_status(task_type="start_attack", state="error", info=f"Locale script not found: {run_path}", script_id=script_id)
            return
        
    publish_status(task_type="start_attack", state="running", info=f"Inline script starting on {run_path}", script_id=script_id)
    
    try:
        if run_path.endswith((".sh", ".bash")):
            proc = subprocess.Popen(["/bin/bash", run_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        else:
            proc = subprocess.Popen([run_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        out,err = proc.communicate(timeout=3000)
        rc = proc.returncode
    except Exception as e:
        err = str(e)
        rc = -1

    publish_status(task_type="start_attack", state="finished", info=f"rc={rc}", script_id=script_id)
    if err:
        publish_status(task_type="start_attack", state="error", info=f"stderr: {err.strip()}", script_id=script_id)

    if cleanup:
        try:
            os.remove(path)
        except Exception:
            pass

def stop_running_attack():
    
    global _current_proc
    
    with _current_proc_lock:
        p = _current_proc
    
    if not p:
        publish_status(task_type="start_attack", state="error", info="No running attack to stop", script_id=None)
        return
    
    try:
        publish_status(task_type="start_attack", state="stopping", info=f"Terminate pid {p.pid}", script_id=_current_proc_meta.get("script_id"))
        p.terminate()

        try:
            p.wait(timeout=3.0)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait(timeout=3.0)
        publish_status(task_type="start_attack", state="finished", info=f"Process {p.pid} stopped", script_id=_current_proc_meta.get("script_id"))

    except Exception as e:
        publish_status(task_type="start_attack", state="error", info=f"Error stopping process {p.pid}: {e}", script_id=_current_proc_meta.get("script_id"))

    finally:
        with _current_proc_lock:
            _current_proc = None
            _current_proc_meta = {}

def on_cmd(channel,data):

    if channel != "ATTACK_CLNT":
        return
    
    try:
        msg = attack_cmd_t.decode(data)
        payload = json.loads(msg.payload_json)
        targets = payload.get("targets", [])
        if CLIENT_ALIAS not in targets:
            return
        if not hasattr(msg, "command") or msg.command == "":
            return
        
    except Exception as e:
        return
    
    print(f"msg receives: {msg.command}")
    
    if msg.command == "lcm_ping":
        report_event("Attack Client", "INFO", f"lcm_ping received: {channel}", lc, dest_channel="COORDINATOR_LOG")
        return
    
    # try:
    #     payload = json.loads(msg.payload_json) if msg.payload_json else {}
    # except Exception:
    #     payload = {}

    if msg.command == "start_attack":
        report_event("Attack Client", "INFO", "start_attack received", lc, dest_channel="COORDINATOR_LOG")
        launch_attack_local(msg)
        return
        
    elif msg.command == "stop_attack":
        report_event("Attack Client", "INFO", "stop_attack received", lc, dest_channel="COORDINATOR_LOG")
        stop_running_attack()
        return
    
    else:
        print("error")
        report_event("Attack Client", "ERROR", f"Unknown command received: {msg.command}", lc, dest_channel="COORDINATOR_LOG")

def set_alias(channel,data):

    global CLIENT_ALIAS

    if channel != "ALIAS_DISTR":
        return
    
    report_event("Attack Client", "INFO", f"set_alias received: {channel}", lc, dest_channel="COORDINATOR_LOG")
    
    try:
        msg = alias_cmd_t.decode(data)
        if msg.ip in CLIENT_IPS:
            CLIENT_ALIAS = msg.alias
            report_event("Attack Client", "INFO", f"Alias set to: {CLIENT_ALIAS} on {msg.ip}", lc, dest_channel="COORDINATOR_LOG")
        return
    
    except Exception as e:
        report_event("Attack Client", "ERROR", f"set_alias ran into error: {e}", lc, dest_channel="COORDINATOR_LOG")
        return

lc.subscribe("ATTACK_CLNT", on_cmd)
lc.subscribe("ALIAS_DISTR", set_alias)

while True:
    
    _get_iface_local()
    request_ntp()
    lc.handle()