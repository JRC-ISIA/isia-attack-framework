#!/usr/bin/env python3

"""Coordinates Attack Agent, Feature Extractor, Logger, Storage Transfer and Traffic Capture Module"""

import json, time, lcm, datetime, threading, os, base64, uuid, subprocess, argparse, dateparser
from typing import List, Optional
from pathlib import Path
from exlcm.store_cmd_t import store_cmd_t
from exlcm.alias_cmd_t import alias_cmd_t
from exlcm.attack_cmd_t import attack_cmd_t
from exlcm.capture_cmd_t import capture_cmd_t
from exlcm.extract_cmd_t import extract_cmd_t
from exlcm.log_schedule import log_schedule
from exlcm.log_t import log_t
from exlcm.task_status_t import task_status_t
from helper_functions import report_event, request_ntp, get_lc

ATTACK_DEF = None
lc = get_lc()

RUN_DEF_THREAD: threading.Thread | None = None
RUN_DEF_STOP = threading.Event()

SCHEDULE: datetime.datetime | None = None

# _ATTACK_STATUS = {}
_TASK_STATUS = {}
_INLINE_LIMIT_BYTES = 2000

def set_def_schedule(time:datetime.datetime | str | None = None):
    global SCHEDULE

    if SCHEDULE is None:
        SCHEDULE = datetime.datetime.now()

    if type(time) is datetime.datetime:
        SCHEDULE = time

    elif type(time) is str:
        _base = SCHEDULE

        try:
            _time = datetime.datetime.fromisoformat(time)
            SCHEDULE = _time

        except ValueError:
            SCHEDULE = dateparser.parse('in '+time,settings={"RELATIVE_BASE":_base})

        except Exception as e:
            print(f"> Error: {e}")
        
def send_inline_script(targets: List[str], interpreter: Optional[str] = "/bin/bash", script_path: Optional[str] = None, attack_type: str = "", args: Optional[List[str]] = None):
    args = args or []
    script_inline = ""
    script_filename = ""
    script_id = ""

    if script_path:
        with open(script_path, "rb") as f:
            raw =f.read()
        if len(raw) > _INLINE_LIMIT_BYTES:
            raise ValueError(f"Script too large for inline send ({len(raw)} bytes).")

        script_inline = base64.b64encode(raw).decode("ascii")
        script_filename = os.path.basename(script_path)
        script_id = str(uuid.uuid4())
    
    msg = attack_cmd_t()
    msg.command = "start_attack"
    msg.payload_json = json.dumps(
        {
            "targets": targets,
            "attack_type": attack_type,
            "args": args,
            "interpreter": interpreter
        }
    )
    msg.timestamp = int(time.time() * 1000)
    msg.script_inline = script_inline
    msg.script_filename = script_filename
    msg.script_id = script_id

    lc.publish("ATTACK_CLNT", msg.encode())
    report_event("Coordinator", "INFO", "Attack command published to ATTACK_CLNT", lc)

def on_task_status(channel, data):
    msg = task_status_t.decode(data)
    key = (msg.task_type, msg.target if msg.target else None)
    _TASK_STATUS[key] = msg.state
lc.subscribe("TASK_STATUS", on_task_status)

# def on_attack_status(channel, data):
#     try:
#         payload = json.loads(data.decode())
#         targets = payload.get("targets")
#         status = payload.get("status")
#         info = payload.get("info")

#         if isinstance(targets, list):
#             for t in targets:
#                 _ATTACK_STATUS[str(t)] = status
#         elif isinstance(targets, str):
#             _ATTACK_STATUS[targets] = status

#         report_event("Coordinator", "INFO", f"Attack status from {targets}: {status} {info}", lc)
#     except Exception as e:
#         report_event("Coordinator", "ERROR", f"Bad attack status {e}", lc)
# lc.subscribe("ATTACK_STATUS", on_attack_status)

def on_module_log(channel, data):

    if data[:8] != log_t._get_packed_fingerprint():
        return

    try:
        msg = log_t.decode(data)
        print(f"> {msg.text}")
        lc.publish("LOGGER", msg.encode())
    except Exception as e:
        print(f'> [Coordinator] fails to forward log. {e}')

def lcm_listener():
    lc.subscribe("COORDINATOR_LOG", on_module_log)
    report_event("Coordinator", "INFO", "Listening for module msgs...", lc)

    while True:
        try:
            lc.handle()
        except Exception as e:
            print(f'> [Coordinator] LCM listener error: {e}')

def help():
    print(
        "Following commands are defined for GUI:\n\
        load_ad <FILE> : loads an attack definition as json\n\
        run_def : runs the definition if set\n\
        set_alias <IPADDR> <ALIAS> : sets alias to module on corresponding ip address\n\
        execute_local <COMMAND-STRING>: can be used to transfer bigger files via scp to attack client\n\
        start_attack <ALIAS1,ALIAS2> <INTERPRETER> <LOCAL_PATH> : to start attacks by scripts/files transfered to attack client before\n\
        start_attack_script <ALIAS1,ALIAS2> <INTERPRETER> </PATH/TO/SCRIPT> <ARG1> <ARG2> : starts attack on clients with script\n\
        stop_attack : stops running attack\n\
        start_capture <IFACE> : starts capturing an interface\n\
        stop_capture : stops running capturing\n\
        shutdown : terminates coordinator\n\
        help : shows list of options\n"
    )
    print(
        "Following commands are defined for CLI:\n\
        --auto_run <FILE> : runs the definition\n\
        example: python3 coordinator.py --auto_run <PATH/TO/JSON>\n"
    )

def lcm_ping(channel:str):

    ch = channel
   
    report_event("Coordinator", "INFO", f"Pings {ch}", lc)
    
    if ch == "ATTACK_CLNT":
        msg = attack_cmd_t()
        msg.command = "lcm_ping"
        msg.payload_json = json.dumps({"test":"test"})
        msg.timestamp = int(time.time() * 1000)
        msg.script_inline = "None"
        msg.script_filename = "None"
        msg.script_id = "None"        
        lc.publish(ch, msg.encode())
    elif ch == "CAPTURE_MDL":
        msg = capture_cmd_t()
        msg.command = "lcm_ping"
        msg.iface = "None"
        msg.timestamp = int(time.time() * 1000)
        msg.bpf = "None"
        lc.publish(ch, msg.encode())
    else:
        print(f"> [ERROR] Unknown channel: {ch}")
        return
    
    report_event("Coordinator", "INFO", f"Ping published to {ch}", lc)

def load_attack_definition(file_path):
    """Loads attack definition from JSON file by given path"""

    global ATTACK_DEF

    try:
        with open(file_path, 'r') as file:
            attack_definition = json.load(file)
        file.close()
        ATTACK_DEF = attack_definition
        report_event("Coordinator", "UPDATE", "Attack defintion loaded", lc)

    except Exception as e:
        return print(f'> Error loading definition: {e}')

def exeqt_attack_def(task,targets:list=None,params:dict=None):
    
    RUN_DEF_STOP.clear()

    function_map = {
        "start_attack": start_attack,
        "start_attack_script": send_inline_script,
        "stop_attack": stop_attack,
        "start_capture": start_capture,
        "stop_capture": stop_capture,
        "set_alias": set_alias,
        "extract_features": extract_features,
        "storage_transfer": storage_transfer,
        "execute_local": exeqt_local
        }
    
    if task in function_map:
        if task == "start_attack":
            function_map[task](targets, params["interpreter"], params["script"])
        elif task == "start_attack_script":
            function_map[task](targets, params["interpreter"], params["script"])
        elif task == "start_capture":
            function_map[task](params["iface"], params["bpf"])
        elif task == "set_alias":
            function_map[task](params["iface"], params["alias"])
        elif task == "execute_local":
            function_map[task](params["cmd"])
        else:
            function_map[task]()
    else:
        print(f"> Task not known: {task}")
        report_event("Coordinator", "ERROR", f"Task not known: {task}", lc)    

def run_definition():
    if ATTACK_DEF is None:
        report_event("Coordinator", "ERROR", "No attack definition set", lc)
        print(f'> Error loading definition: No definition set')
        return
    
    report_event("Coordinator", "INFO", "Execution of attack definition requested", lc)

    try:
        for task in ATTACK_DEF['tasks']:
            report_event("Coordinator", "INFO", f"Task id {task['id']} of attack definition started", lc)
            task_type = task["type"]
            params = task["params"]
            targets = task["targets"]
            raw_blocking = task.get("blocking", False)
            if isinstance(raw_blocking,str):
                blocking = raw_blocking.lower() in ("true", "1", "yes")
            else:
                blocking = bool(raw_blocking)
            if task["time"] != "":
                set_def_schedule(task["time"])
                if SCHEDULE.tzinfo:
                    now = datetime.datetime.now(SCHEDULE.tzinfo)
                else: 
                    now = datetime.datetime.now()
                if SCHEDULE > now:
                    print(f"> Task {task['id']} will be executed at {SCHEDULE.isoformat()}")
                    wait_seconds = (SCHEDULE - now).total_seconds()
                    while wait_seconds > 0 and not RUN_DEF_STOP.is_set():
                        step = min(wait_seconds, 1.0)
                        time.sleep(step)
                        wait_seconds -= step
                    if RUN_DEF_STOP.is_set():
                        report_event("Coordinator", "INFO", "Execution of attack definition aborted", lc)
                        print(f"> Execution aborted while task {task['id']}")
                        print("> ", end="", flush=True)
                        return
            if blocking:
                if isinstance(targets, list) and targets:
                    for t in targets:
                        if t:
                            _TASK_STATUS[(task_type, str(t))] = None
                elif isinstance(targets, str) and targets:
                    _TASK_STATUS[(task_type, targets)] = None
                else:
                    _TASK_STATUS[(task_type, None)] = None
            exeqt_attack_def(task_type, targets, params)
            
            report_event("Coordinator", "INFO", f"Task id {str(task['id'])} of attack definition executed", lc)

            if blocking:
                report_event("Coordinator", "INFO", f"Task id {str(task['id'])} is blocking", lc)

                expected = []

                if isinstance(targets, list):
                    expected = [str(t) for t in targets if t]
                elif isinstance(targets, str) and targets:
                    expected = [targets]

                if expected:
                    while True:
                        all_done = True
                        for tar in expected:
                            stat = _TASK_STATUS.get((task_type, tar))
                            if not isinstance(stat, str):
                                all_done = False
                                break
                            if stat.lower() not in ('finished', 'error'):
                                all_done = False
                                break
                        if all_done:
                            break
                        time.sleep(0.5)

                else:
                    while True:
                        state = _TASK_STATUS.get((task_type, None))
                        if isinstance(state, str) and state.lower() in ("finished", "error"):
                            break
                        time.sleep(0.5)
            
            # reset SCHEDULE to now for next task if not set by task already
            if blocking:
                if SCHEDULE and SCHEDULE.tzinfo:
                    set_def_schedule(datetime.datetime.now(SCHEDULE.tzinfo))
                else:
                    set_def_schedule(datetime.datetime.now())

            print(f"> Task {task['id']} finished")
    
    except KeyboardInterrupt:
        print("\n> Interupped by User.")
        report_event("Coordinator", "INFO", "Execution of attack definition interruped by user", lc)

    except Exception as e:
        print(f"> Error while running definition: {e}")
        report_event("Coordinator", "ERROR", f"run_definition exception: {e}", lc)

    finally:
        report_event("Coordinator", "INFO", "Attack definition finished, returning control", lc)
        print("> Definition finished — you can continue using the CLI.")
        return

def start_attack(targets:list, interpreter:str | None = "/bin/bash", script:str | None = None):
   
    report_event("Coordinator", "INFO", "Attack start requested (local script)", lc)
    
    msg = attack_cmd_t()
    msg.command = "start_attack"
    msg.payload_json = json.dumps({
        "targets": targets,
        "attack_type": "",
        "args": [],
        "interpreter": interpreter
    })
    msg.timestamp = int(time.time() * 1000)
    msg.script_inline = ""
    msg.script_filename = script or ""
    msg.script_id = str(uuid.uuid4())
    lc.publish("ATTACK_CLNT", msg.encode())
    report_event("Coordinator", "INFO", "Attack command published to ATTACK_CLNT", lc)

def stop_attack():
    "will stop attack"
    report_event("Coordinator", "INFO", "Attack stop requested", lc)
    
    msg = attack_cmd_t()
    msg.command = "stop_attack"
    msg.payload_json = json.dumps({
        "definition": None,
        "start_time": None
    })
    msg.timestamp = int(time.time() * 1000)

    lc.publish("ATTACK_CLNT", msg.encode())

    report_event("Coordinator", "INFO", "Attack command published to ATTACK_CLNT", lc)

def start_capture(interface, filter=None):
    """Starts traffic capture of defined intertface"""
    report_event("Coordinator", "INFO", "Capture start requested", lc)
    
    msg = capture_cmd_t()
    msg.command = "start_capture"
    msg.iface = interface
    msg.timestamp = int(time.time() * 1000)
    msg.bpf = filter or ""

    lc.publish("CAPTURE_MDL", msg.encode())

    report_event("Coordinator", "INFO", "Capture command published to CAPTURE_MDL", lc)

def stop_capture():
    """stops traffic capture"""
    report_event("Coordinator", "INFO", "Capture stop requested", lc)
    
    msg = capture_cmd_t()
    msg.command = "stop_capture"
    msg.iface = ""
    msg.timestamp = int(time.time() * 1000)

    lc.publish("CAPTURE_MDL", msg.encode())

    report_event("Coordinator", "INFO", "Capture command published to CAPTURE_MDL", lc)

def set_alias(ipaddr, alias):
    # TODO: enable multidevice option (e.g.list)

    report_event("Coordinator", "INFO", f"alias_set requested for {ipaddr}: {alias}", lc)

    msg = alias_cmd_t()
    msg.ip = ipaddr
    msg.alias = alias
    msg.timestamp = int(time.time() * 1000)
    lc.publish("ALIAS_DISTR", msg.encode())
    
    report_event("Coordinator", "INFO", f"alias_set request published to ALIAS_DISTR", lc)

def exeqt_local(cmd:list[str]):
    report_event("Coordinator", "INFO", "Execute local requested", lc)
    for c in cmd:
        c = c.strip()
        report_event("Coordinator", "INFO", f"Executing '{c}'", lc)
        try:
            proc = subprocess.run(c, shell=True,capture_output=True,text=True,timeout=300)
            if proc.stdout:
                report_event("Coordinator", "INFO", f"Execution of '{c}' successful", lc)
            if proc.stderr:
                report_event("Coordinator", "ERROR", f"Execution of '{c}' unsuccessful: stderr={proc.stderr.strip()}", lc)
            if proc.returncode != 0:
                report_event("Coordinator", "ERROR", f"Execution of '{c}' unsuccessful: rc={proc.returncode}", lc)
        except Exception as e:
            report_event("Coordinator", "ERROR", f"Execution of '{c}' unsuccessful: {e}", lc)

def set_logger_schedule(hour: int = 0, minute: int = 0, interval: int = 24):
    report_event("Coordinator", "INFO", "Logger schedule update requested", lc)
    msg = log_schedule()
    msg.hour = hour
    msg.minute = minute
    msg.interval_hours = interval
    lc.publish("LOGGER_CFG", msg.encode())
    report_event("Coordinator", "INFO", "Logger schedule update published to LOGGER_CFG", lc)

def is_dir_empty(path_input: str):
    path = Path(path_input).resolve()
    print(f"> Checking directory: {path}")
    if path.exists() and path.is_dir():
        has_content = any(item for item in path.iterdir() if item.is_file())
        return not has_content
    return True

def extract_features():
    report_event("Coordinator", "INFO", f"Feature extraction requested", lc)
    if is_dir_empty("./pcap"):
        report_event("Coordinator", "ERROR", f"No pcap files found for feature extraction", lc)
        print(f"> No pcap files found in /pcap for feature extraction.")
        return
    else:
        msg = extract_cmd_t()
        msg.command = "extract_features"
        msg.file = str(next(item.name for item in Path("./pcap").iterdir() if item.is_file()))
        lc.publish("FEATURE_EXTR", msg.encode())
        report_event("Coordinator", "INFO", f"Feature extraction command published to FEATURE_EXTR for file {msg.file}", lc)
        print(f"> Feature extraction command published for file {msg.file}. Waiting for completion...")

def storage_transfer():
    report_event("Coordinator", "INFO", f"Storage transfer requested", lc)
    if is_dir_empty("./dataset"):
        report_event("Coordinator", "ERROR", f"No dataset files found for storage transfer", lc)
        print("> No dataset files found in /dataset for storage transfer.")
        return
    else:
        msg = store_cmd_t()
        msg.command = "transfer_file"
        lc.publish("STORAGE_TRANS", msg.encode())
        report_event("Coordinator", "INFO", f"Storage transfer command published to STORAGE_TRANSFER", lc)
        print(f"> Storage transfer command published for file.")

def main():
    """listens to commandline input"""

    global RUN_DEF_THREAD
    global RUN_DEF_STOP

    set_def_schedule()

    # request_ntp()

    parser = argparse.ArgumentParser()
    parser.add_argument("--auto_run", help="Path to the attack definition JSON to load and run", )
    args, _ = parser.parse_known_args()

    if args.auto_run:
        try:
            report_event("Coordinator", "INFO", "Autorun attack definition requested", lc)
            load_attack_definition(args.auto_run)
            report_event("Coordinator", "UPDATE", "Autorun: attack definition loaded", lc)
        except Exception as e:
            report_event("Coordinator", "ERROR", f"Failed to auto-run {args.auto_run}: {e}", lc)
            return
        
        if RUN_DEF_THREAD and RUN_DEF_THREAD.is_alive():
            print("> A definition is already running.")
        else:
            RUN_DEF_THREAD = threading.Thread(target=run_definition, daemon=False)
            RUN_DEF_THREAD.start()
            print("> Started running the ATTACK_DEF in the background.")
            report_event("Coordinator", "INFO", "Autorun: Started running the ATTACK_DEF in the background.", lc)
        try:
            RUN_DEF_THREAD.join()
        except KeyboardInterrupt:
            report_event("Coordinator", "ERROR", f"Failed to join auto-run {args.auto_run}", lc)
            RUN_DEF_STOP.set()
            RUN_DEF_THREAD.join()

        return

    while True:
        try:
            user_input = input("> ").strip()
            if user_input == "":
                continue
            elif user_input.lower() == "help":
                help()
            elif user_input.lower().startswith("set_alias"):
                parts = user_input.split(maxsplit=2)
                ipaddr = parts[1]
                alias = parts[2]
                set_alias(ipaddr,alias)
            elif user_input.lower().startswith("lcm_ping"):
                parts = user_input.split(maxsplit=1)
                channel = parts[1]
                # TODO: Extend function (on module side) to test other channels
                if channel != "ATTACK_CLNT":
                    print(f"> Channel: {channel} unknnown.")
                    return
                lcm_ping(channel)
            elif user_input.lower().startswith("load_ad"):
                parts = user_input.split(maxsplit=1)
                file_path = parts[1]
                load_attack_definition(file_path)
            elif user_input.lower().startswith("run_def"):
                if RUN_DEF_THREAD and RUN_DEF_THREAD.is_alive():
                    print("> A definition is already running.")
                else:
                    RUN_DEF_THREAD = threading.Thread(target=run_definition, daemon=True)
                    RUN_DEF_THREAD.start()
                    print("> Started running the ATTACK_DEF in the background.")
                    try:
                        RUN_DEF_THREAD.join()
                    except KeyboardInterrupt:
                        print("\n> Interupped by User while waiting for definition to complete.")
                        RUN_DEF_STOP.set()
                        RUN_DEF_THREAD.join()
            elif user_input.lower() == "stop_def":
                RUN_DEF_STOP.set()
                print("> Stop signal sent to running definition.")
            elif user_input.lower().startswith("start_attack_script"):
                parts = user_input.split()
                targets = parts[1].split(",")
                interpreter = parts[2]
                script_path = parts[3]
                try: 
                    send_inline_script(targets=targets,interpreter=interpreter,script=script_path)
                except Exception as e:
                    print(f"> Fails to send script: {e}")
            elif user_input.lower().startswith("start_attack"):
                parts = user_input.split()
                targets = parts[1].split(",")
                interpreter = parts[2]
                script_path = parts[3]
                args = parts[4:]
                try: 
                    start_attack(targets=targets,interpreter=interpreter,script_path=None,args=args)
                except Exception as e:
                    print(f"> Fails to send script: {e}")
            elif user_input.lower().startswith("execute_local"):
                parts = user_input.split()
                commands = parts[1].split(",")
                exeqt_local(cmd=commands)
            elif user_input.lower() == "stop_attack":
                stop_attack()
            elif user_input.lower().startswith("start_capture"):
                parts = user_input.split(maxsplit=1)
                interface = parts[1]
                start_capture(interface)
            elif user_input.lower() == "stop_capture":
                stop_capture()
            elif user_input.lower().startswith("extract_features"):
                extract_features()
            elif user_input.lower().startswith("storage_transfer"):
                storage_transfer()
            elif user_input.lower() == "shutdown":
                #TODO: terminate all modules
                report_event("Coordinator","INFO","Manually shutting down")
                print("> Exiting...")
                break
            else:
                print(
                    f"UNKNOWN COMMAND: {user_input}\n"                    
                )
                help()
        except KeyboardInterrupt:
            print("\n> Interupped by User. Exiting...")
            break

if __name__ =="__main__":
    t_listener = threading.Thread(target=lcm_listener, daemon=True)
    t_listener.start()
    main()

