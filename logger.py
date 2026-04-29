"""Logs Events of differnet Modules"""

import threading, time, datetime, lcm, os
from exlcm.log_t import log_t
from exlcm.log_schedule import log_schedule
from helper_functions import report_event, request_ntp, get_lc

lc = get_lc()
request_ntp()

LOG_LIST = []
LOG_LOCK = threading.Lock()

TARGET_HOUR = 0
TARGET_MIN = 0
TARGET_INTRVL = 24
OUT_DIR = "logs"

def event_listener():
    """Subscribes to LOGGER channel and stores events in memory."""
    global lc
    lc = get_lc()

    def on_log(channel, data):
        msg = log_t.decode(data)
        entry = f"{datetime.datetime.fromtimestamp(msg.timestamp/1000.0):%Y-%m-%d %H:%M:%S} [{msg.module}] {msg.level}: {msg.text}"
        print(entry)
        with LOG_LOCK:
            LOG_LIST.append(entry)
    
    def on_log_schedule(channel, data):
        msg = log_schedule.decode(data)
        global TARGET_HOUR,TARGET_MIN,TARGET_INTRVL
        TARGET_HOUR = msg.hour
        TARGET_MIN = msg.minute
        TARGET_INTRVL = msg.interval_hours
        report_event("Logger", "UPDATE", f"Schedule set to {msg.hour:02d}:{msg.minute:02d} and an {msg.interval_hours} hour interval", lc)

    lc.subscribe("LOGGER", on_log)
    lc.subscribe("LOGGER_CFG", on_log_schedule)

    report_event("Logger", "INFO", "listening on LOGGER")

    # Blocking receive loop
    while True:
        lc.handle()

def store_logs(target_hour=0, target_minute=0, out_dir="logs"):
    """Once per day at target time: write logs to file and clear buffer."""
    now = datetime.datetime.now()
    if not (now.hour == target_hour and now.minute == target_minute):
        return 0

    os.makedirs(out_dir, exist_ok=True)
    filename = os.path.join(out_dir,f"logs_{now:%Y%m%d%H%M}.log")
    
    with LOG_LOCK:
        if not LOG_LIST:
            return 0
        snapshot = LOG_LIST[:]
        LOG_LIST.clear()

    with open(filename, "a", encoding="utf-8") as f:
        for log in snapshot:
            f.write(log + "\n")

def scheduler():
    """Sleep till next run"""
    last_logged_time = None
    while True:
        now = datetime.datetime.now()
        if(now.hour == TARGET_HOUR and now.minute == TARGET_MIN and (last_logged_time != now)):
            report_event("Logger", "INFO", "Writting log file", lc)
            store_logs(TARGET_HOUR, TARGET_MIN, OUT_DIR)
            last_logged_time = now
        # TODO: add interval
        time.sleep(60)

if __name__ == "__main__":
    t_listener = threading.Thread(target=event_listener, daemon=True)
    t_sched    = threading.Thread(target=scheduler, daemon=True)

    t_listener.start()
    t_sched.start()

    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        print("\n[logger] shutting down")