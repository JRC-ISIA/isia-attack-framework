from pathlib import Path
from helper_functions import report_event, request_ntp , get_lc, transfer_file,publish_task_status
from exlcm.store_cmd_t import store_cmd_t

HOSTNAME = "192.168.50.2"
USERNAME = "ssh_access"
PASSWORD = "isiapersistence"

LOCAL_PATH = "dataset/"
REMOTE_PATH = "/volume1/IE_Persistence/IT_Sec/attack-framework/"

def on_cmd(channel,data):

    if channel != "STORAGE_TRANS":
        return
    
    try:
        publish_task_status("storage_transfer", "Storage Transfer", "running", lc=lc)
        msg = store_cmd_t.decode(data)

        if not hasattr(msg, "command") or msg.command == "":
            return
        
        if msg.command == "transfer_file":
            report_event("Storage Transfer", "INFO", f"transfer_file command received: {channel}", lc, dest_channel="COORDINATOR_LOG")
            
            base_path = Path(LOCAL_PATH)
            if not base_path.exists():
                report_event("Storage Transfer", "ERROR", f"Local path {LOCAL_PATH} does not exist", lc, dest_channel="COORDINATOR_LOG")
                print(f"Local path {LOCAL_PATH} does not exist.")
                return
            
            files_found = list(base_path.iterdir())
            if not files_found:
                report_event("Storage Transfer", "ERROR", f"No files found in local path {LOCAL_PATH} for transfer", lc, dest_channel="COORDINATOR_LOG")
                print(f"No files found in local path {LOCAL_PATH} for transfer.")
                return
            
            all_done = True

            for item in files_found:
                success = transfer_file(hostname=HOSTNAME, username=USERNAME, password=PASSWORD, local_path=str(item), remote_path=REMOTE_PATH)
                if success:
                    report_event("Storage Transfer", "INFO", "file transfer completed", lc, dest_channel="COORDINATOR_LOG")
                    if item.is_file():
                        item.unlink()
                        print(f"Local file {item} deleted after transfer.")
                else:
                    all_done = False
                    report_event("Storage Transfer", "ERROR", f"file transfer failed: {item.name}", lc, dest_channel="COORDINATOR_LOG")

        if all_done:
            publish_task_status("storage_transfer", "Storage Transfer", "finished", lc=lc)
        else:
            publish_task_status("storage_transfer", "Storage Transfer", "error", lc=lc)
        
    except Exception as e:
        report_event("Storage Transfer", "ERROR", f"Error processing command: {e}", lc, dest_channel="COORDINATOR_LOG")
        publish_task_status("storage_transfer", "Storage Transfer", "error", lc=lc)
        return
    
if __name__ == "__main__":
    request_ntp()
    lc = get_lc()
    lc.subscribe("STORAGE_TRANS", on_cmd)
    while True:
        lc.handle()