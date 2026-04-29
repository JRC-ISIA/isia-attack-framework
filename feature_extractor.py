"""Extracts defined featureset from pcap, enriches with information engine data"""

import os, pandas as pd
import shutil
from helper_functions import report_event, request_ntp, get_lc, publish_task_status
from exlcm.extract_cmd_t import extract_cmd_t
from scapy.all import PcapReader, IP, IPv6, TCP, UDP, ICMP
from collections import defaultdict
from dataclasses import dataclass
from typing import Optional
from influxdb_client import InfluxDBClient
from datetime import datetime, timezone

@dataclass
class net_features:
    # basic features
    under_attack: bool
    ts:float
    src_ip:str
    dest_ip:str
    protocol:str
    service: str
    duration: float
    scr_bytes: int
    des_bytes: int
    # missed_byte: int  # not available from pcap parsing
    scr_pkts: int
    des_pkts: int
    scr_ip_bytes: int
    des_ip_bytes: int
    # genrated features
    conn_state: int
    total_bytes: int
    byte_rate: float
    total_pkts: int
    pkts_rate: float
    orig_bytes_ratio: float
    resp_bytes_ratio: float
    orig_pkts_ratio: float
    resp_pkts_ratio: float
    syn: int
    syn_ack: int
    pure_ack: int
    packet_with_payload: int
    fin_or_rst: int
    bad_checksum: int
    syn_with_rst: int
    src_port:Optional[int] = None
    dest_port:Optional[int] = None

@dataclass
class host_features:
    # generated resource features
    avg_user_time: Optional[float] = None
    std_user_time: Optional[float] = None
    avg_nice_time: Optional[float] = None
    std_nice_time: Optional[float] = None
    avg_system_time: Optional[float] = None
    std_system_time: Optional[float] = None
    avg_io_wait_time: Optional[float] = None
    std_io_wait_time: Optional[float] = None
    avg_idle_time: Optional[float] = None
    std_idle_time: Optional[float] = None
    avg_tps: Optional[float] = None
    std_tps: Optional[float] = None
    avg_rtps: Optional[float] = None
    std_rtps: Optional[float] = None
    avg_wtps: Optional[float] = None
    std_wtps: Optional[float] = None
    avg_ldavg_1: Optional[float] = None
    std_ldavg_1: Optional[float] = None
    avg_kbmemused: Optional[float] = None
    std_kbmemused: Optional[float] = None
    avg_num_procs: Optional[float] = None
    std_num_procs: Optional[float] = None
    avg_num_swch_s: Optional[float] = None
    std_num_swch_s: Optional[float] = None
    # generated log features
    anomaly_alert: Optional[int] = None
    ossec_alert: Optional[int] = None
    alert_level: Optional[int] = None
    r_w_physical: Optional[int] = None
    file_act: Optional[int] = None
    proc_act: Optional[int] = None
    is_privileged: Optional[int] = None
    login_attmp: Optional[int] = None
    succ_login: Optional[int] = None

PCAP_PATH = None
JSON_PATH = None

ATTACK_WINDOWS = []

ATTACK_START_TIME = None
ATTACK_STOP_TIME = None

def label_dataset(first_ts: float, last_ts: float) -> bool:
    """labels dataset based on logs 'attack start' and 'attack stop' entries and adds label column to dataset"""
#     # TODO: improve to label multiple attacks in one dataset and/or label based on more fine grained log entries (e.g. for each attack step)
#     if ATTACK_START_TIME is None or ATTACK_STOP_TIME is None:
#         return False
#     elif first_ts <= ATTACK_START_TIME and last_ts >= ATTACK_STOP_TIME:
#         return True
#     elif (ATTACK_START_TIME <= first_ts <= ATTACK_STOP_TIME) or (ATTACK_START_TIME <= last_ts <= ATTACK_STOP_TIME):
#         return True
#     return False
    if not ATTACK_WINDOWS:
        return False
    for start, stop in ATTACK_WINDOWS:
        if first_ts <= start and last_ts >= stop:
            return True
        elif (start <= first_ts <= stop) or (start <= last_ts <= stop):
            return True
    return False

def check_bad_checksum(pkt):
    if IP in pkt:
        original_cksum = pkt[IP].chksum
        temp_pkt = pkt[IP].copy()
        del temp_pkt.chksum
        temp_pkt = IP(bytes(temp_pkt))
        return original_cksum != temp_pkt.chksum
    return False

def extract_features(pcap:str):
    """parses pcap and extracts features"""
    report_event("Feature Extractor", "INFO", f"Starting feature extraction for pcap: {pcap}", lc, dest_channel="COORDINATOR_LOG")
    flows = defaultdict(list)

    with PcapReader(pcap) as reader:
        report_event("Feature Extractor", "INFO", f"Reading pcap and grouping into flows: {pcap}", lc, dest_channel="COORDINATOR_LOG")
        for pkt in reader:
            if not (IP in pkt or IPv6 in pkt):
                continue

            proto = pkt.proto if IP in pkt else pkt.nh
            ip_layer = pkt[IP] if IP in pkt else pkt[IPv6]
            src_ip = ip_layer.src
            dest_ip = ip_layer.dst
            src_port = pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else None)
            dest_port = pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else None)
            flow_key = (src_ip, dest_ip, src_port, dest_port, proto)
            flows[flow_key].append(pkt)
        report_event("Feature Extractor", "INFO", f"Finished reading pcap and grouping into flows. Total flows: {len(flows)}", lc, dest_channel="COORDINATOR_LOG")    
    
    dataset = []
    for flow_key, packets in flows.items():

        def pkt_src(pkt):
            ip_layer = pkt[IP] if IP in pkt else pkt[IPv6]
            return ip_layer.src

        def pkt_ip_len(pkt):
            ip_layer = pkt[IP] if IP in pkt else pkt[IPv6]
            return len(ip_layer)

        first_ts = float(packets[0].time)
        last_ts = float(packets[-1].time)
        duration = last_ts - first_ts
        under_attack = label_dataset(first_ts, last_ts)
        features = net_features(
            under_attack=under_attack,
            ts=first_ts,
            src_ip=flow_key[0],
            dest_ip=flow_key[1],
            src_port=flow_key[2],
            dest_port=flow_key[3],
            protocol=str(flow_key[4]),
            service="",  # TODO: implement service detection based on port and/or payload
            duration=duration,
            scr_bytes=sum(len(pkt) for pkt in packets if pkt_src(pkt) == flow_key[0]),
            des_bytes=sum(len(pkt) for pkt in packets if pkt_src(pkt) == flow_key[1]),
            scr_pkts=sum(1 for pkt in packets if pkt_src(pkt) == flow_key[0]),
            des_pkts=sum(1 for pkt in packets if pkt_src(pkt) == flow_key[1]),
            scr_ip_bytes=sum(pkt_ip_len(pkt) for pkt in packets if pkt_src(pkt) == flow_key[0]),
            des_ip_bytes=sum(pkt_ip_len(pkt) for pkt in packets if pkt_src(pkt) == flow_key[1]),
            conn_state=0,  # TODO: implement connection state detection
            total_bytes=sum(len(pkt) for pkt in packets),
            byte_rate=sum(len(pkt) for pkt in packets) / (packets[-1].time - packets[0].time) if packets[-1].time > packets[0].time else 0,
            total_pkts=len(packets),
            pkts_rate=len(packets) / (packets[-1].time - packets[0].time) if packets[-1].time > packets[0].time else 0,
            orig_bytes_ratio=(sum(len(pkt) for pkt in packets if pkt_src(pkt) == flow_key[0]) / sum(len(pkt) for pkt in packets)) if sum(len(pkt) for pkt in packets) > 0 else 0,
            resp_bytes_ratio=(sum(len(pkt) for pkt in packets if pkt_src(pkt) == flow_key[1]) / sum(len(pkt) for pkt in packets)) if sum(len(pkt) for pkt in packets) > 0 else 0,
            orig_pkts_ratio=(sum(1 for pkt in packets if pkt_src(pkt) == flow_key[0]) / len(packets)) if len(packets) > 0 else 0,
            resp_pkts_ratio=(sum(1 for pkt in packets if pkt_src(pkt) == flow_key[1]) / len(packets)) if len(packets) > 0 else 0,
            syn=sum(1 for pkt in packets if TCP in pkt and pkt[TCP].flags & 0x02 != 0),
            syn_ack=sum(1 for pkt in packets if TCP in pkt and pkt[TCP].flags & 0x12 == 0x12),
            pure_ack=sum(1 for pkt in packets if TCP in pkt and pkt[TCP].flags & 0x10 != 0 and pkt[TCP].flags & 0x02 == 0 and pkt[TCP].flags & 0x04 == 0),
            packet_with_payload=sum(1 for pkt in packets if (TCP in pkt and len(pkt[TCP].payload) > 0) or (UDP in pkt and len(pkt[UDP].payload) > 0) or (ICMP in pkt and len(pkt[ICMP].payload) > 0)),
            fin_or_rst=sum(1 for pkt in packets if TCP in pkt and (pkt[TCP].flags & 0x01 != 0 or pkt[TCP].flags & 0x04 != 0)),
            bad_checksum=sum(1 for pkt in packets if IP in pkt and check_bad_checksum(pkt)),
            syn_with_rst=sum(1 for pkt in packets if TCP in pkt and pkt[TCP].flags & 0x02 != 0 and pkt[TCP].flags & 0x04 != 0)
        )
        dataset.append(features)
        
    return dataset

def request_information_engine_data(start_dt: datetime, stop_dt: datetime):
    """gathers addidtional information about testbed state from information engine"""
    url = "http://172.17.20.21:8086"
    token = "R8mt05L4YQDjEwyijC0fzU9lR29Yx94hWC4Tc8lLQ2icaZ3T0E9-0UGd1o5Wevnu58l3RtTkaCmPwLlRcpePBw=="
    org = "fh"
    bucket = "OPCUA_DATA"
    
    start_str = start_dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    stop_str = stop_dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    client = InfluxDBClient(url=url, token=token, org=org)
    read_api = client.query_api()
    query = f'from(bucket: "{bucket}") |> range(start: {start_str}, stop: {stop_str})'

    try:
        df = read_api.query_data_frame(org=org, query=query)
        if isinstance(df, list):
            df = pd.concat(df, ignore_index=True)

        if df.empty:
            print("No data returned from InfluxDB for the specified time range.")
            return host_features()
        
    except Exception as e:
        print(f"Error occurred while querying InfluxDB: {e}")
        return host_features()
    
    tmp_series = df[df['_field'].str.contains("Temperature", na=False)]['_value']

    # features = host_features(
    #     avg_user_time=df[df['_field'] == 'user_time']['_value'].mean(),
    #     std_user_time=df[df['_field'] == 'user_time']['_value'].std(),
    #     avg_nice_time=df[df['_field'] == 'nice_time']['_value'].mean(),
    #     std_nice_time=df[df['_field'] == 'nice_time']['_value'].std(),
    #     avg_system_time = float(tmp_series.mean()) if not tmp_series.empty else None,
    #     std_system_time = float(tmp_series.std()) if not tmp_series.empty else None,
    #     avg_io_wait_time=df[df['_field'] == 'io_wait_time']['_value'].mean(),
    #     std_io_wait_time=df[df['_field'] == 'io_wait_time']['_value'].std(),
    #     avg_idle_time=df[df['_field'] == 'idle_time']['_value'].mean(),
    #     std_idle_time=df[df['_field'] == 'idle_time']['_value'].std(),
    #     avg_tps=df[df['_field'] == 'tps']['_value'].mean(),
    #     std_tps=df[df['_field'] == 'tps']['_value'].std(),
    #     avg_rtps=df[df['_field'] == 'rtps']['_value'].mean(),
    #     std_rtps=df[df['_field'] == 'rtps']['_value'].std(),
    #     avg_wtps=df[df['_field'] == 'wtps']['_value'].mean(),
    #     std_wtps=df[df['_field'] == 'wtps']['_value'].std(),
    #     avg_ldavg_1=df[df['_field'] == 'ldavg_1']['_value'].mean(),
    #     std_ldavg_1=df[df['_field'] == 'ldavg_1']['_value'].std(),
    #     avg_kbmemused=df[df['_field'] == 'kbmemused']['_value'].mean(),
    #     std_kbmemused=df[df['_field'] == 'kbmemused']['_value'].std(),
    #     avg_num_procs=df[df['_field'] == 'num_procs']['_value'].mean(),
    #     std_num_procs=df[df['_field'] == 'num_procs']['_value'].std(),
    #     avg_num_swch_s=df[df['_field'] == 'num_swch_s']['_value'].mean(),
    #     std_num_swch_s=df[df['_field'] == 'num_swch_s']['_value'].std(),
    #     anomaly_alert = 1 if any(df[df['_field'] == "Control.imm.ctr.forceMachineStop"]['_value'] == True) else 0,
    #     is_privileged = 1 if any(df[df['_field'] == "Control.imm.ctr.mode"]['_value'] == 2) else 0,
    # )

    features = host_features(
        avg_system_time = float(tmp_series.mean()) if not tmp_series.empty else None,
        std_system_time = float(tmp_series.std()) if not tmp_series.empty else None,
        
        # Mapping boolean 'forceMachineStop' to anomaly_alert (1 if any stop was forced)
        anomaly_alert = 1 if any(df[df['_field'] == "Control.imm.ctr.forceMachineStop"]['_value'] == True) else 0,
        is_privileged = 1 if any(df[df['_field'] == "Control.imm.ctr.mode"]['_value'] == 2) else 0,
        avg_idle_time = None
    )

    client.close()
    return features

def set_attack_times(range_start:float | None = None, range_end:float | None = None):
    """sets global attack start and stop times based on log entries"""
    # global ATTACK_START_TIME, ATTACK_STOP_TIME
    # with open("logs/logger.out", "r") as f:
    #     for line in f:
    #         client_tag = "[Attack Client]"
    #         start_markers = ["INFO: running"]
    #         stop_markers = ["INFO: finished"]
    #         if client_tag in line:
    #             if any(marker in line for marker in start_markers):
    #                 date_str = line[:19]
    #                 dt = datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S")
    #                 ATTACK_START_TIME = dt.timestamp()
    #             elif any(marker in line for marker in stop_markers):
    #                 date_str = line[:19]
    #                 dt = datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S")
    #                 ATTACK_STOP_TIME = dt.timestamp()
    global ATTACK_WINDOWS
    ATTACK_WINDOWS = []

    curremt_start = None
    with open("logs/logger.out", "r") as f:
        for line in f:
            if "[Attack Client]" not in line:
                continue

            try:
                date_str = line[:19]
                dt = datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S")
                timestamp = dt.timestamp()
            except Exception as e:
                print(f"Error parsing date from log line: {line}. Error: {e}")
                continue
            if "INFO: running" in line:
                curremt_start = timestamp
            elif "INFO: finished" in line and curremt_start is not None:
                ATTACK_WINDOWS.append((curremt_start, timestamp))
                curremt_start = None
    
    if range_start is not None and range_end is not None:
        ATTACK_WINDOWS = [
            (start, stop)
            for start, stop in ATTACK_WINDOWS
            if (start <= range_end) or (stop >= range_start)
        ]

def create_dataset():
    """loads pcap from buffer, runs extraction and enrichment and creates dataset"""
    set_attack_times()

    net_data = extract_features(PCAP_PATH)
    
    start_time = datetime.fromtimestamp(net_data[0].ts, tz=timezone.utc)
    stop_time = datetime.fromtimestamp(net_data[-1].ts, tz=timezone.utc)

    report_event("Feature Extractor", "INFO", f"Extracted network features for {len(net_data)} flows. Time range: {start_time} to {stop_time}", lc, dest_channel="COORDINATOR_LOG")

    host_data = request_information_engine_data(start_time, stop_time)
    final_records = []
    for flow in net_data:
        combinded = {**flow.__dict__, **host_data.__dict__}
        final_records.append(combinded)
    df = pd.DataFrame(final_records)
    df.to_json(JSON_PATH, orient="records", indent=4)
    print("Dataset created and saved successfully.")
    report_event("Feature Extractor", "INFO", f"Dataset created and saved to {JSON_PATH}", lc, dest_channel="COORDINATOR_LOG")

    dest_path = PCAP_PATH.replace('pcap/', 'dataset/')
    os.rename(PCAP_PATH, dest_path)
    print(f"Pcap file moved to archive: {dest_path}")
    report_event("Feature Extractor", "INFO", f"Pcap file moved to archive: {dest_path}", lc, dest_channel="COORDINATOR_LOG")

    shutil.copy2("logs/logger.out", f"dataset/logger_{int(datetime.now().timestamp())}.out")
    report_event("Feature Extractor", "INFO", f"Log file archived: dataset/logger_{int(datetime.now().timestamp())}.out", lc, dest_channel="COORDINATOR_LOG")

def on_cmd(channel,data):

    if channel != "FEATURE_EXTR":
        return
    
    try:
        msg = extract_cmd_t.decode(data)

        if not hasattr(msg, "command") or msg.command == "":
            return
        
        if msg.command == "extract_features":
            report_event("Feature Extractor", "INFO", f"extract_features command received: {channel}", lc, dest_channel="COORDINATOR_LOG")
            if msg.file:
                global PCAP_PATH; PCAP_PATH = f"pcap/{msg.file}"
                report_event("Feature Extractor", "INFO", f"PCAP path set to: {PCAP_PATH}", lc, dest_channel="COORDINATOR_LOG")
            if PCAP_PATH:
                global JSON_PATH; JSON_PATH = PCAP_PATH.replace('pcap/', 'dataset/').replace('capture_Ethernet', 'dataset').replace('.pcap', '.json')
                os.makedirs("dataset", exist_ok=True)
                report_event("Feature Extractor", "INFO", f"JSON path set to: {JSON_PATH}", lc, dest_channel="COORDINATOR_LOG")
                publish_task_status("extract_features", "Feature Extraction", "running", lc=lc)
                create_dataset()
                publish_task_status("extract_features", "Feature Extraction", "finished", lc=lc)

    except Exception as e:
        report_event("Feature Extractor", "ERROR", f"Error processing command: {e}", lc, dest_channel="COORDINATOR_LOG")
        print(f"Error processing command: {e}")
        publish_task_status("extract_features", "Feature Extraction", "error", lc=lc)
        return

if __name__ == "__main__":
    # request_ntp()
    lc = get_lc()
    lc.subscribe("FEATURE_EXTR", on_cmd)
    while True:
        lc.handle()