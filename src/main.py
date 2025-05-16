"""
- MCP - Windows log (Pywin32 win32evtlog) 針對 Sysmon
    - `tool`: ingest_syslog
    - `tool`: query_syslog
    - `prompt` : 指導模型如何使用工具

example:
```
import win32evtlog

server = 'localhost'  # 或指定遠端主機名稱
log_type = 'Microsoft-Windows-Sysmon/Operational'  # Sysmon 日誌的通道名稱

# 開啟事件日誌
handle = win32evtlog.OpenEventLog(server, log_type)

# 設定讀取標誌
flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

# 讀取事件
events = True
while events:
    events = win32evtlog.ReadEventLog(handle, flags, 0)
    for event in events:
        # list all attributes
        for attr in dir(event):
            if not attr.startswith('__'):
                print(f'{attr}: {getattr(event, attr)}')
        print('-' * 50)

# 關閉事件日誌
win32evtlog.CloseEventLog(handle)
```
"""
from mcp.server.fastmcp import FastMCP
import win32evtlog
import datetime
import os
import traceback
import logging
import argparse


parser = argparse.ArgumentParser()
parser.add_argument('--storage-path', type=str, default="C:\\logs\\", help='Log storage path')
args, unknown = parser.parse_known_args()

class Settings:
    STORAGE_PATH = args.storage_path
    LOG_TYPE = "Microsoft-Windows-Sysmon/Operational"
    SERVER = "localhost"
    SIZE = 10


mcp = FastMCP(
    describe="Pywin32 win32evtlog for Retrieval Windows Logs"
)

@mcp.tool()
def ingest_syslog(
    storage_path: str = Settings.STORAGE_PATH,
    log_type: str = Settings.LOG_TYPE,
    server: str = Settings.SERVER,
    size: int = Settings.SIZE
):
    """
    Ingest Windows Sysmon logs

    Args:
        storage_path (str): log storage path
        log_type (str, optional): log type. Defaults to "Microsoft-Windows-Sysmon/Operational".
        server (str, optional): server. Defaults to "localhost".
        size (int, optional): number of log lines to return

    Returns:
        str: log content
    """
    try:
        os.makedirs(storage_path, exist_ok=True)
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        safe_log_type = log_type.replace("/", "_").replace("\\", "_")
        dest_file = os.path.join(storage_path, f"{timestamp}_{safe_log_type}.log")

        handle = win32evtlog.OpenEventLog(server, log_type)
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        written = 0

        with open(dest_file, "a", encoding="utf-8") as f:
            events = True
            while events and written < size:
                events = win32evtlog.ReadEventLog(handle, flags, 0)
                if not events:
                    break
                for event in events:
                    details = {attr: getattr(event, attr) for attr in dir(event) if not attr.startswith("__")}
                    timewritten = details.get("TimeWritten")
                    if hasattr(timewritten, "isoformat"):
                        details["TimeWritten"] = timewritten.isoformat()
                    f.write(str(details) + "\n")
                    written += 1
                    if written >= size:
                        break

        win32evtlog.CloseEventLog(handle)
        return dest_file
    except Exception as e:
        return f"ERROR: {e}\n{traceback.format_exc()}"


@mcp.tool()
def query_syslog(
    timestamp: str,
    log_path: str = Settings.STORAGE_PATH,
    log_type: str = Settings.LOG_TYPE,
    server: str = Settings.SERVER,
    size: int = Settings.SIZE
):
    """
    Query Windows Sysmon logs

    Args:
        timestamp (str): the timestamp (YYYY-MM-DD_HH-MM-SS) to filter log files
        log_path (str): log path
        log_type (str, optional): log type. Defaults to "Microsoft-Windows-Sysmon/Operational".
        server (str, optional): server. Defaults to "localhost".
        size (int, optional): number of log lines to return

    Returns:
        str: log content
    """
    files = os.listdir(log_path)
    matched_files = [
        f for f in files
        if f.endswith(".log") and timestamp in f
    ]
    if not matched_files:
        return "No log files found matching the timestamp"

    logs = []
    for file in matched_files:
        with open(os.path.join(log_path, file), "r", encoding="utf-8") as f:
            events = f.readlines()
            logs.extend(events)

    if not logs:
        return "No events found in matching log files"

    return "\n".join(logs[-size:])


@mcp.prompt()
def prompt_guide():
    return f"""
    You are a Windows log analyst.

    Your task is to analyze the Windows log and provide a summary of the events.
    The log is stored in the following path:
    ```
    {Settings.STORAGE_PATH}
    ```
    
    You can use the following tools:
    - ingest_syslog: Ingest Windows log
        - Args:
            - storage_path (str): log storage path
            - log_type (str, optional): log type. Defaults to "Microsoft-Windows-Sysmon/Operational".
            - server (str, optional): server. Defaults to "localhost".
            - size (int, optional): number of log lines to return
        - Returns:
            - str: log content
    - query_syslog: Query Windows log
        - Args:
            - timestamp (str): the timestamp (YYYY-MM-DD_HH-MM-SS) to filter log files
            - log_path (str): log path
            - log_type (str, optional): log type. Defaults to "Microsoft-Windows-Sysmon/Operational".
            - server (str, optional): server. Defaults to "localhost".
            - size (int, optional): number of log lines to return
        - Returns:
            - str: log content
    
    if you want to ingest the log, use the following prompt:
    ```
    ingest_syslog(
        storage_path="{Settings.STORAGE_PATH}",
        log_type="{Settings.LOG_TYPE}",
        server="{Settings.SERVER}",
        size={Settings.SIZE}
    )
    ```
    
    if you want to query the log, use the following prompt:
    ```
    query_syslog(
        timestamp="2025-05-15_14-47-24",
        log_path="{Settings.STORAGE_PATH}",
        log_type="{Settings.LOG_TYPE}",
        server="{Settings.SERVER}",
        size={Settings.SIZE}
    )
    ```
    """


if __name__ == "__main__":
    mcp.run()
