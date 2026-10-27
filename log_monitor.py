"""
log_monitor.py - Live log file monitoring for the Suspicious IP Checker.

Watches a server log file (Apache/Nginx/CSV format) in real-time using
polling (compatible with Windows). Tracks new entries, aggregates IP
activity, and feeds suspicious IPs into the alert engine.
"""

import os
import re
import time
import threading
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, List, Optional

import pandas as pd


@dataclass
class LogEntry:
    """Normalized log entry."""
    timestamp: str
    ip: str
    path: str
    status: int
    method: str = "GET"
    user_agent: str = ""
    raw_line: str = ""


@dataclass
class IPActivity:
    """Tracks activity for a single IP within monitoring window."""
    ip: str
    request_count: int = 0
    failed_count: int = 0
    paths_accessed: List[str] = field(default_factory=list)
    first_seen: str = ""
    last_seen: str = ""
    is_flagged: bool = False
    flag_reason: str = ""


# Regex patterns for common log formats
APACHE_NGINX_PATTERN = re.compile(
    r'(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+-\s+\S+\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>\w+)\s+(?P<path>\S+)\s+\S+"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)'
)

CSV_REQUIRED_COLS = {"timestamp", "ip", "path", "status"}


class LogMonitor:
    """Monitors a log file for new entries and detects suspicious activity."""

    def __init__(
        self,
        log_path: str,
        check_interval: int = 5,
        request_threshold: int = 5,
        failure_threshold: int = 3,
    ):
        self.log_path = Path(log_path)
        self.check_interval = check_interval
        self.request_threshold = request_threshold
        self.failure_threshold = failure_threshold
        self._file_size = 0
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._entries: List[LogEntry] = []
        self._ip_activity: Dict[str, IPActivity] = {}
        self._callbacks: List[Callable] = []
        self._error: Optional[str] = None

    @property
    def entries(self) -> List[LogEntry]:
        with self._lock:
            return self._entries.copy()

    @property
    def ip_activity(self) -> Dict[str, IPActivity]:
        with self._lock:
            return self._ip_activity.copy()

    @property
    def error(self) -> Optional[str]:
        return self._error

    def on_alert(self, callback: Callable):
        """Register a callback for when a suspicious IP is detected."""
        self._callbacks.append(callback)

    def start(self, load_existing: bool = True):
        """Start monitoring the log file in a background thread.
        If load_existing=True, processes all current file content first.
        """
        if not self.log_path.exists():
            self._error = f"Log file not found: {self.log_path}"
            return False
        self._running = True
        if load_existing:
            # Process all existing lines in the file
            self._file_size = 0
            self._read_new_entries()
        else:
            # Skip existing content, only watch for new appends
            self._file_size = self.log_path.stat().st_size
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()
        return True

    def stop(self):
        """Stop the monitoring thread."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=10)

    @property
    def is_running(self) -> bool:
        return self._running and self._thread is not None and self._thread.is_alive()

    def _monitor_loop(self):
        """Main monitoring loop - polls file for new entries."""
        while self._running:
            try:
                self._read_new_entries()
            except Exception as e:
                self._error = str(e)
            time.sleep(self.check_interval)

    def _read_new_entries(self):
        """Read only new lines appended since last check."""
        if not self.log_path.exists():
            return
        current_size = self.log_path.stat().st_size
        if current_size <= self._file_size:
            # File was truncated/rotated
            if current_size < self._file_size:
                self._file_size = 0
            else:
                return

        with open(self.log_path, "r", encoding="utf-8", errors="ignore") as f:
            f.seek(self._file_size)
            new_lines = f.readlines()
            self._file_size = f.tell()

        for line in new_lines:
            line = line.strip()
            if not line:
                continue
            entry = self._parse_line(line)
            if entry:
                self._process_entry(entry)

    def _parse_line(self, line: str) -> Optional[LogEntry]:
        """Parse a single log line - supports Apache/Nginx combined and CSV."""
        # Try Apache/Nginx combined format
        match = APACHE_NGINX_PATTERN.match(line)
        if match:
            return LogEntry(
                timestamp=match.group("timestamp"),
                ip=match.group("ip"),
                path=match.group("path"),
                status=int(match.group("status")),
                method=match.group("method"),
                raw_line=line,
            )
        # Try CSV format: timestamp,ip,path,status
        parts = line.split(",")
        if len(parts) >= 4:
            try:
                ip = parts[1].strip()
                if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', ip):
                    return LogEntry(
                        timestamp=parts[0].strip(),
                        ip=ip,
                        path=parts[2].strip(),
                        status=int(parts[3].strip()),
                        raw_line=line,
                    )
            except (ValueError, IndexError):
                pass
        return None

    def _process_entry(self, entry: LogEntry):
        """Process a parsed log entry and check thresholds."""
        newly_flagged = False
        with self._lock:
            self._entries.append(entry)
            if entry.ip not in self._ip_activity:
                self._ip_activity[entry.ip] = IPActivity(
                    ip=entry.ip,
                    first_seen=entry.timestamp,
                )
            act = self._ip_activity[entry.ip]
            act.request_count += 1
            act.last_seen = entry.timestamp
            if entry.path not in act.paths_accessed:
                act.paths_accessed.append(entry.path)
            if entry.status >= 400:
                act.failed_count += 1

            # Check if should flag
            if not act.is_flagged:
                reasons = []
                if act.request_count >= self.request_threshold:
                    reasons.append(f"High requests: {act.request_count}")
                if act.failed_count >= self.failure_threshold:
                    reasons.append(f"Auth failures: {act.failed_count}")
                if reasons:
                    act.is_flagged = True
                    act.flag_reason = "; ".join(reasons)
                    newly_flagged = True

        # Fire callbacks outside lock
        if newly_flagged:
            for cb in self._callbacks:
                try:
                    cb(self._ip_activity[entry.ip])
                except Exception:
                    pass

    def get_summary_df(self) -> pd.DataFrame:
        """Return current IP activity as DataFrame for dashboard display."""
        with self._lock:
            data = []
            for act in self._ip_activity.values():
                data.append({
                    "IP": act.ip,
                    "Requests": act.request_count,
                    "Failures": act.failed_count,
                    "Flagged": "YES" if act.is_flagged else "No",
                    "Flag Reason": act.flag_reason,
                    "First Seen": act.first_seen,
                    "Last Seen": act.last_seen,
                    "Paths": ", ".join(act.paths_accessed[:5]),
                })
        if not data:
            return pd.DataFrame(columns=["IP", "Requests", "Failures", "Flagged", "Flag Reason", "First Seen", "Last Seen", "Paths"])
        return pd.DataFrame(data).sort_values("Requests", ascending=False)

    def get_recent_entries_df(self, limit: int = 50) -> pd.DataFrame:
        """Return recent log entries as DataFrame."""
        with self._lock:
            entries = self._entries[-limit:]
        if not entries:
            return pd.DataFrame(columns=["Timestamp", "IP", "Path", "Status"])
        return pd.DataFrame([
            {"Timestamp": e.timestamp, "IP": e.ip, "Path": e.path, "Status": e.status}
            for e in reversed(entries)
        ])


def load_csv_log(csv_path: str) -> List[LogEntry]:
    """Load an entire CSV log file into LogEntry objects (for batch analysis)."""
    entries = []
    try:
        df = pd.read_csv(csv_path)
        if not CSV_REQUIRED_COLS.issubset(df.columns):
            return entries
        for _, row in df.iterrows():
            try:
                entries.append(LogEntry(
                    timestamp=str(row["timestamp"]),
                    ip=str(row["ip"]),
                    path=str(row["path"]),
                    status=int(row["status"]),
                ))
            except (ValueError, TypeError):
                continue
    except Exception:
        pass
    return entries
