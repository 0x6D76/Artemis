"""
File: 
Description:
Author: 0x6D76
Copyright (c) 2025 0x6d76@proton.me
"""
import logging
import os
import re
import sys
from agent.shared.utils import LoadConfig

LIN_AGENT_CONFIG = 'artemis_agent_lin.ini'


def SetupLogging (config):
    """Configures logging for Linux agent, based on configuration."""
    log_file = config.get ('logging', 'log_file')
    log_level_str = config.get ('logging', 'log_level', fallback = 'INFO').upper ()
    max_bytes = config.getint ('logging', 'max_bytes', fallback = 1024 * 1024) # 1 MB
    backup_count = config.getint ('logging', 'backup_count', fallback = 5)

    level = getattr (logging, log_level_str, logging.INFO)

    handlers = []

    if log_file:
        try:
            log_dir = os.path.dirname (log_file)
            if log_dir and not os.path.exists (log_dir):
                os.makedirs (log_dir, exist_ok = True)
            from logging.handlers import RotatingFileHandler
            file_handler = RotatingFileHandler (log_file, maxBytes = max_bytes, backupCount = backup_count)
            handlers.append (file_handler)
        except Exception as e:
            print (f"Error setting up logging: {e} Falling back to console logging.")
            console_handler = logging.StreamHandler(sys.stdout)
            handlers.append(console_handler)

        logging.basicConfig (
            level = level,
            format = '%(asctime)s - %(levelname)s - %(message)s',
            handlers = handlers
        )

    return logging


def ReadAuditLog (config):
    """Reads raw lines from auditd log file."""
    audit_log_path = config.get ('linux_agent', 'audit_log_path', fallback = '/var/log/audit/audit.log')
    raw_lines = []

    try:
        # Currently reads the whole file. To implement: reading from the end
        with open (audit_log_path, 'r', encoding = 'utf-8', errors = 'ignore') as audit_log:
            raw_lines = audit_log.readlines()
        logging.info (f"Read {len (raw_lines)} raw lines from {audit_log_path} ")
        return raw_lines
    except FileNotFoundError:
        logging.error ("Auditd log file not found")
        return []
    except PermissionError:
        logging.error ("Auditd log file permission error")
        return []
    except Exception as e:
        logging.error (f"An error occurred reading auditd log file: {e}", exc_info = True)
        return []


def GroupAuditdLines (raw_lines):
    """Groups raw auditd log lines into complete events."""
    grouped_events = []
    current_event_lines = []
    current_event_serial = None
    current_event_timestamp = None

    # Using regex to find the start of an auditd message to extract timestamp and serial
    # Example: type=SYSCALL msg=audit(1678886400.000:123):
    # This regex looks for 'type=', then word characters (\w+), spaces (\s+), 'msg=audit(',
    # then captures the timestamp (\d+\.\d+), ':', captures the serial (\d+), then '):'
    audit_msg_pattern = re.compile(r'^type=\w+\s+msg=audit\((\d+\.\d+):(\d+)\):')

    for line in raw_lines:
        line = line.strip ()
        # Skipping empty lines
        if not line:
            continue
        match = audit_msg_pattern.match (line)

        if match:
            # Start of a new potential event
            timestamp_str = match.group (1)
            serial_number = match.group (2)
            # Checking if this is a new event (different serial or different timestamp)
            if current_event_serial is not None and (serial_number != current_event_serial or timestamp_str != current_event_timestamp):
                if current_event_lines:
                    grouped_events.append (current_event_lines)
                # Start a new event buffer with current line
                current_event_lines = [line]
                current_event_serial = serial_number
                current_event_timestamp = timestamp_str
            else:
                # Either the very first line or continuation of current event
                current_event_lines.append (line)
                # Update serial/timestamp if the first line didn't have it (rare cases)
                if current_event_serial is None:
                    current_event_serial = serial_number
                    current_event_timestamp = timestamp_str
        else:
            # This line doesn't match the start pattern, it's likely a continuation of the previous line due to
            # wrapping, or an unexpected format.
            # For basic grouping, we'll append it to the current buffer.
            # More robust parsing might need to handle line wrapping explicitly based on field structure.
            if current_event_lines:
                current_event_lines.append (line)
            else:
                logging.warning (f"Skipping line: {line}")
    # End of for loop, adding last event to the buffer
    if current_event_lines:
        grouped_events.append (current_event_lines)

    logging.info (f"Grouped raw into {len (grouped_events)} events.")
    return grouped_events


if __name__ == '__main__':
    current_dir = os.path.dirname(os.path.abspath(__file__))
    config_file = os.path.join(current_dir, LIN_AGENT_CONFIG)
    app_config = LoadConfig(config_file)

    if app_config:
        SetupLogging (app_config)
        logging.info ("Artemis Linux agent is up and running.")
        agent_identity = app_config.get('linux_agent', 'agent_id', fallback="linux-agent-unknown")

        raw_lines = ReadAuditLog (app_config)

        if raw_lines:
            grouped_raw_events = GroupAuditdLines (raw_lines)
            # Verifying grouping by logging a few samples
            logging.info ("Sample of grouped raw events:")
            for i, event_lines in enumerate(grouped_raw_events [:5]):
                logging.info (f"Raw Event: {i+1} - ({len (event_lines)}) lines")
                for line in event_lines:
                    logging.info (line)
                logging.info ("----------")

        logging.info("Artemis Linux agent is done executing.")
