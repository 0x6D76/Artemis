"""
File: 
Description:
Author: 0x6D76
Copyright (c) 2025 0x6d76@proton.me
"""
import logging
import json
import os
import re
import sys
from datetime import datetime, timezone, timedelta
from agent.shared.utils import LoadConfig
from agent.shared.data_formatter import LoadMapping, StandardizeEvent

LIN_AGENT_CONFIG = 'artemis_agent_lin.ini'
LIN_STD_CONFIG = 'standardization_map_lin.json'
# Using regex to find the start of an auditd message to extract timestamp and serial
# Example: type=SYSCALL msg=audit(1678886400.000:123):
# This regex looks for 'type=', then word characters (\w+), spaces (\s+), 'msg=audit(',
# then captures the timestamp (\d+\.\d+), ':', captures the serial (\d+), then '):'
AUDIT_MSG_PATTERN = re.compile(r'^type=\w+\s+msg=audit\((\d+\.\d+):(\d+)\):')
# Regex to parse key=value pairs, handling quoted strings.
# This regex looks for word characters for the key, followed by '=', then either
# a double-quoted string (allowing spaces inside) or non-space characters (\S+).
# It also handles the 'msg=audit(...)` part at the start of the line.
AUDIT_FIELD_PATTERN = re.compile(r'(\w+)=("[^"]*"|\S+)')
# List of field names known to commonly contain hex-encoded values
HEX_ENCODED_FIELDS = ['proctitle', 'comm', 'exe', 'name']
# Regex to check if a string consists only of hex characters (for decoding heuristics)
HEX_ONLY_PATTERN = re.compile(r'^[0-9a-fA-F]+$')


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

    for line in raw_lines:
        line = line.strip ()
        # Skipping empty lines
        if not line:
            continue
        match = AUDIT_MSG_PATTERN.match (line)

        if match:
            # Start of a new potential event
            timestamp_str = match.group (1)
            serial_number = match.group (2)
            # Checking if this is a new event (different serial or different timestamp)
            if current_event_serial is not None and (
                    serial_number != current_event_serial or timestamp_str != current_event_timestamp):
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


def ParseAuditdEvent (event_lines):
    """
    Parses a list of log lines belonging to a single event into a dictionary,
    using original auditd field names as keys.
    """

    if not event_lines:
        return None
    parsed_data = {
        "os" : "linux",
        "event_source" : "auditd",
        "original_raw_lines" : event_lines, # For debugging
        "_line_types" : [] # To store the type of events present in this event
    }
    serial_number = None
    timestamp_str = None
    event_utc_time = None
    first_line = event_lines[0]
    msg_match = AUDIT_MSG_PATTERN.search (first_line)

    if msg_match:
        timestamp_str = msg_match.group (1)
        serial_number = msg_match.group (2)
        parsed_data ["serial_number"] = serial_number
        parsed_data ["timestamp"] = timestamp_str

        # --- Converting auditd timestamp (seconds.milliseconds) to ISO 8601 UTC ---
        try:
            seconds, microseconds = timestamp_str.split ('.')
            # Convert microseconds part to ensure correct precision, pad and trim to 6 digits, if needed
            microseconds = microseconds.ljust(6, '0')[:6]
            # For simplicity, treating this as a local timestamp and then convert to UTC if possible
            # Use datetime.fromtimestamp with the float value
            dt_obj_local = datetime.fromtimestamp (float (f"{seconds}.{microseconds}"))

            # Convert naive local datetime to UTC
            # Requires system's timezone to be correctly set where agent runs
            try:
                import time
                utc_offset_sec = time.timezone if (time.localtime().tm_isdst == 0) else time.altzone
                utc_offset = timezone (-timedelta (seconds=utc_offset_sec))
                dt_obj_aware_local = dt_obj_local.replace (tzinfo=utc_offset)
                event_utc_time = dt_obj_aware_local.astimezone (timezone.utc).isoformat ()

            except Exception as e:
                logging.warning(f"Could not convert auditd timestamp to UTC: {e}")
                # Fallback to local ISO format
                event_utc_time = dt_obj_local.isoformat ()

        # In the event of exception, log it and keep original timestamp string
        except ValueError as e:
            logging.warning (f"Could not parse auditd timestamp '{timestamp_str}' : {e}")
            event_utc_time = timestamp_str
        except Exception as e:
            logging.warning (f"An unexpected error occurred while processing auditd timestamp '{timestamp_str}' : {e}")
            event_utc_time = timestamp_str

    parsed_data ["event_utc_time"] = event_utc_time
    # Process each line in event buffer
    for line in event_lines:
        line = line.strip()
        if not line:
            continue

        # Regex pattern to extract line type (e.g., SYSCALL, CWD, PATH)
        line_type_match = re.match(r'^type=(\w+)', line)
        line_type = 'UNKNOWN'  # Default line_type
        if line_type_match:
            line_type = line_type_match.group(1)
            if line_type not in parsed_data["_line_types"]:
                parsed_data["_line_types"].append(line_type)

        # Find the start of the key=value pairs after the msg=audit(...) part
        data_start_match = AUDIT_MSG_PATTERN.search(line)
        # Add 1 to end() to skip the colon ':' after the serial number
        data_start_index = data_start_match.end() + 1 if data_start_match else 0
        data_string = line[data_start_index:].strip()
        # Find all key=value pairs in data string using finditer for easier processing
        field_matches_iter = AUDIT_FIELD_PATTERN.finditer(data_string)

        # Add fields to the parsed_data dictionary, using a simple for loop
        # Takes care of duplication, where the existing field is replaced with the latest one, if the key match
        for match in field_matches_iter:
            field_name = match.group(1)
            field_value = match.group(2)

            # Clean up quotes from field_value
            if field_value.startswith('"') and field_value.endswith('"'):
                field_value = field_value[1:-1]

            # --- Hex Decoding ---
            if field_name in HEX_ENCODED_FIELDS and len(field_value) > 0 \
                    and len(field_value) % 2 == 0 and HEX_ONLY_PATTERN.fullmatch(field_value):
                try:
                    hex_data = bytes.fromhex(field_value)
                    field_value = hex_data.decode('utf-8', errors='replace')
                    logging.debug(f"Decoded hex field '{field_name}' : '{field_value}'")
                except ValueError as e:
                    logging.warning(
                        f"Couldn't decode hex value for '{field_name}' : '{e}'. "
                        f"Invalid hex format. Keeping the original value '{field_value}'."
                    )
                except Exception as e:
                    logging.warning(
                        f"An error occurred decoding hex value for the field '{field_name}'. Error: '{e}'. "
                        f"Keeping the original value '{field_value}'."
                    )
            # Add the field using the original auditd field name as the key
            parsed_data[field_name] = field_value

    # --- Determine event type based on parsed data ---
    event_type = "OtherEvent"  # Default
    syscall_num = parsed_data.get("syscall")
    rule_key = parsed_data.get("key")
    line_types = parsed_data.get("_line_types", [])

    # Process Creation Detection
    # Check for common execve/execveat syscall numbers
    # Common execve: 59 (x86_64), 221 (i386)
    # Common execveat: 322 (x86_64)
    # Check for 'execve' in comm or exe, or presence of PROCTITLE
    if "SYSCALL" in line_types and syscall_num in ["59", "221", "322"]:
        if "PROCTITLE" in line_types or parsed_data.get("comm") == "auditctl" or parsed_data.get(
                "exe") == "/usr/sbin/auditctl":  # Heuristic for exec
            event_type = "ProcessEvent"
    elif rule_key and ("exec" in rule_key or "process_create" in rule_key):  # If you use specific audit rules
        event_type = "ProcessEvent"

    # File Event Detection
    # Common file-related syscalls: open (2), read (0), write (1), close (3), chmod (90), chown (92)
    if "SYSCALL" in line_types and syscall_num in ["0", "1", "2", "3", "90", "92", "257","262"]:
        if "PATH" in line_types:
            event_type = "FileEvent"
    elif rule_key and ("file_access" in rule_key or "file_mod" in rule_key):
        event_type = "FileEvent"

    # Network Event Detection
    # Common network-related syscalls: socket (41), connect (42), accept (43), bind (49), listen (50)
    if "SYSCALL" in line_types and syscall_num in ["41", "42", "43", "49", "50"]:
        if "SOCKADDR" in line_types:
            event_type = "NetworkEvent"
    elif rule_key and ("net_conn" in rule_key or "socket_op" in rule_key):
        event_type = "NetworkEvent"

    parsed_data["event_type"] = event_type

    return parsed_data


if __name__ == '__main__':
    current_dir = os.path.dirname(os.path.abspath (__file__))
    config_file = os.path.join (current_dir, LIN_AGENT_CONFIG)
    app_config = LoadConfig (config_file)

    if app_config:
        SetupLogging (app_config)
        logging.info ("Artemis Linux agent is up and running.")
        agent_identity = app_config.get ('linux_agent', 'agent_id', fallback = "linux-agent-unknown")

        raw_lines = ReadAuditLog (app_config)

        if raw_lines:
            grouped_raw_events = GroupAuditdLines (raw_lines)
            # Verifying grouping by logging a few samples
            logging.debug ("Sample of grouped raw events:")
            for i, event_lines in enumerate(grouped_raw_events [:5]):
                logging.debug (f"Raw Event: {i+1} - ({len (event_lines)}) lines")
                for line in event_lines:
                    logging.debug (line)
                logging.debug ("----------")

            #--- Parsing grouped events ---
            if grouped_raw_events:
                parsed_auditd_events = []
                for raw_event in grouped_raw_events:
                    parsed_event = ParseAuditdEvent (raw_event)
                    if parsed_event:
                        parsed_auditd_events.append (parsed_event)

                logging.info (f"Finished parsing {len(parsed_auditd_events)} auditd events.")

                # Log samples to verify parsing
                logging.debug ("Sample of parsed auditd events:")
                for i, parsed_event in enumerate (parsed_auditd_events [:3]):  # Log first 3 parsed events
                    logging.debug(f"--- Parsed Event {i + 1} ---")
                    logging.debug(json.dumps(parsed_event, indent=4))
                    logging.debug("--------------------")

                #--- Standardization ---
                mapping_file = os.path.join (current_dir, LIN_STD_CONFIG)
                standardized_mapping = LoadMapping (mapping_file)
                standardized_events = []
                if standardized_mapping and parsed_auditd_events:
                    for parsed_event in parsed_auditd_events:
                        standard_event = StandardizeEvent (parsed_event, agent_identity, standardized_mapping)
                        if standard_event:
                            standardized_events.append (standard_event)
                logging.info (f"Finished standardization of {len(standardized_events)} auditd events.")
                # Log samples to verify standardization
                logging.debug ("Sample of standardized auditd events:")
                for i, event in enumerate (standardized_events[:5]):  # Log first few standardized events
                    logging.debug (f"--- Standardized Event {i + 1} ---")
                    logging.debug (json.dumps(event, indent=4))  # Use json.dumps for readable output
                    logging.debug ("--------------------")

        logging.info("Artemis Linux agent is done executing.")
