"""
File:
Description:
Author: 0x6D76
Copyright (c) 2025 0x6d76@proton.me
"""
import json
from datetime import datetime, timezone

#--- Artemis Standard Schema ---#
# This section conceptually describes the expected structure.
# {
#     "agent_id": "string",
#     "event_timestamp": "string (ISO 8601 UTC)",
#     "hostname": "string",
#     "os": "string (windows or linux)",
#     "event_source": "string (sysmon, auditd, etc.)",
#     "original_event_id": "string",
#     "standard_event_type": "string",
#     "process": { ... }, # Nested process details
#     "network": { ... }, # Nested network details
#     "file": { ... },    # Nested file details
#     "registry": { ... }, # Nested registry details
#     "other_data": { ... } # Optional catch-all
# }

def CreateBaseStandardEvent (parsed_event, agent_id):
    """Creates base structure for a standardized event."""
    return {
        "agent_id": agent_id,
        "event_timestamp": None,  # Will be formatted in the next function
        "hostname": parsed_event.get("hostname"),
        "os": parsed_event.get("os"),
        "event_source": parsed_event.get("event_source"),  # Get source from parsed data (to be added)
        "original_event_id": parsed_event.get("event_id"),
        "standard_event_type": parsed_event.get("event_type"),
        "process": {},
        "network": {},
        "file": {},
        "registry": {},
        "other_data": {},
    }


def StandardizeWindowsEvent (parsed_event, agent_id):
    """Transforms parsed Windows event into standardized Artemis Schema."""
    if not parsed_event:
        return None

    # Create base standardized base event structure
    standard_event = CreateBaseStandardEvent (parsed_event, agent_id)
    # Formatting timestamp
    timestamp_str = parsed_event.get("timestamp")
    if timestamp_str:
        try:
            # Use the provided timestamp string if it's already ISO 8601 UTC
            standard_event["event_timestamp"] = timestamp_str
            # If parsing/reformatting is needed, implement it here
            dt_obj = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            standard_event["event_timestamp"] = dt_obj.isoformat(timespec='microseconds')

        except ValueError as e:
            # Log warnings within the shared module as well
            # Ensure logging is configured before calling this module in the agent
            try:
                import logging
                logging.warning(f"DataFormatter: Could not parse timestamp string '{timestamp_str}': {e}")
            except ImportError:
                print(f"DataFormatter: Logging not configured, cannot log warning: {e}")
            standard_event["event_timestamp"] = timestamp_str
        except Exception as e:
            try:
                import logging
                logging.warning(f"DataFormatter: An unexpected error occurred formatting timestamp: {e}")
            except ImportError:
                print(f"DataFormatter: Logging not configured, cannot log warning: {e}")
            standard_event["event_timestamp"] = timestamp_str

    return standard_event