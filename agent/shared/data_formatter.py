"""
File: data_formatter.py
Description:
Author: 0x6D76
Copyright (c) 2025 0x6d76@proton.me
"""
import json
import logging
from datetime import datetime, timezone

# --- Artemis Standard Schema --- #
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


def LoadMapping (mapping_file):
    """Loads standardization mapping from JSON file."""
    try:
        with open (mapping_file, 'r') as json_file:
            mapping = json.load (json_file)
            logging.info (f"Loaded mapping from {mapping_file}")
            return mapping
    except FileNotFoundError:
        logging.error (f"Standardization file not found: {mapping_file}")
        return None
    except json.JSONDecodeError as e:
        logging.error (f"Error decoding mapping file {mapping_file}: {e}")
        return None
    except Exception as e:
        logging.error (f"An unexpected error occurred while loading: {e}")
        return None


def CreateBaseStandardEvent (parsed_event, agent_id):
    """Creates base structure for a standardized event."""
    os = parsed_event.get('os')
    source = "auditd"
    if os == "windows":
        source = "sysmon"
    return {
        "agent_id": agent_id,
        "event_timestamp": None,  # Will be formatted in StandardizeEvent
        "hostname": parsed_event.get ("hostname"),
        "os": os,
        "event_source": source, # parsed_event.get ("event_source"), Get source from parsed data (to be added)
        "original_event_id": parsed_event.get ("event_id"),
        "standard_event_type": parsed_event.get ("event_type"),
        # Initialize nested objects
        "process": {},
        "network": {},
        "file": {},
        "registry": {},
        "other_data": {},
    }


def StandardizeEvent (parsed_event, agent_id, mapping):
    """Transforms parsed event data into standardized Artemis Schema using the provided mapping."""
    if not parsed_event:
        return None

    # Create base standardized base event structure
    standard_event = CreateBaseStandardEvent (parsed_event, agent_id)
    original_event_id = parsed_event.get ("event_id")
    # Get mapping for the current event
    event_mapping = mapping.get (original_event_id)

    if not event_mapping:
        logging.error (f"No mapping found for Event ID: {original_event_id}")
        standard_event ["other_data"] = parsed_event
        standard_event ["standard_event_type"] = "UnmappedEvent"
        return standard_event

    # Setting event type and action from mapping
    standard_event ["standard_event_type"] = event_mapping.get ("_event_type", "Unknown")
    standard_event ["action"] = event_mapping.get ("_action")

    # Map fields from parsed_event to standard_event using mapping
    for original_field_name, original_field_value in parsed_event.items ():
        # Skip fields that are already handled
        if original_field_name in ["os", "event_id", "hostname", "timestamp", "event_type"]:
            continue

        field_mapping = event_mapping.get (original_field_name)

        if field_mapping:
            # Get standardized file path, e.g., process.process_id
            standard_field_path = field_mapping.get ("standard_field")
            field_type = field_mapping.get ("type")

            # Core standardization logic
            if standard_field_path:
                # Mapping original field values to standard keys
                parts = standard_field_path.split ('.')
                current_dict = standard_event
                try:
                    for i, part in enumerate (parts):
                        if i == len(parts) - 1:
                            # Apply type conversion, if specified
                            if field_type == "integer":
                                try:
                                    current_dict [part] = int (original_field_value) if original_field_value is not None else None
                                except (ValueError, TypeError):
                                    current_dict [part] = original_field_value
                                    logging.warning (f"Standardization: Couldn't convert {original_field_value}")
                            elif field_type == "boolean":
                                if isinstance (original_field_value, str):
                                    current_dict [part] = original_field_value == "true"
                                elif original_field_value is not None:
                                    current_dict [part] = bool (original_field_value)
                                else:
                                    current_dict [part] = None
                            # Other type conversions
                            # elif:
                            else:
                                current_dict [part] = original_field_value
                        else:
                            # Intermediate part of the path, part of nested dictionary
                            if part not in current_dict or not isinstance (current_dict[part], dict):
                                current_dict [part] = {}
                            # Move to the nested dictionary
                            current_dict = current_dict [part]
                except Exception as e:
                    standard_event ["other_data"][original_field_name] = original_field_value
                    logging.error (f"Standardization: Error processing field: {original_field_name} : {e}", exc_info = True)
            else:
                # Mapping exists but standard_field is missing or empty
                standard_event ["other_data"][original_field_name] = original_field_value
                logging.warning (f"Standardization: Mapping found for {original_field_name}, but 'standard_field' is missing or empty")
        else:
            # No mapping found for original_field
            if original_field_name != "UtcTime":
                standard_event ["other_data"][original_field_name] = original_field_value
                logging.debug (f"Standardization: No direct mapping found for {original_field_name}")

    # Formatting timestamp
    timestamp_str = parsed_event.get ("timestamp")
    if timestamp_str:
        try:
            standard_event["event_timestamp"] = timestamp_str
            dt_obj = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            standard_event["event_timestamp"] = dt_obj.isoformat(timespec='microseconds')
        except Exception as e:
            logging.error (f"Couldn't standardize timestamp: {e}")
            standard_event ["event_timestamp"] = timestamp_str

    return standard_event
