"""
File: artemis_agent_win.py
Description:
Author: 0x6D76
Copyright (c) 2025 0x6d76@proton.me
"""
import configparser
import json
import logging
import os
import sys
import win32api # For handle close method, since EvtClose wouldn't work
import win32evtlog
import win32evtlogutil
import win32con
import xml.etree.ElementTree as ET
# Get the absolute path of the directory containing the script
script_dir = os.path.dirname(os.path.abspath(__file__))
# Get the absolute path of the project root (assuming it's two levels up)
project_root = os.path.abspath(os.path.join(script_dir, '..', '..'))
# Add the project root to sys.path
# Insert at the beginning (index 0) so it's checked first
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from agent.shared.utils import LoadConfig
from agent.shared.data_formatter import LoadMapping, StandardizeEvent

WIN_AGENT_CONFIG = 'artemis_agent_win.ini'
WIN_STD_CONFIG = 'standardization_map_win.json'


def SetupLogging (config):
    """Configures logging for the Windows agent."""
    log_file = config.get ('logging', 'log_file')
    log_level_str = config.get ('logging', 'log_level', fallback = 'INFO').upper ()

    # Create log directory, if it doesn't exist
    log_dir = os.path.dirname (log_file)
    if not os.path.exists(log_dir):
        try:
            os.makedirs (log_dir)
        except OSError as e:
            print (f"Error creating {log_dir}: {e}")
            # Use the current dir for the log file
            log_file = os.path.basename (log_file)
    # Map log level string to logging constant, defaults to INFO
    log_level = getattr (logging, log_level_str, logging.INFO)
    logging.basicConfig (
        level = log_level,
        format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers = [logging.FileHandler (log_file)]
    )
    return logging


def CollectRawWindowsEvents (config):
    """Collects raw event objects from Windows Event Log/Sysmon based on config."""
    channel = config.get ('windows_event_log', 'sysmon_channel')
    event_ids_str = config.get ('windows_event_log', 'event_ids')
    batch_size = config.getint ('agent_settings', 'batch_size')
    max_events = config.getint ('agent_settings', 'max_events')

    # Construct the XPath query from the list of event IDs
    # Example: "*[System[(EventID=1 or EventID=3 or EventID=...)]]"
    event_ids = [id.strip () for id in event_ids_str.split (',')]
    if not event_ids:
        logging.error ("No Event ID specified in the configuration file.")
        return []
    event_id_filter = " or ".join ([f"EventID={id}" for id in event_ids])
    query = f"*[System[({event_id_filter})]]"
    logging.info (f"Constructed XPath Query: {query}")

    # Start from the newest
    flags = win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection
    handle = None
    collected_events = []
    count = 0
    try:
        logging.info (f"Attempting to query channel '{channel}'")
        handle = win32evtlog.EvtQuery (channel, flags, query)
        logging.info (f"Query successful")

        try:
            while count < max_events:
                try:
                    events = win32evtlog.EvtNext (handle, batch_size)
                except win32evtlog.error as e:
                    if e.winerror == 15007:
                        logging.info ("No more events in the current query.")
                    else:
                        logging.error (f"Failed to retrieve events: {e}")
                    break

                if not events:
                    logging.info ("Batch is empty, ending event collection.")
                    break

                for event in events:
                    collected_events.append (event)
                    count += 1

                    if count >= max_events:
                        logging.info (f"Reached max size ({max_events}). Stopping event collection.")
                        break
        except Exception as e:
            logging.error (f"An unexpected error occurred during event collection: {e}")


    except win32evtlog.error as e:
        logging.error (f"Failed to query channel {channel} with query '{query}': {e}")
        return []

    except Exception as e:
        logging.error (f"An unexpected error occurred during initial query: {e}")
        return []

    finally:
        # Ensuring opened handle is closed using win32api
        if handle:
            try:
                if hasattr (handle, 'close'):
                    # Attempt to use a .close() method, if it exists
                    handle.close ()
                    logging.info ("Closed event log handle using close ().")
                else:
                    # If no .close() method, try win32api.CloseHandle
                    win32api.CloseHandle (handle)
                    logging.info ("Closed event log handle using win32api.")
            except Exception as e:
                logging.error (f"Error attempting to close handle {handle}: {e}")

    logging.info (f"Finished collecting {len (collected_events)} raw events.")
    return collected_events


def ParseEventData (event):
    """Extract relevant information from the given event using XML parsing."""

    # Format event log into XML data
    xml_data = win32evtlog.EvtRender (event, win32evtlog.EvtRenderEventXml)

    try:
        root = ET.fromstring (xml_data)
        ns = { 'win': 'http://schemas.microsoft.com/win/2004/08/events/event' }

        # Extract common fields from System section
        event_id_elem = root.find ('.//win:EventID', ns)
        event_id = event_id_elem.text if event_id_elem is not None else None
        hostname_elem = root.find ('.//win:Computer', ns)
        hostname = hostname_elem.text if hostname_elem is not None else None
        time_created_elem = root.find ('.//win:TimeCreated', ns)
        timestamp = time_created_elem.attrib.get ('SystemTime') if time_created_elem is not None else None

        # Initialize event_data dictionary with common fields
        event_data = {
            "os" : "windows",
            "event_id" : event_id,
            "hostname" : hostname,
            "timestamp" : timestamp,
            "original_xml" : xml_data # For debugging purposes
        }
        # --- Parse fields from the EventData section using Name attributes ---
        event_data_root = root.find ('.//win:EventData', ns)  # Find the EventData element

        if event_data_root is not None:
            # Find all Data elements within EventData
            for data_elem in event_data_root.findall ('.//win:Data', ns):
                name_attribute = data_elem.attrib.get ('Name')
                if name_attribute is not None:
                    # Extract fields based on the 'Name' attribute
                    event_data [name_attribute] = data_elem.text
        # --- End of parsing fields from the EventData section ---

        # --- Event-specific standardization ---
        # Event IDs- 1, 3, 5, 7, 11, 12, 13, 14, 23, 24
        if event_id == '1':  # ProcessCreate
            event_data ["event_type"] = "ProcessCreate"
        elif event_id == '3':  # NetworkConnect
            event_data ["event_type"] = "NetworkConnect"
        elif event_id == '5': # ProcessTermination
            event_data ["event_type"] = "ProcessTermination"
        elif event_id == '7': # ImageLoaded
            event_data ["event_type"] = "ImageLoaded"
        elif event_id == '11':  # FileCreate
            event_data ["event_type"] = "FileCreate"
        elif event_id == '12':  # Registry object added or deleted
            event_data["event_type"] = "RegistryObjectChange"
        elif event_id == '13':  # Registry value set
            event_data["event_type"] = "RegistryValueSet"
        elif event_id == '14':  # Registry object renamed
            event_data["event_type"] = "RegistryObjectRenamed"
        elif event_id == '23':  # FileDelete
            event_data ["event_type"] = "FileDelete"
        elif event_id == '26': # FileDeleteDetected
            event_data ["event_type"] = "FileDeleteDetected"
        else:
            event_data ["event_type"] = "OtherSysmonEvent"
        # --- End of Event-specific standardization ---
        return event_data

    except Exception as e:
        logging.error (f"Error parsing event XML: {e}", exc_info = True)
        logging.debug (f"Problematic XML: {xml_data}")
        return None


if __name__ == '__main__':
    current_dir = os.path.dirname (os.path.abspath(__file__))
    config_file = os.path.join (current_dir, WIN_AGENT_CONFIG)
    app_config = LoadConfig (config_file)

    if app_config:
        SetupLogging (app_config)
        logging.info ("Artemis Windows Agent is up and running.")
        agent_identity = app_config.get('agent_settings', 'agent_id', fallback="windows-agent-unknown")

        raw_events = CollectRawWindowsEvents (app_config)
        logging.info (f"Received {len(raw_events)} raw events from collection module.")

        parsed_events = []
        for raw_event in raw_events:
            parsed_event = ParseEventData (raw_event)
            if parsed_event:
                parsed_events.append (parsed_event)

        logging.info (f"Finished parsing {len (parsed_events)} events.")
        # Validating parsing logic
        logging.debug (f"Sample of parsed events:")
        for i, event in enumerate (parsed_events):
            logging.debug (f"Event {i+1}:\n{json.dumps (event, indent=4)}")

        mapping_file = os.path.join (current_dir, WIN_STD_CONFIG)
        standardized_mapping = LoadMapping (mapping_file)
        standardized_events = []
        for parsed_event in parsed_events:
            standard_event = StandardizeEvent (parsed_event, agent_identity, standardized_mapping)
            if standard_event:
                standardized_events.append (standard_event)
        logging.info (f"Finished standardization of {len (standardized_events)} events.")

        logging.info ("Sample- Standardized events")
        for i, event in enumerate(standardized_events [:50]):
            logging.info (f"Standardized Event {i + 1}:\n{json.dumps(event, indent=4)}")

        logging.info ("Artemis Windows Agent is done executing.")
