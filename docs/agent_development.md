# 3. Develop Basic Event Log Monitoring
## *3.1 Windows*

### *3.1.1 Data Collection*

| ***Input*** | ***Output*** | ***File Location*** | ***Module(s)*** |
| --- | --- | --- | --- |
| Windows configuration file | `collected_events` → a list of raw event objects returned by `win32evtlog.EvtNext` | `artemis/agent/windows/artemis_agent_win.py` | `SetupLogging`, `CollectRawWindowsEvents`  |

This module is responsible for connecting to the Sysmon channel and reading raw event data based on the configuration file (`artemis_agent_win.ini`). The package  `pywin32` is better suited for this task as it uses Windows APIs directly and can access Event Logs in real-time. We will use the module `win32evtlog` that leverages the Win32 Event Log API to read specific Sysmon logs.

***Functionalities***

1. Load the windows configuration file → `configparser` package.
2. Setup logging mechanism → `logging` package.
    
    Log File location: `C:\ProgramData\Artemis\Logs\artemis_agent_win.log`
    
3. Construct XPath Query.
4. Open a handle to Sysmon channel.
5. Retrieve events in batches.
    
    Use a loop with `win32evtlog.EvtNext(handle, batch_size)` to efficiently read events in chunks. Continue reading batches until `max_events_to_read` is reached or `EvtNext` returns an empty list (indicating no more events).
    
6. Error Handling during the `EvtQuery` and `EvtNext` calls.
7. Close the channel handle.
    
    `EvtClose` kept resulting in `AttributeError`. Tried and resolved it using the generic methods from `win32api`- `close ( )` and `CloseHandle ( )` calls.
    
8. Update main function to implement `SetupLogging` and `CollectRawEvents` functions.

### *3.1.2 Parsing Module*

| ***Input*** | ***Output*** | ***File Location*** | ***Module(s)*** |
| --- | --- | --- | --- |
| `event` → individual raw event object | `event_data` → dictionary object holding the parsed event | `artemis/agent/windows/artemis_agent_win.py` | `ParseEventData` |

This module takes the raw event objects collected by the Data Collection Module and parses them to extract specific data fields relevant to each Sysmon Event ID within the initial scope. It focuses on the Sysmon-specific parsing logic, by leveraging the `win32evtlog.EvtRender` function, and then ElementTree library to extract specific fields needed.

***Functionalities***

1. Format the received event into XML format using `win32evtlog.EvtRender` call and the `win32evtlog.EvtRenderEventXml` flag.
2. Define namespace to correctly parsing critical fields. This also avoids naming conflicts.
    
    ```python
    ns = { 'win': 'http://schemas.microsoft.com/win/2004/08/events/event' }
    ```
    
3. Implement XML parsing using `ElementTree` library and the defined namespace to extract common fields, such as EventID, Timestamp, etc.,
4. Implement XML parsing for each relevant Sysmon Event ID from the scope, using `ElementTree` library and `if...elif` blocks.
5. Implement Error Handling by adding `try…except` blocks around XML parsing to catch parsing errors and log them.
6. Structure parsed data, by organizing them into a dictionary.
7. Update main function to implement the `ParseEventData` function.
8. Validate parsing by logging few samples.

---

## ***3.2 Linux***

### *3.2.1 Data Collection*

| ***Input*** | ***Output*** | ***File Location*** | ***Modules*** |
| --- | --- | --- | --- |
| Linux configuration file | `grouped_events` → list object holding the grouped lines | `artemis/agent/linux/artemis_agent_lin.py` | `ReadAuditLog` , `GroupAuditdLines` |

This module is responsible for reading raw `auditd` event logs. The main challenge with reading from `auditd` logs is, these logs span multiple lines linked by a common timestamp and serial number. To effect these complex operations, the logic is split into two modules- one that reads raw auditd log lines and another that groups lines into complete events. Auditd events start with a line containing `msg=audit(<timestamp>:<serial>):` - the timestamp and serial number uniquely identify an event.

***Functionalities***

1. Load the windows configuration file → `configparser` package.
2. Setup logging mechanism → `logging` package.
    
    Log File location: `/var/log/artemis/agent_linux.log`
    
3. Read raw `auditd` log lines.
    1. Open the log file configured and read the file content.
    2. Append the contents onto a list of lines and return them.
    3. Implement error handling such as `FileNotFoundError` and `PermissionError` .
4. Group `auditd` raw lines into individual events.
    1. Iterate through the list of individual lines (output of #3).
    2. Use regular expression (re) to extract timestamp and serial number from the beginning of each line.
    3. Buffer lines (`current_event_lines`) until a different timestamp or serial number is encountered.
    4. When a new event is detected (different timestamp/serial), the `current_event_lines` buffer contains all the lines for the *previous* complete event. Add this list of lines to a main list of `grouped_events`, and then start a new `current_event_lines` buffer with the current line.
    5. Return the list of completed events, where each item is a list of strings belonging to one auditd event.
5. Update main script to implement the data collection logic .
6. Log a few samples to verify grouping individual events.

### *3.2.2 Parsing Module*

| ***Input*** | ***Output*** | ***File Location*** | ***Module*** |
| --- | --- | --- | --- |
| `event_lines` → list object holding grouped log lines belonging to a single event. | `parsed_data` → dictionary object holding the parsed event | `artemis/agent/linux/artemis_agent_linux.py` | `ParseAuditdEvent` |

 This module takes a grouped list of `auditd` log lines representing a single event and parses them to extract key-value pairs, creating a structured Python dictionary.

***Functionalities***

1. Iterate through each of the lines from `event_lines` .
2. For each line, identify its `type=` and parse the space-separated `key=value` pairs. 
3. Combine all extracted fields from all lines of the event into a single dictionary, using the original `auditd` field names as keys.
4. Format the extracted `auditd` timestamp in seconds.milliseconds format to ISO 8601 format.
5. Update the main function to implement the logic.
6. Verify the parsing logic by logging few samples.

---

## *3.4 Standardization Module*

| ***Input*** | ***Output*** | ***File Location(s)*** | ***Modules*** |
| --- | --- | --- | --- |
| `parsed_data` →  dictionary object holding the parsed event from the respective agent | `standard_event` → dictionary object holding the converted standardized event | `artemis/agent/shared/data_formatter.py` , `artemis/agent/windows/artemis_agent_win.ini`,`artemis/agent/linux/artemis_agent_lin.ini` | `CreateBaseStandardEvent` ,  `StandardizeEvent` |

This module takes the parsed data (which still might be in slightly different formats depending on the OS and source) and transforms it into a single, consistent, standardized Artemis JSON schema that all agents will use.

***Functionalities***

1. Define the standardized JSON schema, henceforth referred to as Artemis Schema to be used by all agents. A sample of it is given below.
    
    ```json
    {
         "agent_id": "string",
         "event_timestamp": "string (ISO 8601 UTC)",
         "hostname": "string",
         "os": "string (windows or linux)",
         "event_source": "string (sysmon, auditd, etc.)",
         "original_event_id": "string",
         "standard_event_type": "string",
         "process": { ... }, # Nested process details
         "network": { ... }, # Nested network details
         "file": { ... },    # Nested file details
         "registry": { ... }, # Nested registry details
         "other_data": { ... } # Optional catch-all
    }
    ```
    
2. Define the structure of Standardization Mapping JSON files `standardization_map_win.json`  and  `standardization_map_lin.json` .
    
    The initial approach was to structure it by the `event_id` . However this can’t be used for Linux systems as the logs do not have standardized EventIDs like Windows logs. Later it was decided to structure it by `event_type` and map original fields to their respective standard fields from Artemis Schema.
    
    A sample of Windows mapping structure is given below.
    
    ```json
    {
      "ProcessCreate": {
        "_event_type": "ProcessEvent",
        "_action": "create",
        "ProcessId": { "standard_field": "process.process_id", "type": "string" },
        "ProcessGuid": { "standard_field": "process.process_guid", "type": "string" },
        "ParentProcessId": { "standard_field": "process.parent_process_id", "type": "string" },
        "ParentProcessGuid": { "standard_field": "process.parent_process_guid", "type": "string" },
        "User": { "standard_field": "process.user", "type": "string" },
        "Image": { "standard_field": "process.executable_path", "type": "string" },
        "ParentImage": { "standard_field": "process.parent_executable_path", "type": "string" },
        "CommandLine": { "standard_field": "process.command_line", "type": "string" },
        "ParentCommandLine": { "standard_field": "process.parent_command_line", "type": "string" },
        "Hashes": { "standard_field": "process.hash", "type": "string" },
        "IntegrityLevel": { "standard_field": "process.integrity_level", "type": "string" }
      },
      ...
     }
    ```
    
    A sample of  Linux mapping structure is given below.
    
    ```json
    {
      "ProcessEvent": {
        "_event_type": "ProcessEvent",
        "_action": "create",
        "pid": { "standard_field": "process.process_id", "type": "integer" },
        "ppid": { "standard_field": "process.parent_process_id", "type": "integer" },
        "comm": { "standard_field": "process.process_name", "type": "string" },
        "exe": { "standard_field": "process.executable_path", "type": "string" },
        "proctitle": { "standard_field": "process.command_line", "type": "string" },
        "uid": { "standard_field": "process.uid", "type": "integer" },
        "auid": { "standard_field": "process.auid", "type": "integer" },
        "cwd": { "standard_field": "process.cwd", "type": "string" },
        "syscall": { "standard_field": "process.syscall_number", "type": "integer" },
        "success": { "standard_field": "action_status", "type": "string" },
        "exit": { "standard_field": "action_exit_code", "type": "integer" },
        "key": { "standard_field": "rule_key", "type": "string" },
        "name": { "standard_field": "file.path", "type": "string" }
      },
      ...
     }
    ```
    
    **Note on `_event_type` and `_action`:** I've added special keys like `_event_type` and `_action` in the mapping to define the standardized event type and any common actions (like file or registry actions) based on the original event.
    
3. Load the mapping file and create base event that maps common fields across various events such as Agent ID, OS, source, hostname, etc., 
4. Get the `event_type` from the `parsed_event` and look up for the event type from loaded map.
5. If mapping exists, iterate through the original fields and map them to their respective standard fields using the loaded map (if the mapping is found).
6. The original fields without corresponding standard fields are put into `standard_event [”other_data”]` dictionary.
7. Format the timestamp from the `parsed_event` into ISO 8601 format and put into `standard_event [”event_timeestamp”]` .
8. Modify the main functions on artemis_agent_win.py and artemis_agent_lin.py to implement this standardization logic.
9. Validate standardization by logging few samples.
---
