Artemis follows a distributed architecture, with lightweight agents deployed on monitored hosts and a centralized server 
for data processing, analysis, presentation and command and control (C2) operations.
As such, the operating codes are logically split and grouped under agent and server directories, with each containing 
the code to their respective operations.
<br>
<b><i><u>Core Design Principles:</u></i></b> Modularity, Abstraction, Configuration-Driven Logic, 
Standardized Data Format

## Artemis Agent
#### Deployed on Monitored Hosts- Windows and Linux

### <b><i><u> Agent Configuration File</u></i></b>
- <b>Agent Configuration:</b> ```artemis_agent_win.ini``` (for Windows) and ```artemis_agent_lin.ini``` (for Linux) specifying the following:

  - Log source(s) to monitor, such as Sysmon channels, Event log channels, auditd logs and syslog files.
  - Basic filtering criteria, such as EventIDs, Event source or other related keywords.
  - Communication settings, such as protocols, server address and port address for communication.
  - Logging configurations.

### <b><i><u>Data Collection Module</u></i></b>

  - Reads raw events from the configured OS log sources.
  - Implements basic filtering at the source, for specific events, if possible.

### <b><i><u>Basic Parsing Module</u></i></b>

  - Takes raw event data and performs initial parsing specific to the log source format
  - e.g., parsing Sysmon XML, splitting auditd log lines and extracting fields.\

### <b><i><u>Standardization Module</u></i></b>

  - Takes parsed data from the previous module and transforms it into a consistent predefined 
    JSON schema, known as Artemis Schema, used across all agents and the server.
  - Ensures data from different OS types and log sources has a uniform structure.

### <b><i><u>Communication Module</u></i></b>
   
  - Handles securely transmitting the standardized JSON data to the Server's Ingestion Layer. Includes buffering and 
    retry logic for resilience.

### <b><i><u>Remote Command Receiver Module</u></i></b>

  - Listens for incoming commands from the Server's Remote Response/C2 Module via a secure channel. 
    Validates incoming commands.

### <b><i><u>Remote Command Execution Module</u></i></b>

  - Executes the received commands on the host (e.g., runs a script, retrieves a file, 
    terminates a process - with extreme caution and proper authorization). 
  - Returns the result to the Remote Command Receiver.

---

## Artemis Agent
