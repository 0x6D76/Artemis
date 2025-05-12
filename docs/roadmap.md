# <b><u>Phase 1: Planning and Design</u></b>

## <i>Step 1: Define scope and Specific Use Cases</i>
- [ ] Precisely list the specific types of suspicious activities that will be the initial focus of the scope.
- [ ] Choose operating system(s) that the tool will support.
- [ ] Decide on the initial data sources to prioritize.
- [ ] Outline the basic architecture.
- [ ] Decide on the data storage solution.
- [ ] Plan the technology stack for
    
  - [ ] Server
  - [ ] Data aggregation
  - [ ] Visualization

## <i>Step 2: Setup Lab Environment</i>
- [ ] Plan on the required number of VMs and deploy them. To consider- Agents (Windows & Linux), Server and Attacker.
- [ ] Configure networking within the lab environment so VMs can communicate.
- [ ] Install necessary tools and software appropriate to the VMs.
- [ ] Setup separate VM for server components and install appropriate tools and packages.
- [ ] Develop a network diagram of the lab setup.

---

# <b><u>Phase 2: Agent Development - Core Functionality</b></u>

## <i>Step 3: Develop Basic Event Log Monitoring</i>
- [ ] On Windows, develop code to interface with and consume Sysmon events, focussing on reading relevant security 
      channels.
- [ ] On Linux, develop code to read from ```auditd```.
- [ ] Implement basic parsing logic for log entries, to extract key information, such as timestamp, user, event type, 
      process ID and other relevant parameters.

## <i>Step 4: Implement Process Monitoring</i>
- [ ] Develop functionality to list running processes, their parent processes, command lines, and potentially process 
      hashes.
- [ ] Implement monitoring for new process creation and process termination events.

## <i>Step 5: Implement Basic Persistence Monitoring (Initial Set)</i>
- [ ] On Windows, focus on monitoring key Windows Registry Run keys, Startup folders, and potentially WMI event 
      consumers.
- [ ] On Linux, focus on monitoring common persistence locations like ```/etc/rc.local```, systemd services, 
      and user cron jobs.

## <i>Step 6: Agent-to-Server Communication</i>
- [ ] Choose a communication protocol.
- [ ] Implement secure communication between agent(s) and server.
- [ ] Develop a simple data format for sending collected events from the agent to the server.

--- 

# <b><u>Phase 3: Server Development and Data Processing</b></u>

## <i>Step 7: Data Ingestion and Aggregation</i>
- [ ] Build the server-side component to receive data from the agents.
- [ ] Implement logic to parse the incoming data and store it in the chosen database.
- [ ] Design the database schema to efficiently store and query the collected security events.

## <i>Step 8: Implement Initial Detection Logic</i>
- [ ] Develop rules or simple algorithms on the server to identify the suspicious activities defined in <i>Step 1</i>
      based on the aggregated data. This could include:
  - [ ] Matching on specific event IDs and patterns.
  - [ ] Identifying processes running from unusual locations.
  - [ ] Flagging modifications to persistence locations.
- [ ] Implement an alerting mechanism when a detection rule is triggered (e.g., print to console, send to a log file 
      the server is monitoring, or integrate with a simple notification system).

## <i>Step 9: Integrate Threat Intelligence</i>
- [ ] Research and identify a free or open-source threat intelligence feed (e.g., abuse.ch, AlienVault OTX).
- [ ] Develop functionality on the server to ingest data from the threat intelligence feed.
- [ ] Implement correlation logic to check if any collected events or indicators (process hashes, IP addresses, 
      domain names) match entries in the threat intelligence feed.

---

# <b><u>Phase 3: Advanced Features and Visualization</b></u>
