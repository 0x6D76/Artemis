# <b><u>Phase 1: Planning and Design</u></b>

## <i>Step 1: Define scope and Specific Use Cases</i>
- [x] Precisely list the specific types of suspicious activities that will be the initial focus of the scope.
- [x] Choose operating system(s) that the tool will support.
- [x] Decide on the initial data sources to prioritize.
- [x] Outline the basic architecture.
- [x] Decide on the data storage solution.
- [x] Plan the technology stack for
    
  - [x] Server
  - [x] Data aggregation
  - [x] Visualization

## <i>Step 2: Setup Lab Environment</i>
- [x] Plan on the required number of VMs and deploy them. To consider- Agents (Windows & Linux), Server and Attacker.
- [x] Configure networking within the lab environment so VMs can communicate.
- [x] Install necessary tools and software appropriate to the VMs.
- [x] Setup separate VM for server components and install appropriate tools and packages.
  - [x] Develop a network diagram of the lab setup.

---

# <b><u>Phase 2: Agent Development - Core Functionality</b></u>

## <i>Step 3: Develop Basic Event Log Monitoring</i>
- [x] On Windows, develop code to interface with and consume Sysmon events, focussing on reading relevant security 
      channels.
- [x] On Linux, develop code to read from ```auditd```.
- [x] Implement basic parsing logic for log entries, to extract key information, such as timestamp, user, event type, 
      process ID and other relevant parameters.
- [x] Structure the collected log data into a consistent, easily parsable format i.e., Artemis JSON schema

## <i>Step 4: Implement Process Monitoring and Analysis</i>
- [ ] Develop functionality to collect more detailed process information: process integrity level (Windows), 
      capabilities/effective user ID (Linux), command line arguments (crucial!), parent-child process relationships, 
      loaded modules/libraries.
- [ ] Implement monitoring for new process creation and process termination events.
- [ ] Implement monitoring for process injection attempts (detecting suspicious parent-child relationships or processes 
      running from unusual directories).
- [ ] Calculate the hash of executed processes (e.g., MD5, SHA256) for threat intelligence correlation later.

## <i>Step 5: Implement Persistence Monitoring</i>
- [ ] On Windows, focus on monitoring key Windows Registry Run keys, Startup folders, and potentially WMI event 
      consumers.
- [ ] On Linux, focus on monitoring common persistence locations like ```/etc/rc.local```, systemd services, 
      and user cron jobs.

## <i>Step 6: Agent-to-Server Communication</i>
- [ ] Choose a communication protocol.
- [ ] Implement basic data compression for transmission to reduce bandwidth usage.
- [ ] Implement secure communication between agent(s) and server.
- [ ] Develop a simple data format for sending collected events from the agent to the server.

--- 

# <b><u>Phase 3: Server Development and Data Processing</b></u>

## <i>Step 7: Data Ingestion and Aggregation</i>
- [ ] Build the server-side component to receive data from the agents.
- [ ] Implement a robust parsing and validation layer for incoming agent data based on Artemis JSON schema. 
      Handle malformed data gracefully.
- [ ] Integrate with the chosen message queue to handle bursts of data and decouple the ingestion from the processing.
- [ ] Develop workers or consumers that read from the message queue (or directly from the ingestion layer) and process 
      the data before storing it. This processing might include basic field enrichment or initial filtering.
- [ ]  Implement efficient writing of the processed data into the database and index them for faster searching.

## <i>Step 8: Implement Initial Detection Logic</i>
- [ ] Develop rules or simple algorithms on the server to identify the suspicious activities defined in <i>Step 1</i>
      based on the aggregated data. This could include:
  - [ ] Matching on specific event IDs and patterns.
  - [ ] Identifying processes running from unusual locations.
  - [ ] Flagging modifications to persistence locations.
  - [ ] Correlating multiple events (e.g., a process creation followed by a registry modification in a persistence key, 
        or a suspicious process initiating an outbound network connection).
- [ ] Implement simple stateful analysis (e.g., tracking process lineage).
- [ ] Develop a flexible rule engine or structure that allows adding new detection rules easily.
- [ ] Implement an alerting mechanism when a detection rule is triggered (e.g., print to console, send to a log file 
      the server is monitoring, or integrate with a simple notification system).

## <i>Step 9: Integrate Threat Intelligence</i>
- [ ] Research and identify a free or open-source threat intelligence feed (e.g., abuse.ch, AlienVault OTX).
- [ ] Automate the process of fetching updates from the chosen threat intelligence feed(s). Implement error handling 
      for feed ingestion.
- [ ] Implement correlation logic to check if any collected events or indicators (process hashes, IP addresses, 
      domain names) match entries in the threat intelligence feed.
- [ ] Implement a mechanism to flag or enrich events in the database that correlate with threat intelligence 
      indicators.

---

# <b><u>Phase 4: Advanced Features and Visualization</b></u>

## <i>Step 10: Implement Contextual Anomaly Detection (Basic)</i>
- [ ] Choose a specific type of anomalous behavior to detect (e.g., a process running from a directory it normally 
      doesn't, unusual network connections for a specific process, a user logging in at an unusual time).
- [ ] Explore slightly advanced anomaly detection techniques (e.g., statistical analysis of frequency, 
      simple behavioral profiling).
- [ ] Integrate anomaly flagging into data processing pipeline and database.

## <i>Step 11: Set up Prometheus for Metrics Collection</i>
- [ ] Install and configure Prometheus on the server VM.
- [ ] Ensure Prometheus is collecting metrics from your server components (data ingestion rate, processing speed, 
      database write latency, number of detections triggered).
- [ ] Modify the agent and server components to expose relevant metrics (e.g., number of events collected, 
      processing time, number of detections) in a format Prometheus can scrape.

## <i>Step 12: Build Threat Hunting Dashboards with Grafana</i>
- [ ] Install and configure Grafana on the server VM.
- [ ] Configure Grafana data sources to connect to the data storage (Elasticsearch, PostgreSQL, etc.) and Prometheus.
- [ ] Design and build dashboards in Grafana to visualize the collected data, detections, anomalies, and system metrics. 
      Create dashboards tailored for threat hunting (e.g., process trees, timeline of events for a host, geographical 
      distribution of suspicious connections).

## <i>Step 13: Implement Basic Remote Response Actions</i>
- [ ] Design a secure command and control mechanism for the server to send basic commands to the agent 
      (e.g., retrieve a file, terminate a process)
- [ ] Implement the agent-side functionality to receive and execute these commands securely.
- [ ] Implement logging of all commands sent to agents and their execution status.

---

# <b><u>Phase 5: Testing and Documentation</b></u>

## <i>Step 14: Comprehensive Testing</i>
- [ ] Conduct thorough testing of the agent on both Windows and Linux, ensuring it collects data correctly and 
      efficiently.
- [ ] Test the detection rules and anomaly detection with simulated malicious activities in the lab.
- [ ] Test the server's data ingestion and processing capabilities.
- [ ] Test the Grafana dashboards to ensure they accurately reflect the data and provide useful insights.
- [ ] Test the remote response actions carefully in the isolated lab.

## <i>Step 15: Refine and Optimize</i>
- [ ] Based on testing, optimize the agent's performance and resource usage.
- [ ] Refine the detection logic to reduce false positives and improve accuracy.
- [ ] Improve the usability and clarity of the Grafana dashboards.

## <i>Step 16: Comprehensive Documentation</i>
- [ ] Write a detailed project report covering:
  - Project overview and goals.
  - Architecture design (with diagrams).
  - Technology stack used.
  - Agent implementation details (including challenges with OS APIs).
  - Server implementation details (data ingestion, storage, processing).
  - Detection logic and anomaly detection methods.
  - Threat intelligence integration.
  - Grafana dashboard design and how to use them for hunting.
  - Remote response capabilities and security considerations.
  - Installation and configuration guides for the agent and server.
  - Lessons learned and future improvements.

---

# <b><u>Potential Technologies to Consider</b></u>

- <b>Agent Development:</b> Python (with libraries for interacting with OS APIs), Go, Rust (for performance).
- <b>Event Ingestion:</b> Syslog, Apache Kafka, RabbitMQ.
- <b>Server/Backend:</b> Python (Flask/Django), Go, Node.js.
- <b>Data Storage:</b> Elasticsearch, PostgreSQL, TimescaleDB (for time-series data).
- <b>Metrics Collection:</b> Prometheus Node Exporter (for host metrics), custom exporters for agent metrics.
- <b>Visualization:</b> Grafana.
- <b>Anomaly Detection Libraries:</b> Scikit-learn (for Python), or explore dedicated time-series anomaly detection 
   libraries.