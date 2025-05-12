```text
artemis/
├── agent/
│   ├── windows/
│   │   ├── artemis_agent_win.py      # Main script for the Windows agent
│   │   ├── artemis_agent_win.ini     # Configuration file for the Windows agent
│   │   └── requirements.txt          # Python dependencies for Windows agent (pywin32, configparser, etc.)
│   ├── linux/
│   │   ├── artemis_agent_linux.py    # Main script for the Linux agent
│   │   ├── artemis_agent_linux.ini   # Configuration file for the Linux agent
│   │   └── requirements.txt          # Python dependencies for Linux agent (libraries for auditd/syslog, configparser, etc.)
│   └── shared/                       # (Optional) Code shared between Windows and Linux agents
│       ├── __init__.py               # Makes 'shared' a Python package
│       ├── data_formatter.py         # Logic to transform parsed data into the standardized JSON schema
|       ├── utils.py                  # Common utilities used across agents of different OS
│       └── comms_client.py           # Abstracted logic for sending data (handles buffering, retries)
├── server/
│   ├── artemis_server.py           # Main entry point/orchestrator for the server components
│   ├── config/                     # Server configuration files
│   │   ├── server_config.ini       # General server settings (ports, database connection, message queue connection)
│   │   ├── detection_rules/        # Directory containing detection rule definitions (e.g., YAML files)
│   │   │   ├── process_rules.yaml
│   │   │   ├── file_rules.yaml
│   │   │   └── ...
│   │   ├── threat_intel_feeds.yaml # Configuration for threat intelligence feeds
│   │   └── remote_actions.yaml     # Configuration for available remote actions
│   ├── database/                   # Database related scripts or configuration
│   │   └── schema.sql              # SQL script to create the database tables
│   ├── dashboard/                  # Files related to monitoring and visualization
│   │   ├── grafana/                # Exported Grafana dashboard JSON files
│   │   └── prometheus/             # Prometheus configuration file (prometheus.yml)
│   ├── requirements.txt            # Python dependencies for the server (message queue library, database driver, web framework for ingestion, etc.)
│   └── modules/                    # Server core modules 
│       ├── __init__.py             # Makes 'modules' a Python package
│       ├── ingestion.py            # Code for the Ingestion Layer
│       ├── processing_worker.py    # Code for the Processing & Normalization Workers
│       ├── detection_engine.py       # Code for the Detection Engine Workers
│       ├── anomaly_detector.py       # Code for Anomaly Detection Workers
│       ├── threat_intel_manager.py   # Code for the Threat Intelligence Manager
│       ├── data_storage_interface.py # Code to interact with the database (abstracted)
│       └── remote_commander.py       # Code for the Remote Response / C2 Module
├── docs/                           # Project documentation
│   ├── images/                     # Directory for diagrams (architecture, network) and screenshots
│   ├── README.md                   # High-level project description, goals, features
│   ├── architecture.md             # Detailed explanation of the architectural design
│   ├── setup_guide.md              # Instructions for setting up the lab environment (Azure VMs, OS configs, tool installations)
│   ├── agent_development.md        # Details on agent implementation (Windows and Linux specific challenges, modules)
|   ├── file_hierarchy.md           # Hierarchical structure of the project
│   ├── server_development.md       # Details on server implementation (each module's function, data flow)
│   ├── detection_logic.md          # Explanation of the detection rules, mapping to MITRE ATT&CK
│   ├── threat_hunting_guide.md     # How to use Grafana dashboards and server features for hunting
│   ├── remote_response.md          # Details on the Remote Response/C2 capabilities and security
│   └── lessons_learned.md          # Reflections on challenges, solutions, and future improvements
├── simulations/                    # Scripts or guides for simulating attacks for testing
│   ├── windows/
│   │   └── execute_persistence_technique.ps1 # Example simulation script
│   └── linux/
│       └── simulate_c2_beacon.sh # Example simulation script
└── README.md    # Main project README (can link to docs/README.md)
```