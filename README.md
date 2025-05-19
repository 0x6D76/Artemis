# Artemis
#### Host-Based Threat Intelligence and Hunting Platform

## Objective
To build a custom, lightweight host-based agent for Windows and Linux that collects security-relevant data, sends it to 
a central server for aggregation, threat intelligence correlation, anomaly detection, rule-based detection, and provides
intuitive dashboards for threat hunting and monitoring. Includes capabilities for secure remote command execution for 
investigation and active response.

To know the current status of the development and functionalities implemented so far, check [Roadmap](docs/roadmap.md)

---

## Core Functionalities
- Security Monitoring
- Threat Detection
- Threat Hunting
- Threat Feed Integration
- Basic Remote Response

---

## Initial Scope and Data Sources
The platform will focus initially on detecting techniques related to,
1. **Execution:** Command and Scripting Interpreter
2. **Persistence:** Boot or Logon Autostart Execution
3. **Defense Evasion/Impact:** File System Interaction
4. **Credential Access:** Credentials from Password Stores
5. **Command and Control (C2):** Network Connections (focus on suspicious connections by processes)

The corresponding data sources identified are:

- **Windows:** Security Event Log (4688, 4624, 4697), Sysmon (1, 3, 7, 10, 11, 12, 13, 14, 23, 24), 
               PowerShell Operational Log (4104).
- **Linux:** `auditd` (syscalls `execve`/`execveat`, `creat`, `openat`, `write`, `unlinkat`, `renameat`, `linkat`, 
             `rmdir`, `connect`, `socket`, `sendto`, `recvfrom`), Syslog (`auth.log`, `cron.log`), 
              History files (optional initially).

---
## Setup Guide
The complete setup guide for the platform can be found in [SetupGuide](docs/setup_guide.md).