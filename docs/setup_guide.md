# Host Agents
Artemis agent works by collecting relevant security events from the host machines and sending them to the Artemis 
server.
For this to work, the host machines need to be configured to log these events with the relevant data sources.

## Setting up and Configuring Data Sources

### *Windows Host*

**Configuring Windows Event Logging by tweaking Group Policy Setting**

Step-1: Open Group Policy Editor (gpedit.msc).

Step-2: Enable Audit Process Creation.

- Computer Configuration → Policies → Windows Settings → Security Settings → Advanced Audit Policy Configuration → 
  System Audit Policies - Local Group Policy Object → Detailed Tracking → Audit Process Creation → Turn on Success
- Computer Configuration → Administrative Templates → System → Audit Process Creation → 
  Enable ‘Include command line in process creation events’

Step-3: Update Group Policy settings by running the command `gpupdate /force` from the Command Prompt.

**Configuring Sysmon**

&nbsp;&nbsp;&nbsp;&nbsp;Step-1: Download Sysmon from the official [link](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) and extract the contents.

&nbsp;&nbsp;&nbsp;&nbsp;Step-2: Create a Sysmon configuration XML file, preferably in the same directory as Sysmon. 
The configuration file used for the lab setup is available on [sysmon_config.xml](../agent/windows/sysmon_config.xml).

&nbsp;&nbsp;&nbsp;&nbsp;Step-3: Open Command Prompt, navigate to the folder where Sysmon is downloaded to and 
install it using the command `sysmon64.exe -i config.xml`.

### *Linux Host*

**Configuring auditd to log Process Creation**

&nbsp;&nbsp;&nbsp;&nbsp;Step-1: Open a Terminal and install audit daemon and plugins using the command `sudo apt install auditd audispd-plugins -y`.

&nbsp;&nbsp;&nbsp;&nbsp;Step-2: Configure auditd rules by adding the following lines to `/etc/audit/rules.d/audit.rules`

```
## Audit process execution
-a always,exit -S execve,execveat -k process_exec
```

&nbsp;&nbsp;&nbsp;&nbsp;Step-3: Load the new rules by executing the command `sudo auditctl -R /etc/audit/rules.d/audit.rules`.

&nbsp;&nbsp;&nbsp;&nbsp;Step-4: Restart the auditd service: `sudo systemctl restart auditd`.

---