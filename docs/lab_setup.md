The Artemis lab environment is set up in Azure within a dedicated Virtual Network using the 10.1.0.0/16 subnet for 
isolation. It consists of four virtual machines

- One **Kali Linux VM** to simulate a malicious attacker, used for executing defined threat techniques against the 
  agent VMs.
- One **Ubuntu Server 22.04 LTS VM** running the Artemis Linux agent.
- One **Windows Server 2022 VM** running the Artemis Windows agent.
- One **Ubuntu Server 22.04 LTS VM** hosting the Artemis server components (data ingestion, database, monitoring tools).

All VMs within the 10.1.0.0/16 subnet are configured to communicate with each other to facilitate testing and data 
transfer, while inbound access from external networks is strictly controlled via Network Security Groups.

<p align="center">
  <img src=images/Lab_Setup.jpg />
</p>
