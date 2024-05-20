# Creating a SOC with Honeynet in Azure (Live Traffic)


## Introduction

In this project, I built a mini honeynet in Azure to monitor and analyze live traffic. By ingesting log data from various resources into a Log Analytics workspace and using Microsoft Sentinel, I created attack maps, triggered alerts, and generated incidents. The project involved measuring security metrics in an insecure environment over 24 hours, applying security controls to harden the environment, and then measuring the metrics again for another 24 hours to assess improvements. The metrics we focused on include:


## Metrics Generated
- SecurityEvent (Windows Event Logs)
- Syslog (Linux Event Logs)
- SecurityAlert (Log Analytics Alerts Triggered)
- SecurityIncident (Incidents created by Sentinel)
- AzureNetworkAnalytics_CL (Malicious Flows allowed into our honeynet)


## Architecture of the Lab
![Windows VM](https://github.com/boydjenkins18/Azure-SOC-Honeynet/assets/29837017/0bf8c7b0-a525-4e46-a0aa-8de798449c2c)

## Technologies, Regulations, and Azure Components
- Virtual Network (VNet)
- Network Security Group (NSG)
- Virtual Machines (2 Windows, 1 Linux)
- Log Analytics Workspace with KQL Queries
- Azure Key Vault
- Azure Storage Account
- Microsoft Sentinel
- Microsoft Defender for the Cloud
- Microsoft Remote Desktop
- CMD and Powershell
- NIST SP 800-53 r5
- NIST SP 800-61 r2


## Architecture Before Hardening / Security Controls
![Before](https://github.com/boydjenkins18/Azure-SOC-Honeynet/assets/29837017/71e70216-f057-4b4f-821c-8fa99c2eaad9)
<br><br>
For the "BEFORE" metrics, all resources were originally deployed, exposed to the internet. The Virtual Machines had both their Network Security Groups and built-in firewalls wide open, and all other resources are deployed with public endpoints visible to the Internet; aka, no use for Private Endpoints.

## Architecture After Hardening / Security Controls
![After](https://github.com/boydjenkins18/Azure-SOC-Honeynet/assets/29837017/1d47fab0-0205-4ae8-95f3-5c6af5b2b70b)
<br><br>
To improve the "AFTER" metrics, Network Security Groups were hardened by blocking ALL traffic with the exception of my admin workstation, and all other resources were protected by their built-in firewalls as well as Private Endpoint


## Attack Maps Before Hardening / Security Controls
NSG Malicious Allowed In
![nsg-malicious-allowed-in](https://github.com/boydjenkins18/Azure-SOC-Honeynet/assets/29837017/cc0c7895-dc6c-41f6-972e-3830a5432971)<br><br>
Windows RDP Authentication Failures
![windows-rdp-auth-fail](https://github.com/boydjenkins18/Azure-SOC-Honeynet/assets/29837017/54670dc1-8d46-4793-bf09-82cb3188d212)<br><br>
Linux SSH Authentication Failures
![linux-ssh-auth-fail](https://github.com/boydjenkins18/Azure-SOC-Honeynet/assets/29837017/55036932-31e0-49ab-851f-87944b032525)<br><br>
MS SQL Authentication Failures
![mssql-auth-fail](https://github.com/boydjenkins18/Azure-SOC-Honeynet/assets/29837017/dbc5d127-f96c-40f7-9916-7620870ab0b7)<br><br>


## Metrics Before Hardening / Security Controls

The following table shows the metrics we measured in our insecure environment for 24 hours:
Start Time 2024-05-18 15:05:45
Stop Time 2024-05-19 15:05:45

| Metric                   | Count
| ------------------------ | -----
| SecurityEvent            | 18966
| Syslog                   | 2297
| SecurityAlert            | 2
| SecurityIncident         | 173
| AzureNetworkAnalytics_CL | 1717


## Hardening Steps
The initial 24-hour study revealed that the lab was vulnerable to multiple threats due to its visibility on the public internet. To address these findings, I activated NIST SP 800-53 r4 within the compliance section of Microsoft Defender and focused on fulfilling the compliance standards associated with SC.7.*. Additional assessments for SC-7 - Boundary Protection.
<br>
![sc7](https://github.com/boydjenkins18/Azure-SOC-Honeynet/assets/29837017/fa7683a3-2084-433d-bed4-d4b698c946d7)


## Attack Maps Before Hardening / Security Controls

```All map queries actually returned no results due to no instances of malicious activity for the 24 hour period after hardening.```

## Metrics After Hardening / Security Controls

The following table shows the metrics we measured in our environment for another 24 hours, but after we have applied security controls:
Start Time 2024-05-19 19:02:17
Stop Time	2024-05-20 19:02:17

| Metric                   | Count
| ------------------------ | -----
| SecurityEvent            | 8575
| Syslog                   | 1
| SecurityAlert            | 0
| SecurityIncident         | 0
| AzureNetworkAnalytics_CL | 0


## Overall Improvement After Securing Environment

| Metric                   | Attackers Percentage
| ------------------------ | -----
| SecurityEvent            | -54.79%
| Syslog                   | -99.96%
| SecurityAlert            | -100%
| SecurityIncident         | -100%
| AzureNetworkAnalytics_CL | -100%

<br>

<details>
<summary> Utilizing NIST 800-61 r2 </summary>

For each simulated attack I then practiced incident response following NIST SP 800-61 r2.
<br><br>
![68747470733a2f2f692e696d6775722e636f6d2f365054473763306c2e706e67](https://github.com/boydjenkins18/Azure-SOC-Honeynet/assets/29837017/0336fb90-9423-4ad1-bde7-c058f43c20f6)<br><br>
Each organization will have policies related to an incident response that should be followed. This event is just a walkthrough for possible actions to take in the detection of malware on a workstation.

### Preparation
- The Azure lab was set up to ingest all of the logs into Log Analytics Workspace, Sentinel and Defender were configured, and alert rules were put in place.

### Detection & Analysis
- Malware has been detected on a workstation with the potential to compromise the confidentiality, integrity, or availability of the system and data.
- Assigned alert to an owner, set the severity to "High", and the status to "Active"
- Identified the primary user account of the system and all systems affected.
- A full scan of the system was conducted using up-to-date antivirus software to identify the malware.
- Verified the authenticity of the alert as a "True Positive".
- Sent notifications to appropriate personnel as required by the organization's communication policies.

### Containment, Eradication & Recovery
- The infected system and any additional systems infected by the malware were quarantined.
- If the malware was unable to be removed or the system sustained damage, the system would have been shut down and disconnected from the network.
- Depending on organizational policies the affected systems could be restored known clean state, such as a system image or a clean installation of the operating system and applications. Or an up-to-date anti-virus solution could be used to clean the systems.

### Post-Incident Activity
- In this simulated case, an employee had downloaded a game that contained malware.
- All information was gathered and analyzed to determine the root cause, extent of damage, and effectiveness of the response.
- Report disseminated to all stakeholders.
- Corrective actions are implemented to remediate the root cause.
- And a lessons-learned review of the incident was conducted.
</details>

<details>
  <summary>Incident Management Playbook for this Project</summary>
  https://github.com/boydjenkins18/Azure-SOC-Honeynet/blob/main/Incident%20Management%20Playbook%20for%20Azure%20SOC%20Project.docx
  
</details>
## Conclusion

In this project, a mini honeynet was constructed in Microsoft Azure and log sources were integrated into a Log Analytics workspace. Microsoft Sentinel was employed to trigger alerts and create incidents based on the ingested logs. Additionally, metrics were measured in the insecure environment before security controls were applied, and then again after implementing security measures. It is noteworthy that the number of security events and incidents were drastically reduced after the security controls were applied, demonstrating their effectiveness.

It is worth noting that if the resources within the network were heavily utilized by regular users, it is likely that more security events and alerts may have been generated within the 24-hour period following the implementation of the security controls.
