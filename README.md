# CTF Incident Response Report 

* Acme Corp – Advanced Persistent Threat: “Phantom Hackers”
* Analyst: Richard Edwards
* Platform: Microsoft Defender for Endpoint (MDE)
* Tools: KQL, Defender Tables, Endpoint Telemetry
* Date: 21, May 2025

## Executive Summary
This report outlines a successful threat hunt and incident investigation performed during a Capture The Flag (CTF) exercise. The simulated adversary, The Phantom Hackers, deployed a fake antivirus binary (BitSentinelCore.exe) to compromise host anthony-001 at Acme Corp. The campaign involved social engineering, stealthy persistence, keylogging, and data staging for exfiltration.
Through Microsoft Defender for Endpoint telemetry and custom KQL queries, all 8 forensic flags were identified and documented. The kill chain was reconstructed, the persistence techniques discovered, and root cause traced back to a compiler-based dropper.

## Table of Contents
1. Forensic Timeline
2. Incident Summary
3. Flag-by-Flag Breakdown
4. Recommendations
5. Appendix: Queries

## Forensic Timeline
###	Timestamp (UTC)	Event	Details
* 1.	2025-05-07T02:00:36.794406Z	- BitSentinelCore.exe written to disk	Dropped by csc.exe (C# compiler). Initial compromise.
* 2. 	2025-05-07T02:02:14Z	- BitSentinelCore.exe executed	Executed from explorer.exe, starts attack chain.
* 3. 	2025-05-07T02:02:14Z	- ThreatMetrics folder created	Possible malware staging directory.
* 4. 	2025-05-07T02:02:14Z	- cmd.exe launched	Executes scheduled task creation command.
* 5. 	2025-05-07T02:02:15Z	- schtasks.exe creates scheduled task "UpdateHealthTelemetry"	Ensures daily persistence.
* 6. 	2025-05-07T02:02:14Z	- Registry autorun key created	Enables execution of BitSentinelCore.exe on user login.
* 7. 2025-05-07T02:06:51Z	- Keylogger artifact systemreport.lnk dropped	Found in Recent folder, likely referencing keystroke logs.
* 8. 2025-05-07T02:48:47Z	- exfiltratedata.ps1 executed	Data staging via PowerShell script.
* 9. 2025-05-07T02:48:55Z	- employee-data.zip created by 7z.exe	Sensitive data compressed for exfiltration.

## Incident Summary
The attacker leveraged a social engineering vector to deliver a fake antivirus binary called BitSentinelCore.exe. This was compiled using csc.exe and written to disk on May 7, 2025. Upon execution, the binary set up multiple persistence mechanisms (registry and scheduled task), created keylogging artifacts, and initiated data collection through PowerShell and 7z.exe.
The malware avoided detection by:
* Using LOLBin execution (cmd.exe, schtasks.exe, PowerShell)
* Dropping in low-visibility locations (AppData, ProgramData)
* Faking legitimacy through benign-looking task names like "UpdateHealthTelemetry"
The investigation focused on:
* Identifying the root cause (csc.exe)
* Mapping the full malicious process chain
* Tracking persistence methods
* Discovering keylogger and exfiltration behavior

## Flag-by-Flag Breakdown with Queries

### Flag 1 – Fake Antivirus Program Name
Answer: BitSentinelCore.exe

```kql
// returned 11 results and BitSentinelCore.exe was found to be the Fake Antivirus Program name
DeviceProcessEvents
| where DeviceName contains "anthony"
| where ProcessRemoteSessionDeviceName == @"BUBBA"
| where FileName endswith ".exe"
| where FileName startswith "a" or FileName startswith "b" or FileName startswith "c"
| summarize take_any(*) by FileName
```
<img width="1388" alt="CTF -Artifact-flag1" src="https://github.com/user-attachments/assets/fcc1a1d2-c5b9-4f5b-beed-1e732a84f4df" />


### Flag 2 – Malicious File Written to Disk
Answer: Dropped by csc.exe 

```kql
//Flag 2 - query returned 1 result that shows csc.exe is responsible for dropping the malicious file into disk // Timestamp 2025-05-07T02:00:36.794406Z 
DeviceFileEvents
| where FileName == "BitSentinelCore.exe"
| project Timestamp, DeviceName, FolderPath, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| sort by Timestamp asc
```
<img width="1385" alt="CTF-Artifact-flag2" src="https://github.com/user-attachments/assets/b0d9f150-8851-41c3-aa73-49733b5d98df" />



### Flag 3 – Process Command Line of Malware
Answer: BitSentinelCore.exe execution

```kql
// Flag 3 - Command used to start up the program? = "BitSentinelCore.exe" 
DeviceProcessEvents
| where DeviceName contains "anthony"
| where FileName == "BitSentinelCore.exe"
| project Timestamp, DeviceName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc 
```

<img width="1383" alt="CTF-Artifact-flag3" src="https://github.com/user-attachments/assets/28c97e9f-c1a7-4ca1-b67a-5e72817e4d11" />



### Flag 4 – Keylogger Artifact
Answer: systemreport.lnk

```kql
// flag 4 - returns 6 folderpaths that contain .lnk extensions because the previous query led to a ThreatMetrics.lnk file. Curious about other '.lnk' files that were created around the time of the incident
// correct  Answer found to be filename "systemreport.lnk" at 2025-05-07T02:06:51.3594039Z
DeviceFileEvents
|where DeviceName contains "anthony"
| where FolderPath contains ".lnk"
| where ActionType in ("FileCreated", "FileWritten")
| project Timestamp, FileName, FolderPath, InitiatingProcessFileName, ActionType
| order by Timestamp asc
```

<img width="1388" alt="CTF-Artifact-flag4" src="https://github.com/user-attachments/assets/ccfa51d6-1a79-486a-b327-7fe35fe62c1e" />

Queries that led to the keylogger Artifact
<img width="1383" alt="CTF-Artifact-flag4-2" src="https://github.com/user-attachments/assets/a438ba62-a77b-46ce-9910-fbefba8da695" />



### Flag 5 – Registry Persistence
Answer: HKEY_CURRENT_USER\...\Microsoft\Windows\CurrentVersion\Run

```kql
// Flag 5 query - returned 1 item - RegistryValueData = "C:\ProgramData\BitSentinelCore.exe" and RegistryKey = "HKEY_CURRENT_USER\S-1-5-21-2009930472-1356288797-1940124928-500\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" - correct
DeviceRegistryEvents
| where DeviceName contains "anthony"
| where ActionType == "RegistryValueSet"
| where RegistryKey endswith @"\Run" or RegistryKey contains "CurrentVersion\\Run"
| project Timestamp, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName
| order by Timestamp asc
```

<img width="1345" alt="CTF-Artifact-flag5" src="https://github.com/user-attachments/assets/3514aff2-1c1f-4933-a6d0-008c33d14caf" />



### Flag 6 – Scheduled Task Persistence
Answer: UpdateHealthTelemetry

```kql
//Flag 6 query - returned "cmd.exe" /c schtasks /Create /SC DAILY /TN "UpdateHealthTelemetry" /TR "C:\ProgramData\BitSentinelCore.exe" /ST 14:00 
//Scheduled task created by anthony = UpdateHealthTelemetry
DeviceProcessEvents
| where DeviceName contains "anthony"
| where ProcessCommandLine contains "schtasks"
| where ProcessCommandLine contains "/Create"
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp asc
```

<img width="1348" alt="CTF-Artifact-flag6" src="https://github.com/user-attachments/assets/8d1396a1-c1e0-43ed-a270-343c3208a858" />



### Flag 7 – Malicious Process Chain
Answer: BitSentinelCore.exe -> cmd.exe -> schtasks.exe

```kql
// flag 7 - understanding the parent process which turned out to be : BitSentinelCore.exe -> cmd.exe -> schtasks.exe (BitSentinelCorewas launched via explorer.exe but BitSentinelCoreis the official start of the malicious process)
DeviceProcessEvents
| where DeviceName contains "anthony"
| where FileName in~ ("schtasks.exe", "cmd.exe", "BitSentinelCore", "explorer.exe")
| order by Timestamp asc
```

<img width="1382" alt="CTF-Artifact-flag7" src="https://github.com/user-attachments/assets/e20106b3-abd1-47dc-88ce-f54d0a520713" />



### Flag 8 – Initial Event Timestamp
Answer: 2025-05-07T02:00:36.794406Z (csc.exe wrote BitSentinelCore.exe)

```kql
//Flag 8 is asking for the Timestamp of the leading event that caused all the trouble
// csc.exe responsible for dropping the malicious file into disk - discovered in flag 2 
// At Timestamp 2025-05-07T02:00:36.794406Z (answer for flag 8)
DeviceFileEvents
| where FileName == "BitSentinelCore.exe"
| where InitiatingProcessFileName =~ "csc.exe"
| project Timestamp, DeviceName, FolderPath, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| sort by Timestamp asc
```

<img width="1379" alt="CTF-Artifact-flag8" src="https://github.com/user-attachments/assets/cbb22b1d-e978-4a23-b1ed-b5fd9800583e" />



## Recommendations
* Detect script compilation (csc.exe) in user space.
* Monitor for persistence techniques:
    * Autorun registry keys
    * Scheduled tasks with suspicious task names
* Alert on unsigned binaries executed from ProgramData or AppData
* Correlate .lnk creation in Recent folder with possible surveillance or keylogging
* Implement PowerShell transcription logging and anti-exfiltration controls

## Appendix: Queries
To support transparency and reproducibility, the exact queries used in each flag are documented above in Flag Breakdown. All queries were executed via Microsoft Defender for Endpoint’s Advanced Hunting console.

### Final Thoughts
This challenge mimicked a realistic and well-orchestrated APT campaign. The exercise demonstrated:
* The importance of telemetry correlation
* The value of persistence hunting via registry/schedule analysis
* The necessity of creative thinking and iterative KQL filtering
This report serves as a technical reference, a training artifact, and a portfolio showcase for incident response capability.
