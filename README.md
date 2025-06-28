# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/Bruk-CyberTech/Threat-Hunting-and-Security-Operations/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched the DeviceFileEvents table for ANY file that had the string "tor" in it and discovered what looks like the user "employeex" downloaded a tor installer, did something that resulted in many tor-related files being copied to the desktop and the creation of a file called I "tor-shopping-list.txt" on the desktop. These events began at: 2025-06-28T02:33:14.0483092Z.

**Query used to locate events:**

```kql
DeviceFileEvents
|where DeviceName =="bruk-threat-hun"
|where InitiatingProcessAccountName =="employeex"
|where FileName contains "tor"
|order by Timestamp desc
|project Timestamp, DeviceName,ActionType, FileName, FolderPath, SHA256, account= InitiatingProcessAccountName

```
![image](https://github.com/user-attachments/assets/ce3c8b04-6bf0-4064-b397-de12928492b8)


---

### 2. Searched the `DeviceProcessEvents` Table

Searched the DeviceProcessEvents table for any ProcessCommandLine that contained the string “tor-browser-windows-x86_64-portable-14.5.4.exe /s” Based on the logs returned, at 2025-06-28T02:33:14.0483092Z, “employeex” on the “bruk-threat-hun” device ran the file “tor-browser-windows-x86_64-portable-14.5.4.exe /s” from their Downloads folder, using a command that triggered a silent installation. 

**Query used to locate event:**

```kql

DeviceProcessEvents
|where DeviceName == "bruk-threat-hun"
|where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.4.exe"
|project Timestamp, DeviceName,AccountName,ActionType, FileName, FolderPath, SHA256,ProcessCommandLine

```
![image](https://github.com/user-attachments/assets/4577a906-2f7a-438d-ad88-4039f945859f)



---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "employeex" actually opened
the tor browser. There was evidence that they did open it at 2025-06-28T02:33:10.8188514Z.
There were several other instances of firefox.exe (tor) as well as tor.exe opened afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName =="bruk-threat-hun"
|where FileName has_any ("tor.exe", "firefox.exe", "start-tor-browser.exe")
|project Timestamp, DeviceName,AccountName,ActionType, FileName, FolderPath, SHA256,ProcessCommandLine
|order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/b13707ae-8c2d-4081-a381-2b521d3a0d8f">

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports.On June 27, 2025, at 7:34 PM, a program called "firefox.exe", located in the Tor Browser folder on the desktop of user "EmployeeX", successfully made a network connection to the IP address 127.0.0.1 (which refers to the same computer). This activity happened on the device named "bruk-threat-hun". There were other connections as well. 
Query used to locate events:


**Query used to locate events:**

```kql
DeviceNetworkEvents
|where DeviceName == "bruk-threat-hun"
|where InitiatingProcessAccountName != "system"
|where RemotePort in ( 9001, 9030, 9040, 9050, 9051, 9150 )
|project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
|order by Timestamp desc

```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/87a02b5b-7d12-4f53-9255-f5e750d0e3cb">

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer  (Silent Install)

- **Timestamp:** `2025-06-27T19:30:17`
- **Event:**  The user "EmployeeX" executed the Tor Browser portable installer using a silent command.
- **Action:** Silent installation of the Tor Browser initiated.
- **File Path:** `C:\Users\EmployeeX\Downloads\tor-browser-windows-x86_64-portable-14.5.4.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-06-27T19:32:36`
- **Event:**  The same installer was executed again, possibly to complete or retry the extraction
- **Action:** Re-launch of the silent installer.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.1.exe /S`
- **File Path:** `C:\Users\EmployeeX\Downloads\tor-browser-windows-x86_64-portable-14.5.4.exe`

### 3.  Application Launch - Tor Browser Main UI (firefox.exe)

- **Timestamp:** ` 2025-06-27T19:33:10`
- **Event**:**The user launched the Tor Browser using its Firefox-based front-end.
- **Action:** Launch of Tor Browser main application. 'firefox.exe'
- **File Path:** `C:\Users\EmployeeX\Desktop\Tor Browser\Browser\firefox.exe`
 
### 4. Network Connection - TOR Network

- **Timestamp:** `2025-06-27T19:33:47`
- **Event:** A network connection to IP `127.0.0.1` on port `9001` by user "employee" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2024-11-08T22:18:08Z` - Connected to `194.164.169.85` on port `443`.
  - `2024-11-08T22:18:16Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2025-06-27T19:33:17 to 19:33:18`
- **Event:** The user "employee" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\employee\Desktop\tor-shopping-list.txt`

---

## Summary

The user "employee" on the "threat-hunt-lab" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-lab` by the user `employee`. The device was isolated, and the user's direct manager was notified.

---
