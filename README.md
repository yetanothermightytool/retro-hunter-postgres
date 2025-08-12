# Retro Hunter - PostgresSQL 🕵🏾‍♀️
**Security Scanner & Threat Audit Tool** for Veeam Backup & Replication Restore Points using the Veeam Data Integration API.

## 🛡️Find Threats in Your Backups – With Retro Hunter
Imagine you’re responsible for your company’s security. You have backups. You trust them. But what if malware or suspicious files are hiding right now or were silently active weeks ago? Wouldn’t it be great to look inside your backups, like a time machine, and search for threats?

That’s exactly what Retro Hunter does!
It connects directly to your Veeam backups and scans files from past restore points for signs of malware, hacked binaries, and other suspicious behavior. And the best part: it comes with a beautiful, easy-to-use dashboard that shows you everything.

![alt text](https://github.com/yetanothermightytool/retro-hunter/blob/main/Images/retro-hunter.png)

Retro Hunter is a lightweight Python-based toolkit that scans Veeam Backup & Replication restore points for malware, suspicious binaries, and unusual patterns. It allows you to investigate historical restore points and perform regular scans over time. By integrating with threat intelligence sources like MalwareBazaar, it continuously checks known file hashes and monitors the scanning results.

## ✅ Key Features
- Search for Veeam backups from a specific host or Veeam Backup Repository
- Mounts the manually selected backup via the Veeam Data Integration API
- Mounts the latest restore point from all supported platforms from a Veeam Backup Repository
- Scans mounted Veeam restore points
- Saves useful metadata from the presented files
- Parallelized scanning using Python’s multiprocessing for fast performance
- Tracks file changes across restore points (hash or size drift)
- Detects known malware using hash lookups from MalwareBazaar
- Identifies out-of-place LOLBAS (Living Off the Land Binaries and Scripts)
- Optionally applies YARA rules to selected file types during scan
- Optionally scans the Windows Eventlog for specific event-ids (Security/PowerShell)
- Optionally scans specific Windows Registry Hives
- Displays findings in a Streamlit dashboard
- Uses PostgreSQL as the database

## 🚀 Quickstart (tl;dr)
Run the setup script, and start scanning! Execute `setup.sh` with the path to your `malwarebazaar.csv` file to initialize the environment and databases. Once done, you can use `retro-hunter.py` to analyze mounted restore points for malware, LOLBAS, and YARA hits, or to index all executables and scripts. Finally, open the dashboard at https://<your-hostname>:8501 to explore the results.

**Important** You must add the Linux server on which this script is executed to the [backup infrastructure](https://helpcenter.veeam.com/docs/backup/vsphere/add_linux_server.html).

**Tested on UBUNTU 24.04**

Something missing? Check the [Coming Soon section](#coming-soon).

## ⚙️ Setup Process
The setup process is simplified with the setup.sh script. You only need to download the malwarebazaar.csv file (See more in the [Technical Details of the Scripts](#database) and run the script on your Linux host. You will be asked for the Veeam Backup & Replication Server hostname, REST API user, and a password during the setup. The password will be securely encrypted and stored using Fernet.

```bash
./setup.sh /path/to/malwarebazaar.csv retro-hunter
```

## 🐳 Docker Support
A minimal Docker setup is provided to run the Streamlit dashboard and the PostgreSQL database as a container.

## 🛠️ Technical Details of the Scripts
## Version Information
~~~~
Version: 2.1 (Aug 5 2025)
Requires: Veeam Backup & Replication v12.3.1 & Linux & Python 3.1+
Author: Stephan "Steve" Herzig
~~~~

## Prerequisites
Some preparations are required for this script to run. 

### Veeam Backup & Replication
- You must add the Linux server on which this script is executed to the [backup infrastructure](https://helpcenter.veeam.com/docs/backup/vsphere/add_linux_server.html).
- Create a separate user for REST API access. The user must be assigned the “Veeam Backup Administrator” role.

### Python Modules
The following Python modules are not part of the standard library and must be installed separately using pip. A requirements.txt contains the necessary modules.
- requests
- cryptography (for cryptography.fernet.Fernet)
- colorama
- yara (usually installed via yara-python)
- python-evtx for Windows Event Log scanning 
- and more for the Docker containers (requirements.txt)

## YARA Rules
Save additional YARA rule files in the script folder directory yara_rules. (File extensions .yar and .yara). A sample rule is stored in the yara_rules directory.

### YARA Rules Generator
The Streamlit Dashboard includes a YARA rule generator that creates rules based on stored executables with high entropy and PE metadata.

## Database Content
The malwarebazaar table in badfiles.db contains the SHA256 values of the malware files. Download the complete [data dump](https://bazaar.abuse.ch/export/#csv) and unzip the CSV file as malwarebazaar.csv to the folder where the setup.sh script is stored. The setup.sh script will import the values into the database.

## Retro Hunter Python Script
### Script Parameters
The following parameters must be passed to the script

- `--host2scan`
Hostname for which the backups must be presented.
- `--repo2scan`
Repository name for which the hosts and restore points are retreved. Can be combined with --all.
- `--all`
_(optional)_ Scans the latest restore point of all valid hosts in the specified repository. Recommended to use with --iscsi for better performance.
Supported platforms are VMware and Hyper-V.
- `--scan`
Triggers the malware and threat detection scan by executing the scanner.py script after a restore point has been mounted.
- `--store`
Collects the metadata for all relevant binary files by executing the store.py script after a restore point has been mounted.
- `--maxhosts`
_(optional)_ The maximum number of hosts to be scanned in parallel when using --all. (Default 1)
- `--workers`
_(optional)_ The number of workers to use for the scanning process. (Default 4)
- `--iscsi`
_(optional)_ Present the backups using iSCSI. Only filesystems with the NTFS, ext4 and xfs filesystem can be scanned.
- `--yaramode`
_(optional)_ YARA scan mode - off (default), all, suspicious (scans only files that show indicators of compromise), content (Targets commont document/text files to detecte sensitive data patterns (e.g. PII, credentials), highentropy 
- `--evtscan`
_(optional)_ Enables scanning of Windows Event Logs 
- `--evtlogs`
_(optional)_ Comma-separated list of EVTX log files to scan
- `--days`
_(optional)_ Limit EVTX parsing to events within N days before restore point timestamp
- `--regscan`
_(optional)_ Enables scanning of the Windows Registry **🔴 NEW**

### Examples
Some examples of how the script can be executed.

Scan host win-server-01. Restore points are presented using iSCSI.
```bash
sudo ./retro-hunter.py --host2scan win-server-01 --iscsi --scan
```
Scan the latest restore point of all suppored hosts from Veeam Repository "Repository 01". Triggers a YARA scan, when a suspicious file is found. Restore points are presented using iSCSI.
```bash
sudo ./retro-hunter.py --repo2scan "Repository 01" --yaramode suspicious --iscsi --scan
```

## Retro Hunter Streamlit Dashboard
✅ Key Metrics (Top 5 KPIs):
| Metric  | Description |
| ------------- | ------------- |
| 🦠 Malware Matches  | Total number of files matching known malware hashes|
| 🛠️ LOLBAS Hit | Files flagged by LOLBAS rule matches |
| 🔬 YARA Matches | Files identified via YARA rules |
| 📂 Total Files | Number of indexed files |
| 🌀 Multi-use Hashes | SHA256 hashes that appear with multiple filenames (possible masquerading) |
| 🛑 High Severity Events | Number of critical security-related events (e.g., policy changes, log clears and more) |
| ⚠️ Medium to High Events | Number of optentially suspicious events requiringfurther review |


📊 Table Overview
| Table  | Description |
| ------------- | ------------- |
| 🐞 Malware Hash Matches | Displays files from the backup that match known malware hashes (e.g. from MalwareBazaar). Helps identify known threats |
| 🔍 Scan Findings | Results from YARA or LOLBAS scans. Includes detection labels, scan timestamps, and affected files |
| 💣 Large Executables > 50MB | Shows .exe files larger than 50MB, which may indicate suspicious payloads or packers |
| 📁 Suspicious EXEs in AppData | Lists executables located in AppData folders – commonly abused by malware for persistence or evasion |
| 📂 Scripts in Temp/Download Directories | Detects script files (e.g., .ps1, .sh, .bat) in temporary or download paths – often used for staging attacks |
| 🌀 Multi-use Hashes (Same SHA256, multiple filenames) | Highlights SHA-256 hashes used with different filenames. May indicate renamed or disguised malware |
| ⚙️ System Process Names Outside System32 | Known system process names (e.g., svchost.exe, lsass.exe) found outside trusted paths like System32. Strong indicator of abuse or masquerading |
| 🧬 Suspicious IFEO Debuggers (Registry Scan) | Description coming soon|  **🔴 NEW** |
| 🧠 High Entropy Files in Suspicious Paths | Identifies files with high entropy (>7.5), indicating possible encryption or obfuscation, located in suspicious directories |
| 📑 Windows Event Log Entries | Parsed entries from Windows Event Log files (Security & PowerShell) for forensic and threat analysis |
| 🧬 High-Entropy Executables with Recent PE Timestamps | Executable files with high entropy (>= 7.59) and suspicious Portable Executable attributes|

## The Scripts
### Scanning Process Details (scanner.py)
The following folders are excluded from the scan process. You can adjust the list using the existing DEFAULT_EXCLUDES variable.

- **Windows\\WinSxS**
- **Windows\\Temp**
- **Windows\\SysWOW64**
- **Windows\\System32\\DriverStore**
- **Windows\\Servicing**
- **ProgramData\\Microsoft\\Windows Defender**
- **ProgramData\\Microsoft\\Windows Defender\\Platform**
- **System Volume Information**
- **Recovery**
- **Windows\\Logs**
- **Windows\\SoftwareDistribution\\Download**
- **Windows\\Prefetch**
- **Program Files\\Common Files\\Microsoft Shared**
- **Windows\\Microsoft.NET\\Framework64**
- **$Recycle.Bin**

### scanner.py Parameters
The Data Integration API script is not using all the available scanner.py parameters. This can be adjusted if necessary.
- Mount			Path to the mounted backup filesystem

Optional Parameters
- `--Filetypes`
_(optional)_ Comma-separated list of file extensions (e.g., .exe,.dll)")
- `--Maxsize`
_(optional)_ Maximum file size in MB
- `--Exclude`
_(optional)_ Experimental Comma-separated list of directories to exclude (partial paths)
- `--CSV`
_(optional)_ Save results to this CSV file
- `--Verbose`
_(optional)_ Print all scanned files, not just matches
- `--Logfile`
_(optional)_ Path to logfile for matches (might get removed)
- `--yara`
_(optional)_ YARA scan mode (off, all, suspicious, content)

## store.py script details
This script scans the mounted file system and collects detailed metadata for selected files (DEFAULT_BINARY_EXTS list or --filetypes is used). It calculates a SHA-256 hash for each file and stores all data in a local SQLite database. If the database does not exist, it is automatically created during the first run. The metadata stored includes file name, path, size, timestamps, extension, file type, and whether the file is executable. Each entry is tagged with a hostname, restore point ID, and timestamp, making later comparisons across backups possible.
The script supports parallel processing and can speed up scanning using multiple CPU cores. Filters can be applied to limit which files are scanned: only specific file types (like .exe or .dll), a maximum file size, and folders to exclude. 
The script extracts key information for each file that matches the filters and calculates its SHA-256 hash. All collected data is inserted into the database, unless an entry with the same hostname and hash already exists.

### File Type Detection (Simple explanation)
The script detects files based on their extensions:
- Executables: .exe, .dll, .bin, .sh, etc. 
- Scripts: .py, .js, .ps1, .bat 
- Images: .jpg, .png, .gif, etc. 
- Documents: .pdf, .docx, .txt, etc. 
- Archives: .zip, .tar, .7z, etc.
If a file doesn’t match known types, it is labeled "other".

### Entropy Calculation
Entropy is calculated using the Shannon entropy formula, based on the distribution of byte values in the file. The script reads the full content of each file and computes how evenly the byte values (0–255) are distributed, which reflects the randomness of the data. Highly random content is typical for encrypted, packed, or obfuscated files—techniques often used by malware to avoid detection.
When such high-entropy files are found in directories like AppData, ProgramData, Temp, Public, Downloads, or Recycle.Bin, they are flagged as potentially suspicious. These locations are frequently abused by attackers to stage or hide payloads, since they are writable and often excluded from routine checks. By correlating entropy levels with file system paths, the dashboard view aims to surface files that deserve further analysis, even if they have not been flagged by signature-based scanners.

### Entropy Classification Range
| Entropy Range | Description                                                                 |
|---------------|-----------------------------------------------------------------------------|
| 0.0 – 3.5     | Very low entropy – likely plain text, config files, or uncompressed data.  |
| 3.5 – 6.5     | Medium entropy – common for standard executables, DLLs, scripts, etc.      |
| 6.5 – 7.5     | Elevated entropy – may indicate mild compression or some obfuscation.      |
| > 7.5         | High entropy – potentially packed, encrypted, or malicious (e.g., malware).|'

For executable files with high entropy (>= 7.5), store.py automatically extracts additional metadata, including file type signatures (Magic) and Portable Executable (PE) attributes to support deeper malware analysis. It helps detect packed malware, malware droppers with recent compilation dates, and potentially unwanted programs. The results are displayed in the dashboard. (Entropy >= 7.9 and PE Timestamp > 2024-06-15)

### Argument Description
- `--mount`
_(mandatory)_ Root directory to scan
- `--hostname`
_(mandadory)_ The name of the host to which this data belongs
- `--restorepoint-id`
_(mandatory)_ The Veeam restore point ID
- `--rp-timestamp`
_(mandatory)_ Timestamp of the restore point
- `--Filetypes`
_(optional)_ Comma-separated file extensions to scan
- `--workers`
_(optional)_ Number of parallel worker processes to use (default: half of CPU cores)
- `--maxsize`
_(optional)_ Max file size in MB to include (e.g., skip huge ISO files)
- `--exclude`
_(optional)_ Comma-separated list of folder names to skip 
- `--db`
_(optional)_ SQLite DB path (default is file_index.db)

## event-parser.py script  
The event-parser.py script extracts and analyzes security-related events from Windows event logs. It focuses on a defined set of Event IDs (Security & PowerShell Event Log) known to indicate potential threats, policy changes, or suspicious PowerShell usage.

• Windows Security Event Ids (High Severity)
4618, 4649, 4719, 4765, 4766, 4794, 4897, 4964, 5124, 1102

The list is based on official Microsoft recommendations [Microsoft: Events to Monitor](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor).

• PowerShell Events Ids
800, 4104

These events are parsed, stored in the database, and visualized in the dashboard with severity classifications (High / Medium to High).

## Registry scanner script details
**coming soon**

## Retro Hunter PostgreSQL Cleanup Script (db-cleaner.py)

This script removes outdated entries from key PostgreSQL tables in your Retro Hunter environment:
• files
• scan_findings
• win_events
• registry (to be added)

### Options

Option Description
- `--days N` Delete entries older than N days (based on restore point timestamp fields)
- `--dry-run` Only show what would be deleted, nothing is removed
- `--clean-only` Only delete entries that are not flagged as malware/YARA/LOLBAS hits
- `--host HOSTNAME` Restrict cleanup to a specific hostname
### Examples

Dry-run: preview deletions older than 60 days
```bash
./db-cleaner.py --days 60 --dry-run
```
Fully delete old non-malicious data
```bash
./db-cleaner.py --days 90 --clean-only
```
Cleanup only for a specific host
```bash
./db-cleaner.py --days 30 --host WIN-VM1
```

## Coming Soon
- MCP Server (Model Context Protocol)

## Possible improvements
- Mark the scanned restore point as infected in Veeam Backup & Replication.
- And a few other nice things that I'm currently researching.

## Considerations and Limitations
- The scripts have been created and tested on Ubuntu 24.04 and Veeam Backup & Replication 12.3.1 and 12.3.2
- Only filesystems with the NTFS can be scanned when presenting the restore points using iSCSI
- When mounting NTFS disks, it’s important to know that Ubuntu (from version 24.04 and newer) uses the built-in ntfs3 kernel driver, which provides better performance and more stable access. In contrast, Rocky Linux and other RHEL-based systems usually rely on the older ntfs-3g driver through FUSE, which is slower because it runs in user space. This means that the way NTFS is handled can vary depending on the system. It is technically possible to upgrade Rocky Linux to a newer Kernel (5.15 or higher) to support the native ntfs3 driver. Mounting NTFS volumes works well when using the -t ntfs parameter, especially with iSCSI attached disks. FUSE is not working and there are currently no efforts to conduct further research in this area.

## Version History
- 2.2 ( )
   -
   -
   -
- 2.1 (August 5th 2025)
   - Windows Registry Scanner
- 2.0 (July 18th 2025)
   - PostgreSQL as a database.
- 1.3 (July 14th 2025)
  - The new YARA highentropy mode in scanner.py starts a scan using the stored YARA rules
  - The store.py script extracts file type signatures (Magic) and Portable Executable metadata for high-entropy executable file
  - Store.py script optimizations
  - Streamlit dasboard update to show the High-Entropy Executable files
  - YARA rule generator in the Streamlit dashboard on High-Entropy executable files
- 1.2 (July 8th 2025)
  - The scanner.py now also saves the SHA256 value for found LOLBAS files
  - Streamlit Dashboard date filter is now applied to all tables showing the restore point date
  - Streamlit Dashboard bugfixes (empty tables)
  - The store.py script now performs an entropy analysis (Shannon formula)
  - setup.sh script bugfixes
- 1.1 (June 26 2025)
  - repo2scan now supports Scale-Out Backup Repositories
  - Store specific Windows Event Log entries (Security & PowerShell Event log first)
  - Dashboard Update
- 1.0 (June 2025)
  - Initial version

## Disclaimer
**This script is not officially supported by Veeam Software. Use it at your own risk.**

Made with ❤️, fueled by 🍺, and powered by the **Veeam Data Integration API**.
Inspired by real-world needs, supported by a bit of AI.
