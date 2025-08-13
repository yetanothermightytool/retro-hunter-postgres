#!/usr/bin/env python3
import os
import re
import argparse
from datetime import datetime
from Registry import Registry
import psycopg2
from dotenv import load_dotenv

load_dotenv(dotenv_path=".env.local")

# Registry key patterns to be scanned
KEY_PATTERNS = [
   # ---------------------- Code Injection / Execution Hijacking ----------------------
   r".*\\AppCertDlls$",
   r".*\\AppInit_DLLs$",
   r".*\\LoadAppInit_DLLs$",
   r".*\\KnownDlls$",
   r".*\\Image File Execution Options\\.*",
   r".*\\SilentProcessExit\\.*",
   r".*\\Session Manager\\KnownDLLs$",

   # ---------------------- Admin, Hacker & Red Team Tools ----------------------
   r".*\\Software\\Sysinternals\\.*",
   r".*\\Software\\ProcessHacker\\.*",
   r".*\\Software\\NirSoft\\.*",
   r".*\\Software\\Microsoft\\Windbg\\.*",
   r".*\\Software\\OllyDbg\\.*",

   # ---------------------- Known Malware / Threat Actor Artefacts ----------------------
   r".*\\Explorer\\Advanced\\Hidden$",
   r".*\\Software\\Classes\\mscfile\\shell\\open\\command$",
   r".*\\Control\\SafeBoot\\.*",
   r".*\\Microsoft\\Windows\\CurrentVersion\\ShellCompatibility\\InboxApp$",
   r".*\\Software\\Classes\\.msc\\.*",
   r".*\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell$",

   # ---------------------- ASEPs: Per-user ----------------------
   r".*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run$",
   r".*\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce$",
   r".*\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx$",
   r".*\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run$",
   r".*\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce$",
   r".*\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\(Load|Run)$",
   r".*\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell$",
   # Terminal Server Install (per-user context)
   r".*\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Terminal Server\\Install\\Software\\Microsoft\\Windows\\CurrentVersion\\Run$",
   r".*\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Terminal Server\\Install\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce$",
   r".*\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Terminal Server\\Install\\Software\\Microsoft\\Windows\\CurrentVersion\\RunonceEx$",

   # ---------------------- ASEPs: System-wide ----------------------
   r".*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run$",
   r".*\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce$",
   r".*\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx$",
   r".*\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run$",
   r".*\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce$",
   r".*\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx$",
   # Terminal Server Install (system-wide context)
   r".*\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Terminal Server\\Install\\Software\\Microsoft\\Windows\\CurrentVersion\\Run$",
   r".*\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Terminal Server\\Install\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce$",
   r".*\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Terminal Server\\Install\\Software\\Microsoft\\Windows\\CurrentVersion\\RunonceEx$",
   # Group Policy controlled Run
   r".*\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run$",

   # ---------------------- RunServices (service startup at boot) ----------------------
   r".*\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServices$",
   r".*\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce$",
   # Optional: 32-bit view under Wow6432Node
   r".*\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunServices$",
   r".*\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce$",

   # ---------------------- Boot Execute / Session Manager (additional keys) ----------------------
   r".*\\System\\CurrentControlSet\\Control\\Session Manager\\BootExecute$",
   r".*\\System\\CurrentControlSet\\Control\\Session Manager\\Execute$",
   r".*\\System\\CurrentControlSet\\Control\\Session Manager\\S0InitialCommand$",
   r".*\\System\\CurrentControlSet\\Control\\Session Manager\\SetupExecute$",
   r".*\\System\\CurrentControlSet\\Control\\ServiceControlManagerExtension$",
   r".*\\Winlogon\\Userinit$",
   r".*\\Winlogon\\Shell$",
   r".*\\Session Manager\\PendingFileRenameOperations$",
   r".*\\Control\\Session Manager\\BootExecute$",

   # ---------------------- Startup folder path resolution in Registry ----------------------
   r".*\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders$",
   r".*\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders$",
   r".*\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders$",
   r".*\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders$",

   # ---------------------- Network / Remote Access Artefacts ----------------------
   r".*\\Microsoft\\Terminal Server Client\\Servers\\.*",
   r".*\\Network\\Connections\\Pbk$",
   r".*\\Internet Settings$",
   r".*\\Tcpip\\Parameters\\Interfaces\\.*",
   r".*\\NetworkList\\Profiles\\.*",

   # ---------------------- User Activity / Forensic Artefacts ----------------------
   r".*\\UserAssist\\.*",
   r".*\\Explorer\\RecentDocs$",
   r".*\\TypedPaths$",
   r".*\\TypedURLs$",
   r".*\\ComDlg32\\LastVisitedPidlMRU$",
   r".*\\Windows\\CurrentVersion\\Explorer\\RunMRU$",
   r".*\\Windows\\PowerShell\\.*\\ConsoleHost_history$",

   # ---------------------- Services & Drivers ----------------------
   r".*\\Services\\.*",

   # ---------------------- Defensive Evasion / Security Config ----------------------
   r".*\\Windows Defender\\.*",
   r".*\\AeDebug$",

   # ---------------------- Miscellaneous ----------------------
   r".*\\MountPoints2\\.*",
   r".*\\Windows\\CurrentVersion\\Uninstall\\.*",
]

# Registry hives to scan
HIVES = {
   "SYSTEM": r"Windows/System32/config/SYSTEM",
   "SOFTWARE": r"Windows/System32/config/SOFTWARE",
   "NTUSER": r"Users/{user}/NTUSER.DAT",
}

def init_pg():
   conn = psycopg2.connect(
       host=os.getenv("POSTGRES_HOST", "localhost"),
       port=os.getenv("POSTGRES_PORT", 5432),
       dbname=os.getenv("POSTGRES_DB"),
       user=os.getenv("POSTGRES_USER"),
       password=os.getenv("POSTGRES_PASSWORD")
   )
   cur = conn.cursor()
   cur.execute("""
       CREATE TABLE IF NOT EXISTS registry_scan (
           id SERIAL PRIMARY KEY,
           hostname TEXT,
           restorepoint_id TEXT,
           rp_timestamp TEXT,
           rp_status TEXT,
           hive TEXT,
           key_path TEXT,
           value_name TEXT,
           value_data TEXT,
           last_written TEXT
       )
   """)
   cur.execute("""
       CREATE UNIQUE INDEX IF NOT EXISTS idx_unique_registry_entry
       ON registry_scan(hostname, restorepoint_id, hive, key_path, value_name, value_data)
   """)
   conn.commit()
   return conn, cur

def match_interesting_key(key_path):
   for pattern in KEY_PATTERNS:
       if re.search(pattern, key_path, re.IGNORECASE):
           return True
   return False

def parse_hive(hive_path, hive_name, hostname, restorepoint_id, rp_timestamp, rp_status):
   if not os.path.exists(hive_path):
       return []

   results = []

   def walk_keys(key):
       hits = []
       full_path = key.path()
       if match_interesting_key(full_path):
           last_written = key.timestamp().isoformat() if key.timestamp() else ""
           for val in key.values():
               val_name = val.name()
               try:
                   val_data = str(val.value())
               except Exception:
                   val_data = "<unreadable>"

               if "Services" in full_path and ".exe" not in val_data.lower():
                   continue

               hits.append((
                   hostname, restorepoint_id, rp_timestamp, rp_status,
                   hive_name, full_path, val_name, val_data, last_written
               ))
       for subkey in key.subkeys():
           hits.extend(walk_keys(subkey))
       return hits

   try:
       reg = Registry.Registry(hive_path)
       results = walk_keys(reg.root())
   except Exception as e:
       print(f"⚠️ Failed to parse hive {hive_path}: {e}")

   return results

def parse_all_hives(mount_path, hostname, restorepoint_id, rp_timestamp, rp_status):
   all_hits = []
   for hive, rel_path in HIVES.items():
       if "{user}" in rel_path:
           users_dir = os.path.join(mount_path, "Users")
           if not os.path.isdir(users_dir):
               continue
           for user in os.listdir(users_dir):
               user_path = os.path.join(users_dir, user)
               hive_path = os.path.join(user_path, "NTUSER.DAT")
               if os.path.isfile(hive_path):
                   hits = parse_hive(hive_path, f"NTUSER ({user})", hostname, restorepoint_id, rp_timestamp, rp_status)
                   all_hits.extend(hits)
       else:
           hive_path = os.path.join(mount_path, rel_path)
           hits = parse_hive(hive_path, hive, hostname, restorepoint_id, rp_timestamp, rp_status)
           all_hits.extend(hits)
   return all_hits

def store_hits_pg(cur, conn, hits):
   inserted = 0
   for hit in hits:
       try:
           cur.execute("""
               INSERT INTO registry_scan (
                   hostname, restorepoint_id, rp_timestamp, rp_status,
                   hive, key_path, value_name, value_data, last_written
               ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
               ON CONFLICT DO NOTHING
           """, hit)
           if cur.rowcount > 0:
               inserted += 1
       except Exception as e:
           print(f"⚠️ Error inserting hit: {e}")
   conn.commit()
   print(f"✅ {inserted} new registry entries saved.")

def parse_args():
   parser = argparse.ArgumentParser(description="Parse Windows Registry hives for security-relevant keys")
   parser.add_argument("--mount", required=True, help="Mounted Windows volume path")
   parser.add_argument("--hostname", required=True, help="Hostname to tag")
   parser.add_argument("--restorepoint-id", required=True, help="Restore point ID")
   parser.add_argument("--rp-timestamp", required=True, help="Restore point timestamp (ISO format)")
   parser.add_argument("--rp-status", required=True, help="Restore point malware status")
   return parser.parse_args()

def main():
   args = parse_args()
   print(f"🔍 Scanning Registry hives in {args.mount}")
   conn, cur = init_pg()
   hits = parse_all_hives(args.mount, args.hostname, args.restorepoint_id, args.rp_timestamp, args.rp_status)
   print(f"✅ Found {len(hits)} interesting registry entries.")
   store_hits_pg(cur, conn, hits)
   cur.close()
   conn.close()

if __name__ == "__main__":
   main()
