#!/usr/bin/env python3
import argparse
import json
import signal
import time
import os
import re
import subprocess
import requests
import socket
from dotenv import load_dotenv
from cryptography.fernet import Fernet
from dateutil import parser as dtparser
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from datetime import datetime
import psycopg2

# Load environment for DB
load_dotenv(dotenv_path=".env.local")

# Variables & disable self-signed certificate warning
timestamp   = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
API_VERSION = "1.3-rev1"
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Get password for REST API and SMB Access
def get_password():
   with open("encryption_key.key", "rb") as key_file:
       key = key_file.read()
   with open("encrypted_password.bin", "rb") as password_file:
       encrypted_password = password_file.read()
   return Fernet(key).decrypt(encrypted_password).decode()

def get_smb_password():
   with open("encryption_key.key", "rb") as key_file:
       key = key_file.read()
   with open("encrypted_smb_password.bin", "rb") as password_file:
       encrypted_password = password_file.read()
   return Fernet(key).decrypt(encrypted_password).decode()

# Load Scan Engines json file
def load_scan_engines():
   if not os.path.exists("scan-engines.json"):
       return []
   with open("scan-engines.json", "r") as f:
       data = json.load(f)
   engines = []
   for eng in data.get("engines", []):
       if os.path.exists(eng["path"]):
           engines.append(eng)
   return engines

# PostgreSQL DB Functions
def get_db_conn():
   return psycopg2.connect(
       dbname=os.getenv("POSTGRES_DB"),
       user=os.getenv("POSTGRES_USER"),
       password=os.getenv("POSTGRES_PASSWORD"),
       host=os.getenv("POSTGRES_HOST", "localhost"),
       port=os.getenv("POSTGRES_PORT", 5432),
   )

def init_db():
   conn = get_db_conn()
   cur = conn.cursor()
   cur.execute(
       """
       CREATE TABLE IF NOT EXISTS nas_scan_findings (
           id SERIAL PRIMARY KEY,
           share_name TEXT NOT NULL,
           restore_point_id TEXT,
           restore_point_time TEXT,
           mount_host TEXT,
           scan_engine TEXT NOT NULL,
           file_path TEXT,
           detection TEXT NOT NULL,
           scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
       )
       """
   )
   cur.execute("CREATE INDEX IF NOT EXISTS idx_nas_share_name ON nas_scan_findings(share_name)")
   cur.execute("CREATE INDEX IF NOT EXISTS idx_nas_restore_point_id ON nas_scan_findings(restore_point_id)")
   conn.commit()
   conn.close()

def write_nas_findings_to_db(findings, meta):
   if not findings:
       return 0
   conn = get_db_conn()
   cur = conn.cursor()
   for file_path, detection, engine_name in findings:
       cur.execute(
           """
           INSERT INTO nas_scan_findings (
               share_name,
               restore_point_id,
               restore_point_time,
               mount_host,
               scan_engine,
               file_path,
               detection
           ) VALUES (%s,%s,%s,%s,%s,%s,%s)
           """,
           (
               meta.get("share_name"),
               meta.get("restore_point_id"),
               meta.get("restore_point_time"),
               meta.get("mount_host"),
               engine_name,
               file_path,
               detection,
           ),
       )
   conn.commit()
   conn.close()
   return len(findings)

# Veeam REST API functions
def connect_veeam_rest_api(api_url, username, password):
   url = f"{api_url}/api/oauth2/token"
   headers = {
       "Content-Type": "application/x-www-form-urlencoded",
       "x-api-version": API_VERSION,
       "accept": "application/json",
   }
   data = {"grant_type": "password", "username": username, "password": password}
   response = requests.post(url, headers=headers, data=data, verify=False)
   response.raise_for_status()
   return response.json()["access_token"]

def get_veeam_rest_api(api_url, endpoint, token, params=None):
   url = f"{api_url}/api/{endpoint}"
   headers = {
       "accept": "application/json",
       "x-api-version": API_VERSION,
       "Authorization": f"Bearer {token}",
   }
   r = requests.get(url, headers=headers, params=params, verify=False)
   r.raise_for_status()
   return r.json()

def post_veeam_rest_api(api_url, endpoint, token, body):
   url = f"{api_url}/api/{endpoint}"
   headers = {
       "accept": "application/json",
       "x-api-version": API_VERSION,
       "Content-Type": "application/json",
       "Authorization": f"Bearer {token}",
   }
   r = requests.post(url, headers=headers, json=body, verify=False)
   r.raise_for_status()
   if r.content:
       return r.json()
   return {}

def post_logout(api_url, token):
   url = f"{api_url}/api/oauth2/logout"
   headers = {
       "accept": "application/json",
       "x-api-version": API_VERSION,
       "Authorization": f"Bearer {token}",
   }
   requests.post(url, headers=headers, verify=False)

def get_nas_restore_points(api_url, token, sharename, limit=10):
   params = {
       "skip": 0,
       "limit": limit,
       "orderColumn": "CreationTime",
       "orderAsc": "false",
       "platformNameFilter": "UnstructuredData",
       "nameFilter": f"*{sharename}*",
   }
   return get_veeam_rest_api(api_url, "v1/restorePoints", token, params)

def display_nas_restore_points(rp_response):
   data = rp_response.get("data", [])
   print("\n{:<5} {:<50} {:<25}".format("Id", "Name", "Creation Time"))
   print("-" * 90)
   for idx, rp in enumerate(data):
       name = rp.get("name", "<no-name>")
       creation_iso = rp.get("creationTime")
       try:
           creation_str = dtparser.isoparse(creation_iso).strftime("%Y-%m-%d %H:%M:%S")
       except Exception:
           creation_str = creation_iso or "unknown"
       print("{:<5} {:<50} {:<25}".format(idx, name, creation_str))

class TimeoutException(Exception):
   pass

def _timeout_handler(signum, frame):
   raise TimeoutException

def select_restore_point(num_items, timeout_seconds=30):
   signal.signal(signal.SIGALRM, _timeout_handler)
   print(f"\nYou have {timeout_seconds} seconds to select a restore point.")
   print("Default is 0 (latest).")
   signal.alarm(timeout_seconds)
   try:
       choice = input(f"Enter number (0-{num_items - 1}): ")
       signal.alarm(0)
   except TimeoutException:
       print("Timeout → using index 0.")
       return 0
   if not choice.isdigit():
       print("Invalid → index 0.")
       return 0
   idx = int(choice)
   if 0 <= idx < num_items:
       return idx
   print("Out of range → index 0.")
   return 0

def get_managed_server_id(api_url, token, mounthost):
   params = {"nameFilter": mounthost}
   resp = get_veeam_rest_api(api_url, "v1/backupInfrastructure/managedServers", token, params)
   data = resp.get("data", [])
   if not data:
       raise RuntimeError(f"No managed server matches '{mounthost}'.")
   return data[0].get("id")

def deep_contains_id(obj, target_id):
   if isinstance(obj, dict):
       for v in obj.values():
           if v == target_id:
               return True
           if deep_contains_id(v, target_id):
               return True
   elif isinstance(obj, list):
       for item in obj:
           if deep_contains_id(item, target_id):
               return True
   return False

def resolve_mount_server_id(api_url, token, managed_server_id):
   ms_list = get_veeam_rest_api(api_url, "v1/backupInfrastructure/mountServers", token)
   candidates = ms_list.get("data", [])
   matched = []
   for ms in candidates:
       ms_id = ms.get("id")
       detail = get_veeam_rest_api(api_url, f"v1/backupInfrastructure/mountServers/{ms_id}", token)
       if deep_contains_id(detail, managed_server_id):
           matched.append((ms_id, ms.get("type", "")))
   if not matched:
       raise RuntimeError("No mount server found.")
   win = [m for m in matched if m[1] == "Windows"]
   return win[0][0] if win else matched[0][0]

def start_instant_file_share_recovery(api_url, token, rp_id, mount_server_id, smb_user):
   payload = {
       "autoSelectMountServers": False,
       "restoreOptions": [
           {
               "restorePointId": rp_id,
               "mountServerId": mount_server_id,
               "permissions": {
                   "owner": "Administrator",
                   "permissionType": "AllowEveryone",
                   "permissionScope": [],
               },
           }
       ],
       "reason": "AV Scan",
   }
   return post_veeam_rest_api(api_url, "v1/restore/instantRecovery/unstructuredData", token, payload)

def stop_instant_file_share_recovery(api_url, token, session_id):
   url = f"{api_url}/api/v1/restore/instantRecovery/unstructuredData/{session_id}/unmount"
   headers = {
       "accept": "application/json",
       "x-api-version": API_VERSION,
       "Content-Type": "application/json",
       "Authorization": f"Bearer {token}",
   }
   requests.post(url, headers=headers, json={}, verify=False)

def try_extract_session_id(ir_response):
   if isinstance(ir_response, dict):
       if isinstance(ir_response.get("id"), str):
           return ir_response["id"]
       for v in ir_response.values():
           sid = try_extract_session_id(v)
           if sid:
               return sid
   elif isinstance(ir_response, list):
       for item in ir_response:
           sid = try_extract_session_id(item)
           if sid:
               return sid
   return None

def extract_production_share_name(ir_response):
   name_value = None

   # Find "name" recursively
   if isinstance(ir_response, dict):
       if isinstance(ir_response.get("name"), str):
           name_value = ir_response["name"]
       else:
           for v in ir_response.values():
               if isinstance(v, dict) and isinstance(v.get("name"), str):
                   name_value = v["name"]
                   break
               if isinstance(v, list):
                   for item in v:
                       if isinstance(item, dict) and isinstance(item.get("name"), str):
                           name_value = item["name"]
                           break

   if not name_value:
       return None, None

   # Strip leading slashes
   s = name_value.strip().lstrip("\\/")

   # Detect NFS export 
   if ":/" in s:
       server, export = s.split(":/", 1)
       export = "/" + export.lstrip("/")
       return server, export

   parts = s.split("\\")
   if len(parts) < 2:
       return None, None
   return parts[0], parts[1].rstrip("$")

def build_mountpoint(base, host, share):
   raw = f"{host}_{share}"
   name = re.sub(r"[^A-Za-z0-9._-]+", "_", raw) or "veeam_share"
   return os.path.join(base, name)

def normalize_file_path_for_db(raw_path, mountpoint):
  if not raw_path:
      return None
  raw_path = raw_path.strip()

  try:
      rel = os.path.relpath(raw_path, mountpoint)
      # If rel starts with "..", the file is not really inside this mountpoint
      if rel.startswith(".."):
          return raw_path
      # Normalize leading slashes/backslashes
      return rel.lstrip("/\\")
  except Exception:
      # Fallback: simple prefix strip
      if raw_path.startswith(mountpoint):
          return raw_path[len(mountpoint):].lstrip("/\\")
      return raw_path

def parse_thor_output(stdout, engine, mountpoint, findings):
  lines = stdout.splitlines()
  current = None

  for line in lines:
      line = line.strip()
      if not line:
          continue

      # Start of a new finding
      if line.startswith(("Warning", "Alert")):
          # Flush previous finding if complete
          if current and current.get("file") and (current.get("reason") or current.get("severity")):
              det_parts = []
              if current.get("severity"):
                  det_parts.append(current["severity"])
              if current.get("reason"):
                  det_parts.append(current["reason"])
              detection_text = " | ".join(det_parts)

              file_path = normalize_file_path_for_db(current.get("file"), mountpoint)
              findings.append((file_path, detection_text, engine["name"]))

          # Start new block
          current = {
              "severity": line,
              "file": None,
              "reason": None,
          }

      elif line.startswith("FILE:") and current is not None:
          val = line.split("FILE:", 1)[1].strip()
          # Only the path before EXT:
          if " EXT:" in val:
              val = val.split(" EXT:", 1)[0].strip()
          current["file"] = val

      elif line.startswith("REASON_") and current is not None:
          current["reason"] = line.split(":", 1)[1].strip()

  # Flush last block
  if current and current.get("file") and (current.get("reason") or current.get("severity")):
      det_parts = []
      if current.get("severity"):
          det_parts.append(current["severity"])
      if current.get("reason"):
          det_parts.append(current["reason"])
      detection_text = " | ".join(det_parts)

      file_path = normalize_file_path_for_db(current.get("file"), mountpoint)
      findings.append((file_path, detection_text, engine["name"]))

def run_scan_engine(engine, mountpoint, meta, findings):
  params = []
  has_placeholder = False
  for p in engine.get("params", []):
      if p == "{path}":
          params.append(mountpoint)
          has_placeholder = True
      else:
          params.append(p)
  if not has_placeholder:
      params.append(mountpoint)

  cmd = [engine["path"]] + params
  result = subprocess.run(cmd, capture_output=True, text=True)
  stdout = result.stdout

  print(f"\n🔍 {engine['name']} scan output")
  print(stdout)

  # THOR parsing
  if engine["name"].lower() == "thor":
      parse_thor_output(stdout, engine, mountpoint, findings)
      return

  # YARA parsing: "RULE file_path"
  if engine["name"].lower() == "yara":
      for line in stdout.splitlines():
          parts = line.strip().split(maxsplit=1)
          if len(parts) == 2:
              rule_name, file_path_raw = parts
              file_path = normalize_file_path_for_db(file_path_raw, mountpoint)
              detection_text = f"YARA: {rule_name}"
              findings.append((file_path, detection_text, engine["name"]))
              print(f"{timestamp} 🐞 {detection_text} {file_path}")
      return

  # Default regex-based parsing (e.g. ClamAV)
  regex = re.compile(engine["regex"])
  detections = [line for line in stdout.splitlines() if regex.search(line)]

  if detections:
      print(f"\n🕵🏾‍♀️ {engine['name']} detections:")
      for d in detections:
          print(f"{timestamp} 🐞 {d}")
          m = re.match(r"^([^:]+):\s*(.*)$", d)
          if m:
              file_path_raw = m.group(1)
              detection_text = m.group(2)
          else:
              file_path_raw = None
              detection_text = d

          file_path = normalize_file_path_for_db(file_path_raw, mountpoint)
          findings.append((file_path, detection_text, engine["name"]))
  else:
      print(f"\n{timestamp} No detections from {engine['name']}.")

# The fun starts here...
def main():
   parser = argparse.ArgumentParser(description="NAS Instant File Share Recovery with multi-engine scan from Linux")
   parser.add_argument("--vbrserver", default="__REPLACE_VBR_SERVER__", help="VBR server hostname or IP")
   parser.add_argument("--sharename", required=True, help="Share name")
   parser.add_argument("--mounthost", required=True, help="Hostname of the Windows mount host (managed server)")
   parser.add_argument("--username", default="__REPLACE_REST_API_USER__", help="Veeam REST API username")
   parser.add_argument("--timeout", type=int, default=30, help="Seconds for restore point selection timeout")
   parser.add_argument("--wait", type=int, default=60, help="Seconds to wait after starting Instant Recovery before scanning")
   parser.add_argument("--mount-base", default="/mnt", help="Base directory where SMB share will be mounted (default: /mnt)")
   parser.add_argument("--smb-user", help="SMB username override (default: same as --username)")
   parser.add_argument("--smb-share", help="Explicit SMB share name on mount host (overrides auto-detected share name)")
   parser.add_argument("--noninteractive", action="store_true", help="Do not prompt, always use latest restore point")
   args = parser.parse_args()

   engines = load_scan_engines()
   init_db()

   api_url = f"https://{args.vbrserver}:9419"
   username = args.username
   smb_user = args.smb_user or username
   password = get_password()
   smb_pass = get_smb_password()

   print("🐻 Get Bearer Token...")
   token = connect_veeam_rest_api(api_url, username, password)

   session_id = None
   findings = []
   meta = None
   mountpoint = None

   try:
       managed_server_id = get_managed_server_id(api_url, token, args.mounthost)
       mount_server_id = resolve_mount_server_id(api_url, token, managed_server_id)

       rp_response = get_nas_restore_points(api_url, token, args.sharename, 10)
       data = rp_response.get("data", [])
       if not data:
           print("❌ No restore points found.")
           return

       print(f"📂 Get 10 latest Restore Points for Sharename {args.sharename}...")
       display_nas_restore_points(rp_response)

       if args.noninteractive:
           selected_index = 0
       else:
           selected_index = select_restore_point(len(data), args.timeout)

       selected_rp = data[selected_index]
       rp_id = selected_rp.get("id")
       rp_time = selected_rp.get("creationTime")

       ir_response = start_instant_file_share_recovery(api_url, token, rp_id, mount_server_id, smb_user)
       session_id = try_extract_session_id(ir_response)

       print(f"\n⏳ Waiting {args.wait} seconds...")
       time.sleep(args.wait)

       prod_host, prod_share = extract_production_share_name(ir_response)
       if not prod_share:
           print("❌ Could not extract share.")
           return

       # Build correct share name for DB
       if prod_share.startswith("/"):
           share_name_for_db = f"{prod_host}:{prod_share}"
       else:
           share_name_for_db = f"\\\\{prod_host}\\{prod_share}"

       effective_share = (args.smb_share or prod_share).lstrip("/\\")

       try:
           server_ip = socket.gethostbyname(args.mounthost)
       except Exception:
           print(f"❌ Cannot resolve {args.mounthost}")
           return

       mountpoint = build_mountpoint(args.mount_base, args.mounthost, effective_share)
       os.makedirs(mountpoint, exist_ok=True)

       smb_unc = f"//{args.mounthost}/{effective_share}"
       opts = f"username={smb_user},password={smb_pass},ro,ip={server_ip}"
       cmd_mount = ["mount", "-t", "cifs", smb_unc, mountpoint, "-o", opts]

       print(f"⏳ Mounting {smb_unc}...")
       try:
           subprocess.run(cmd_mount, check=True)
       except Exception:
           print("❌ Mount failed.")
           return

       meta = {
           "share_name": share_name_for_db,
           "restore_point_id": rp_id,
           "restore_point_time": rp_time,
           "mount_host": args.mounthost,
       }

       for eng in engines:
           run_scan_engine(eng, mountpoint, meta, findings)

   finally:
       print("\n🛑 Unmounting...")
       if mountpoint:
           subprocess.run(["umount", mountpoint], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
           try:
               os.rmdir(mountpoint)
           except Exception:
               pass

       if session_id:
           stop_instant_file_share_recovery(api_url, token, session_id)

       if meta and findings:
           inserted = write_nas_findings_to_db(findings, meta)
           print(f"🗄️ Inserted {inserted} NAS findings into DB")

       post_logout(api_url, token)

if __name__ == "__main__":
   main()
