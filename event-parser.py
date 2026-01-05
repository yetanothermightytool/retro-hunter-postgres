#!/usr/bin/env python3
import argparse
import os
import psycopg2
from datetime import datetime, timedelta
from Evtx.Evtx import Evtx
from xml.etree import ElementTree as ET
from dotenv import load_dotenv

load_dotenv(dotenv_path=".env.local")

# Logical event groups to simplify configuration and keep things extensible
EVENT_GROUPS = {
   # Windows Security – baseline (policy and important changes)
   "security_core": [4618, 4649, 4719, 4765, 4766, 4794, 4897, 4964, 5124, 1102,],
   # AppLocker
   "applocker_core": [8004, 8007,],
   # PowerShell – core logging 
   "powershell_core": [4104, 800,],
   # Sysmon – core telemetry (can be adjusted based on your Sysmon config)
   "sysmon_core": [1, 2, 3, 5, 6, 7, 8, 10, 11, 12, 13, 23, 25,],
   # Reserved for future telemetry 
   "future_extended_telemetry": []
}

def _default_groups_for_logfile(logfile):
  name = logfile.lower()
  if "sysmon" in name:
      return ["sysmon_core"]
  if "powershell" in name:
      return ["powershell_core"]
  if "security" in name:
      return ["security_core"]
  # Fallback: no default groups 
  return []

def resolve_event_ids_for_logfile(logfile, args):
  # Hard override via --event-ids
  if args.event_ids:
      return [int(e.strip()) for e in args.event_ids.split(",") if e.strip()]

  groups = []

  # Explicit logical groups via --event-groups
  if args.event_groups:
      groups.extend(g.strip() for g in args.event_groups.split(",") if g.strip())
  else:
      # Default groups based on logfile name
      groups.extend(_default_groups_for_logfile(logfile))

      # Optional: add extended Security process-related events
      if args.extended and "security" in logfile.lower():
          groups.append("security_process")
          groups.append("applocker_core")
  if not groups:
      # No groups selected -> no event ID filter, parse everything
      return None

  event_ids = set()
  for g in groups:
      if g not in EVENT_GROUPS:
          available = ", ".join(EVENT_GROUPS.keys())
          raise ValueError(f"Unknown event group '{g}'. Available groups: {available}")
      event_ids.update(EVENT_GROUPS[g])

  return sorted(event_ids)

def parse_args():
  parser = argparse.ArgumentParser(description="Parse Windows EVTX logs into PostgreSQL")
  parser.add_argument("--mount", required=True)
  parser.add_argument("--hostname", required=True)
  parser.add_argument("--restorepoint-id", required=True)
  parser.add_argument("--rp-timestamp", required=True)
  parser.add_argument("--rp-status", required=True)
  parser.add_argument("--logfile", default="Security.evtx")
  parser.add_argument("--event-ids", help="Comma-separated list of numeric event IDs (hard override, applies to all logfiles)")
  parser.add_argument("--event-groups", help="Comma-separated logical event groups (e.g. security_core,sysmon_core)")
  parser.add_argument("--days", type=int)
  parser.add_argument("--limit", type=int)
  parser.add_argument("--verbose", action="store_true")
  parser.add_argument("--extended", action="store_true", help="Include extended Security event IDs in addition to the default IDs")
  return parser.parse_args()

def init_table(cur):
   cur.execute("""
       CREATE TABLE IF NOT EXISTS win_events (
           id SERIAL PRIMARY KEY,
           hostname TEXT,
           restorepoint_id TEXT,
           rp_timestamp TEXT,
           rp_status TEXT,
           logfile TEXT,
           event_id INTEGER,
           level TEXT,
           timestamp TEXT,
           source TEXT,
           message TEXT
       )
   """)
   cur.execute("CREATE INDEX IF NOT EXISTS idx_event_host_ts ON win_events(hostname, event_id, timestamp)")

   cur.execute("""
       CREATE UNIQUE INDEX IF NOT EXISTS uniq_win_events_entry
       ON win_events(hostname, event_id, timestamp, rp_timestamp)
   """)

def parse_evtx(file_path, hostname, restorepoint_id, rp_timestamp, rp_status, allowed_ids, days_back, limit, verbose):
   events = []
   count = 0
   ns = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}
   rp_dt = datetime.fromisoformat(rp_timestamp)
   start_dt = rp_dt - timedelta(days=days_back) if days_back else None

   with Evtx(file_path) as log:
       for record in log.records():
           try:
               xml = ET.fromstring(record.xml())
               system = xml.find("e:System", ns)
               if system is None:
                   continue

               eid_node = system.find("e:EventID", ns)
               if eid_node is None or eid_node.text is None:
                   continue

               eid = int(eid_node.text.strip())
               if allowed_ids and eid not in allowed_ids:
                   continue

               timestamp_raw = system.find("e:TimeCreated", ns).attrib.get("SystemTime", "")
               timestamp_dt = datetime.fromisoformat(timestamp_raw.replace("+00:00", ""))

               if start_dt and not (start_dt <= timestamp_dt <= rp_dt):
                   continue

               source = system.find("e:Provider", ns).attrib.get("Name", "")
               level_map = {"1": "Critical", "2": "Error", "3": "Warning", "4": "Information", "5": "Verbose"}
               level_node = system.find("e:Level", ns)
               level_str = level_map.get(level_node.text, "Unknown") if level_node is not None else "Unknown"
               message = "".join(xml.itertext())[:1000].strip().replace("\n", " ")

               events.append((
                   hostname, restorepoint_id, rp_timestamp, rp_status,
                   os.path.basename(file_path), eid, level_str,
                   timestamp_raw, source, message
               ))

               count += 1
               if verbose:
                   print(f"[{eid}] {timestamp_raw} - {source} - {level_str}")
               if limit and count >= limit:
                   break

           except Exception as e:
               if verbose:
                   print(f"⚠️ Error parsing event: {e}")
   return events

def store_events(cur, events):
   inserted = 0
   for e in events:
       cur.execute("""
           INSERT INTO win_events (
               hostname, restorepoint_id, rp_timestamp, rp_status,
               logfile, event_id, level, timestamp, source, message
           ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
           ON CONFLICT DO NOTHING
       """, e)
       if cur.rowcount > 0:
           inserted += 1
   return inserted

def main():
 args = parse_args()

 conn = psycopg2.connect(
   host=os.getenv("POSTGRES_HOST", "localhost"),
   port=os.getenv("POSTGRES_PORT", 5432),
   user=os.getenv("POSTGRES_USER"),
   password=os.getenv("POSTGRES_PASSWORD"),
   dbname=os.getenv("POSTGRES_DB")
 )
 cur = conn.cursor()
 init_table(cur)

 logfiles = [l.strip() for l in args.logfile.split(",") if l.strip()]
 all_events = []

 for logfile in logfiles:
   evtx_path = os.path.join(args.mount, "Windows", "System32", "winevt", "Logs", logfile)
   if not os.path.isfile(evtx_path):
     print(f"❌ EVTX not found: {evtx_path}")
     continue

   used_ids = resolve_event_ids_for_logfile(logfile, args)

   if args.verbose:
       if used_ids is None:
           print(f"ℹ️ No event ID filter applied for {logfile} (processing all events).")
       else:
           print(f"ℹ️ Using {len(used_ids)} event IDs for {logfile}: {used_ids}")  

   parsed = parse_evtx(
     evtx_path,
     args.hostname,
     args.restorepoint_id,
     args.rp_timestamp,
     args.rp_status,
     used_ids,
     args.days,
     args.limit,
     args.verbose
   )
   all_events.extend(parsed)

 inserted = store_events(cur, all_events)
 conn.commit()
 cur.close()
 conn.close()

 print(f"✅ Stored {inserted} events into win_events.")

if __name__ == "__main__":
 main()
