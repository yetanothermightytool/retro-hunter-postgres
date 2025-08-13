#!/usr/bin/env python3
import argparse
import os
import psycopg2
from datetime import datetime, timedelta
from Evtx.Evtx import Evtx
from xml.etree import ElementTree as ET
from dotenv import load_dotenv

load_dotenv(dotenv_path=".env.local")

# Important Windows Event IDs
DEFAULT_EVENT_IDS = [4618, 4649, 4719, 4765, 4766, 4794, 4897, 4964, 5124, 1102]
# Extended: High-volume or optional events for deeper analysis
# - 4688 / 4689 Process creation / termination
# - 4104       PowerShell ScriptBlock logging (requires Script-Block Logging enabled)
# - 8004 / 8007→ AppLocker Script Enforcement/Audit
EXTENDED_EVENT_IDS = [4688, 4689,8004,8007]
POWERSHELL_EVENT_IDS = [4104,800]

def parse_args():
   parser = argparse.ArgumentParser(description="Parse Windows EVTX logs into PostgreSQL")
   parser.add_argument("--mount", required=True)
   parser.add_argument("--hostname", required=True)
   parser.add_argument("--restorepoint-id", required=True)
   parser.add_argument("--rp-timestamp", required=True)
   parser.add_argument("--rp-status", required=True)
   parser.add_argument("--logfile", default="Security.evtx")
   parser.add_argument("--event-ids")
   parser.add_argument("--days", type=int)
   parser.add_argument("--limit", type=int)
   parser.add_argument("--verbose", action="store_true")
   parser.add_argument("--extended", action="store_true",help="Include extended event IDs in addition to default IDs")
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

   if "PowerShell" in logfile:
     used_ids = POWERSHELL_EVENT_IDS
   else:
     if args.event_ids:
       used_ids = [int(e.strip()) for e in args.event_ids.split(",")]
     elif args.extended:
       used_ids = DEFAULT_EVENT_IDS + EXTENDED_EVENT_IDS
     else:
       used_ids = DEFAULT_EVENT_IDS

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
