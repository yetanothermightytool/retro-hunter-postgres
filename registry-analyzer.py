#!/usr/bin/env python3
import os
import argparse
from datetime import datetime, timedelta
import psycopg2
import psycopg2.extras
from dotenv import load_dotenv

# Load PostgreSQL credentials from .env.local
load_dotenv(dotenv_path=".env.local")

# Query catalog with query type
# Each entry: key -> (description, payload, mode)
QUERY_CATALOG = {
   # -------- Original / condition-based ----------
   "0": (
       "Suspicious IFEO Debuggers (e.g., cmd.exe, powershell, RATs)",
       """
       key_path ILIKE '%\\Image File Execution Options\\%'
       AND value_name = 'Debugger'
       AND (
           value_data ILIKE '%cmd.exe%' OR
           value_data ILIKE '%powershell.exe%' OR
           value_data ILIKE '%wscript.exe%' OR
           value_data ILIKE '%cscript.exe%' OR
           value_data ILIKE '%\\Users\\%' OR
           value_data ILIKE '%\\Temp\\%' OR
           value_data ILIKE '%\\AppData\\%' OR
           value_data ILIKE '%rat.exe%' OR
           value_data ILIKE '%payload%' OR
           value_data ILIKE '%\\Tasks\\%' OR
           value_data ILIKE '%\\explorer.exe%' OR
           value_data ILIKE '%\\svchost.exe%'
       )
       """,
       "condition",
   ),
   "1": (
       "Suspicious Autostart Entries (Run/RunOnce outside system paths)",
       """
       (
           key_path ILIKE '%\\Run' OR
           key_path ILIKE '%\\RunOnce' OR
           key_path ILIKE '%\\RunOnceEx'
       )
       AND value_data ILIKE '%.exe%'
       AND value_data NOT ILIKE '%\\Windows\\System32%'
       AND value_data NOT ILIKE '%Program Files%'
       AND value_data NOT ILIKE '%ProgramData%'
       AND value_data NOT ILIKE '%windir%'
       """,
       "condition",
   ),
   "2": (
       "Suspicious Services (.exe in uncommon paths)",
       """
       key_path ILIKE '%\\Services\\%' AND value_data ILIKE '%.exe%'
       AND value_data NOT ILIKE '%\\Windows%'
       AND value_data NOT ILIKE '%Program Files%'
       AND value_data NOT ILIKE '%SystemRoot%'
       AND value_data NOT ILIKE '%windir%'
       """,
       "condition",
   ),
   "3": (
       "AppInit_DLLs (Potential Code Injection)",
       "key_path ILIKE '%AppInit_DLLs%' AND value_data IS NOT NULL AND value_data <> ''",
       "condition",
   ),
   "4": (
       "Winlogon Shell Manipulation",
       "key_path ILIKE '%\\Winlogon\\Shell%' AND value_data NOT ILIKE '%explorer.exe%'",
       "condition",
   ),
   "5": (
       "MountPoints2 (USB Dropper or Persistence)",
       "key_path ILIKE '%\\MountPoints2\\%'",
       "condition",
   ),
   "6": (
       "PowerShell Execution History (ConsoleHost)",
       "key_path ILIKE '%\\ConsoleHost_history%'",
       "condition",
   ),

   # -------- Extended ASEP / condition-based ----------
   "7": (
       "All ASEP Run keys (Run / RunOnce / RunOnceEx / RunServices / Policies\\Explorer\\Run)",
       r"""
       key_path ~* '(\\|^)Software\\(Wow6432Node\\)?Microsoft\\Windows\\CurrentVersion\\(Run$|RunOnce$|RunOnceEx$|RunServices$|RunServicesOnce$|Policies\\Explorer\\Run$)'
       """,
       "condition",
   ),
   "8": (
       "Boot/Logon Execute family (Session Manager & related)",
       r"""
       key_path ~* 'System\\CurrentControlSet\\Control\\Session Manager\\(BootExecute$|Execute$|S0InitialCommand$|SetupExecute$)'
       OR key_path ~* 'System\\CurrentControlSet\\Control\\ServiceControlManagerExtension$'
       """,
       "condition",
   ),
   "9": (
       "Group Policy controlled Run (per-user and system-wide)",
       r"""
       key_path ~* '(\\|^)Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run$'
       """,
       "condition",
   ),
   "10": (
       "Terminal Server Install Run keys (per-user & system-wide)",
       r"""
       key_path ~* 'Software\\Microsoft\\Windows NT\\CurrentVersion\\Terminal Server\\Install\\Software\\Microsoft\\Windows\\CurrentVersion\\(Run$|RunOnce$|RunonceEx$)'
       """,
       "condition",
   ),
   "11": (
       "Startup folder path resolution in Registry (Explorer Shell/User Shell Folders)",
       r"""
       key_path ~* 'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\(User Shell Folders$|Shell Folders$)'
       """,
       "condition",
   ),
   "12": (
       "Any Session Manager Execute or PendingFileRenameOperations",
       r"""
       key_path ILIKE '%\\Session Manager\\PendingFileRenameOperations%' OR
       key_path ~* 'System\\CurrentControlSet\\Control\\Session Manager\\(BootExecute$|Execute$|SetupExecute$|S0InitialCommand$)'
       """,
       "condition",
   ),
   "13": (
       "Winlogon Userinit/Shell anomalies (non-default values)",
       r"""
       (
           key_path ILIKE '%\\Winlogon\\Userinit%' AND (value_data IS NULL OR value_data NOT ILIKE '%userinit.exe%')
       ) OR (
           key_path ILIKE '%\\Winlogon\\Shell%' AND value_data NOT ILIKE '%explorer.exe%'
       )
       """,
       "condition",
   ),

   # -------- Full SELECT (your Streamlit query) ----------
   "14": (
       "Suspicious IFEO Debuggers (detailed view with restore point timestamp)",
       """
       SELECT
           hostname AS "Host",
           key_path AS "Key Path",
           value_name AS "Value Name",
           value_data AS "Value Data",
           rp_timestamp AS "RP Timestamp"
       FROM registry_scan
       WHERE key_path ILIKE '%%Image File Execution Options%%'
         AND value_name = 'Debugger'
         AND (
             value_data ILIKE '%%cmd.exe%%' OR
             value_data ILIKE '%%powershell.exe%%' OR
             value_data ILIKE '%%wscript.exe%%' OR
             value_data ILIKE '%%cscript.exe%%' OR
             value_data ILIKE '%%\\Users\\%%' OR
             value_data ILIKE '%%\\Temp\\%%' OR
             value_data ILIKE '%%\\AppData\\%%' OR
             value_data ILIKE '%%rat.exe%%' OR
             value_data ILIKE '%%payload%%' OR
             value_data ILIKE '%%\\Tasks\\%%' OR
             value_data ILIKE '%%\\explorer.exe%%' OR
             value_data ILIKE '%%\\svchost.exe%%'
         )
       ORDER BY "RP Timestamp" DESC
       LIMIT 100
       """,
       "select",
   ),
}

def parse_args():
   p = argparse.ArgumentParser(description="Threat Hunting Queries (Registry Scan Summary) - PostgreSQL")
   p.add_argument("--hostname", help="Filter by hostname")
   p.add_argument("--since-days", type=int, help="Only include entries from last N days")
   p.add_argument("--limit", type=int, default=100, help="Limit results per condition-query (default: 100)")
   return p.parse_args()

def get_pg_conn():
   return psycopg2.connect(
       host=os.getenv("POSTGRES_HOST", "localhost"),
       port=int(os.getenv("POSTGRES_PORT", 5432)),
       dbname=os.getenv("POSTGRES_DB"),
       user=os.getenv("POSTGRES_USER"),
       password=os.getenv("POSTGRES_PASSWORD"),
   )

def build_filter_clause(args):
   """Build WHERE filters for condition-queries. Uses timestamptz casting safely."""
   filters, params = [], []

   if args.hostname:
       filters.append("hostname = %s")
       params.append(args.hostname)

   if args.since_days:
       cutoff = (datetime.now() - timedelta(days=args.since_days)).isoformat()
       filters.append("NULLIF(last_written, '')::timestamptz >= %s::timestamptz")
       params.append(cutoff)

   return filters, params

def _escape_percents(sql_fragment: str) -> str:
   """Escape literal % (→ %%) to avoid Python-style interpolation issues in psycopg2."""
   return sql_fragment.replace("%", "%%")

def run_condition_query(cur, description, condition, filters, params, limit):
   # Safely embed the condition; parameters are only for filters + limit
   where = f"({_escape_percents(condition)})"
   if filters:
       where += " AND " + " AND ".join(f"({f})" for f in filters)

   sql = f"""
       SELECT
           hostname,
           key_path,
           value_name,
           value_data,
           COUNT(DISTINCT restorepoint_id) AS restorepoints,
           MIN(NULLIF(rp_timestamp, '')::timestamptz) AS first_seen,
           MAX(NULLIF(rp_timestamp, '')::timestamptz) AS last_seen
       FROM registry_scan
       WHERE {where}
       GROUP BY hostname, key_path, value_name, value_data
       ORDER BY last_seen DESC NULLS LAST
       LIMIT %s
   """

   print(f"\n🔎 {description}\n")
   cur.execute(sql, params + [int(limit)])
   rows = cur.fetchall()
   if not rows:
       print("⚠️  No matching entries found.\n")
       return

   for hostname, path, name, data, count, first, last in rows:
       print(f"[{hostname}] {path} → {name} = {data}")
       print(f"📅 Seen in {count} restore point(s) between {first} and {last}")
       print("-" * 80)

def run_select_query(cur, description, select_sql):
   # Execute as-is (already contains SELECT ... WHERE ... ORDER ... LIMIT)
   print(f"\n🔎 {description}\n")
   cur.execute(select_sql)
   rows = cur.fetchall()
   if not rows:
       print("⚠️  No matching entries found.\n")
       return

   # Print rows generically with column headers
   colnames = [desc.name for desc in cur.description]
   print(" | ".join(colnames))
   print("-" * 80)
   for r in rows:
       print(" | ".join("" if v is None else str(v) for v in r))
   print("-" * 80)

def main():
   args = parse_args()

   while True:
       print("\n🛡️  Registry Threat Hunting Menu (PostgreSQL)\n")
       for k, (desc, _, _) in sorted(QUERY_CATALOG.items(), key=lambda x: int(x[0])):
           print(f" {k}. {desc}")
       print(" q. Quit")

       selection = input("\nChoose a category (e.g., 1): ").strip().lower()
       if selection in ("q", "quit", "exit"):
           break
       if selection not in QUERY_CATALOG:
           print("❌ Invalid selection.")
           input("\nPress Enter to return to the menu...")
           continue

       description, payload, mode = QUERY_CATALOG[selection]
       try:
           with get_pg_conn() as conn, conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
               if mode == "condition":
                   filters, params = build_filter_clause(args)
                   run_condition_query(cur, description, payload, filters, params, args.limit)
               elif mode == "select":
                   run_select_query(cur, description, payload)
               else:
                   print(f"❌ Unknown mode for selection {selection!r}: {mode}")
       except Exception as e:
           print(f"❌ Error: {e}")

       input("\nPress Enter to return to the menu...")

if __name__ == "__main__":
   main()
