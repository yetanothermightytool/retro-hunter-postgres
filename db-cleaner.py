#!/usr/bin/env python3
import psycopg2
import argparse
from datetime import datetime, timedelta

from dotenv import load_dotenv
load_dotenv(dotenv_path=".env.local")

def parse_args():
   parser = argparse.ArgumentParser(description="Cleanup old entries from PostgreSQL")
   parser.add_argument("--days", type=int, default=90, help="Delete entries older than X days")
   parser.add_argument("--dry-run", action="store_true", help="Only show what would be deleted")
   parser.add_argument("--clean-only", action="store_true", help="Only delete non-malicious entries (files table only)")
   parser.add_argument("--host", help="Optionally restrict cleanup to specific host")
   return parser.parse_args()

def connect_pg():
   import os
   return psycopg2.connect(
       host=os.getenv("POSTGRES_HOST", "localhost"),
       port=os.getenv("POSTGRES_PORT", 5432),
       dbname=os.getenv("POSTGRES_DB", "retro-hunter"),
       user=os.getenv("POSTGRES_USER"),
       password=os.getenv("POSTGRES_PASSWORD")
   )

def delete_from_table(cur, table, time_field, cutoff, host=None):
   query = f"SELECT id FROM {table} WHERE {time_field} < %s"
   params = [cutoff]
   if host:
       query += " AND hostname = %s"
       params.append(host)

   cur.execute(query, params)
   rows = cur.fetchall()
   ids = [r[0] for r in rows]
   print(f"📁 Table: {table}")
   print(f"   ↳ Matching entries: {len(ids)}")

   if ids:
       cur.executemany(f"DELETE FROM {table} WHERE id = %s", [(i,) for i in ids])
       print(f"   ✅ Deleted: {len(ids)}")
   else:
       print(f"   ℹ️ Nothing to delete.")

def cleanup():
   args = parse_args()
   cutoff = (datetime.now() - timedelta(days=args.days)).strftime("%Y-%m-%d %H:%M:%S")

   print(f"📅 Cleanup cutoff: {cutoff}")
   conn = connect_pg()
   cur = conn.cursor()

   if args.clean_only:
       # Special case for files table
       print("🧹 Cleaning only safe entries from 'files' table (excluding malware/YARA)...")

       # Get bad hashes
       cur.execute("SELECT sha256 FROM malwarebazaar")
       malware_hashes = set(r[0] for r in cur.fetchall())

       cur.execute("SELECT sha256 FROM lolbas")
       lolbas_hashes = set(r[0] for r in cur.fetchall())

       all_bad_hashes = malware_hashes.union(lolbas_hashes)

       file_query = "SELECT id, sha256 FROM files WHERE rp_timestamp < %s"
       file_params = [cutoff]
       if args.host:
           file_query += " AND hostname = %s"
           file_params.append(args.host)

       cur.execute(file_query, file_params)
       rows = cur.fetchall()
       total = len(rows)

       safe_ids = [r[0] for r in rows if r[1] not in all_bad_hashes]

       print(f"📁 Table: files")
       print(f"   ↳ Matching entries: {total}")
       print(f"   ↳ Malware-protected entries kept: {total - len(safe_ids)}")

       if not args.dry_run and safe_ids:
           cur.executemany("DELETE FROM files WHERE id = %s", [(i,) for i in safe_ids])
           print(f"   ✅ Deleted: {len(safe_ids)}")
       elif args.dry_run:
           print(f"   ℹ️ Dry-run: {len(safe_ids)} entries would be deleted")

   else:
       # All tables normal cleanup
       delete_from_table(cur, "files", "rp_timestamp", cutoff, args.host)
       delete_from_table(cur, "scan_findings", "rp_timestamp", cutoff, args.host)
       delete_from_table(cur, "win_events", "rp_timestamp", cutoff, args.host)
       delete_from_table(cur, "registry_scan", "rp_timestamp", cutoff, args.host)

   if not args.dry_run:
       conn.commit()
       print("💾 Changes committed to database.")
   else:
       print("🧪 Dry-run mode: no changes committed.")

   cur.close()
   conn.close()

if __name__ == "__main__":
   cleanup()
