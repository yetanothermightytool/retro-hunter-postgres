#!/usr/bin/env python3
import argparse
import os
import hashlib
import psycopg2
import multiprocessing
from queue import Empty
from datetime import datetime, timezone
import stat
import math
import pefile
import magic
from dotenv import load_dotenv
import time

load_dotenv(dotenv_path=".env.local")

CHUNK_SIZE = 500
ENTROPY_READ_SIZE = 204800
MIN_FILESIZE_BYTES = 5 * 1024

DEFAULT_BINARY_EXTS = [".exe", ".dll", ".sys", ".msi", ".bat", ".cmd", ".ps1",
                      ".sh", ".bin", ".run", ".so", ".out", ".deb", ".rpm",
                      ".jar", ".pyc", ".apk", ".com"]

EXECUTABLE_EXTS = {'.exe', '.dll', '.bin', '.so', '.elf', '.sh', '.bat', '.cmd', '.ps1', '.apk', '.com'}
SCRIPT_EXTS     = {'.py', '.js', '.vbs', '.pl', '.rb', '.ps1', '.sh', '.bat', '.cmd'}
IMAGE_EXTS      = {'.png', '.jpg', '.jpeg', '.gif', '.bmp', '.tiff'}
DOCUMENT_EXTS   = {'.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.txt', '.rtf'}
ARCHIVE_EXTS    = {'.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz'}

BENIGN_DIRS = ["appdata\\local\\microsoft", "appdata\\local\\google", "syswow64", "windows\\system32",
              "windows\\servicing", "windows\\winsxs", "programdata\\microsoft\\windows defender",
              "appdata\\locallow\\microsoft\\cryptneturlcache", "appdata\\local\\microsoft\\credentials",
              "office\\16.0\\webservicecache"]

SUSPICIOUS_DIRS = ["appdata\\roaming", "appdata\\local\\temp", "downloads", "recycle.bin", "programdata\\temp",
                  "users\\public", "windows\\temp"]

def parse_args():
   parser = argparse.ArgumentParser(description="Index binary files into PostgreSQL")
   parser.add_argument("--mount", required=True)
   parser.add_argument("--hostname", required=True)
   parser.add_argument("--restorepoint-id", required=True)
   parser.add_argument("--rp-timestamp", required=True)
   parser.add_argument("--rp-status", required=True)
   parser.add_argument("--workers", type=int, default=max(1, multiprocessing.cpu_count() // 2))
   parser.add_argument("--filetypes")
   parser.add_argument("--maxsize", type=int)
   parser.add_argument("--exclude")
   parser.add_argument("--verbose", action="store_true")
   return parser.parse_args()

def init_table(conn):
   cur = conn.cursor()
   cur.execute("""
       CREATE TABLE IF NOT EXISTS files (
           id SERIAL PRIMARY KEY,
           hostname TEXT,
           restorepoint_id TEXT,
           rp_timestamp TEXT,
           rp_status TEXT,
           path TEXT,
           filename TEXT,
           extension TEXT,
           size BIGINT,
           modified TIMESTAMPTZ,
           created TIMESTAMPTZ,
           sha256 TEXT,
           filetype TEXT,
           is_executable BOOLEAN,
           entropy REAL,
           suspicious_structure TEXT,
           magic_type TEXT,
           pe_timestamp TEXT,
           pe_sections TEXT,
           inserted_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
           UNIQUE(hostname, sha256)
       );
   """)
   cur.execute("CREATE INDEX IF NOT EXISTS idx_files_sha256 ON files(sha256)")
   cur.execute("CREATE INDEX IF NOT EXISTS idx_files_host_filename_sha256_ts ON files(hostname, filename, sha256, rp_timestamp)")
   conn.commit()

def detect_filetype(extension, is_exec=False):
   ext = extension.lower()
   if ext in EXECUTABLE_EXTS or (not ext and is_exec):
       return "executable"
   elif ext in SCRIPT_EXTS:
       return "script"
   elif ext in IMAGE_EXTS:
       return "image"
   elif ext in DOCUMENT_EXTS:
       return "document"
   elif ext in ARCHIVE_EXTS:
       return "archive"
   else:
       return "other"

def calculate_entropy(filepath):
   try:
       with open(filepath, 'rb') as f:
           data = f.read(ENTROPY_READ_SIZE)
       if not data:
           return 0.0
       entropy = 0
       for x in range(256):
           p_x = data.count(bytes([x])) / len(data)
           if p_x > 0:
               entropy -= p_x * math.log2(p_x)
       return round(entropy, 2)
   except:
       return None

def is_suspicious_structure(file_path):
   file_path = file_path.lower()
   if any(good in file_path for good in BENIGN_DIRS):
       return "no"
   elif any(bad in file_path for bad in SUSPICIOUS_DIRS):
       return "yes"
   return "no"

def enrich_pe_metadata(filepath):
   try:
       magic_type = magic.from_file(filepath)
   except:
       magic_type = None
   try:
       pe = pefile.PE(filepath, fast_load=False)
       raw_timestamp = pe.FILE_HEADER.TimeDateStamp
       pe_timestamp = datetime.fromtimestamp(raw_timestamp, timezone.utc).isoformat()
       sections = [s.Name.decode(errors='ignore').strip('\x00') for s in pe.sections]
       pe_sections = ",".join(sections)
   except:
       pe_timestamp, pe_sections = None, None
   return magic_type, pe_timestamp, pe_sections

def get_files(root, filetypes, maxsize, excludes):
   result = []
   normalized_excludes = [ex.lower().replace("\\", os.sep).replace("/", os.sep) for ex in excludes]
   for dirpath, _, files in os.walk(root):
       norm_dir = dirpath.lower()
       if any(ex in norm_dir for ex in normalized_excludes):
           continue
       for name in files:
           full_path = os.path.join(dirpath, name)
           if not os.path.isfile(full_path):
               continue
           ext = os.path.splitext(name)[1].lower()
           try:
               size = os.path.getsize(full_path)
           except:
               continue
           if maxsize and size > maxsize * 1024 * 1024:
               continue
           if size < MIN_FILESIZE_BYTES:
               continue
           if filetypes:
               if ext and ext in filetypes:
                   result.append(full_path)
               elif not ext and os.access(full_path, os.X_OK):
                   result.append(full_path)
           else:
               result.append(full_path)
   return result

def is_executable(path):
   try:
       st = os.stat(path)
       return bool(st.st_mode & stat.S_IXUSR)
   except:
       return False

def sha256_file(path):
   h = hashlib.sha256()
   try:
       with open(path, "rb") as f:
           while True:
               chunk = f.read(8192)
               if not chunk:
                   break
               h.update(chunk)
       return h.hexdigest()
   except:
       return None

def extract_metadata(path):
   try:
       stat_result = os.stat(path)
       extension = os.path.splitext(path)[1].lower()
       exec_flag = is_executable(path)
       entropy_val = calculate_entropy(path)
       filetype_val = detect_filetype(extension, exec_flag)
       magic_type, pe_timestamp, pe_sections = None, None, None
       if entropy_val and entropy_val >= 7.5 and filetype_val == "executable":
           magic_type, pe_timestamp, pe_sections = enrich_pe_metadata(path)
       return {
           "filename": os.path.basename(path),
           "path": os.path.dirname(path),
           "extension": extension,
           "size": stat_result.st_size,
           "modified": datetime.fromtimestamp(stat_result.st_mtime).isoformat(),
           "created": datetime.fromtimestamp(stat_result.st_ctime).isoformat(),
           "is_executable": exec_flag,
           "sha256": sha256_file(path),
           "filetype": filetype_val,
           "entropy": entropy_val,
           "suspicious_structure": is_suspicious_structure(path),
           "magic_type": magic_type,
           "pe_timestamp": pe_timestamp,
           "pe_sections": pe_sections
       }
   except:
       return None

def worker(chunk_queue, result_queue, hostname, restorepoint_id, rp_timestamp, rp_status):
   while True:
       try:
           chunk = chunk_queue.get(timeout=5)
       except Empty:
           break
       try:
           for file_path in chunk:
               meta = extract_metadata(file_path)
               if meta and meta["sha256"]:
                   meta.update({
                       "hostname": hostname,
                       "restorepoint_id": restorepoint_id,
                       "rp_timestamp": rp_timestamp,
                       "rp_status": rp_status
                   })
                   result_queue.put(meta)
       finally:
           chunk_queue.task_done()

def db_writer(result_queue, dsn, verbose=False, batch_size=1000):
   conn = psycopg2.connect(**dsn)
   init_table(conn)
   cur = conn.cursor()
   inserted_total = 0
   batch = []
   while True:
       item = result_queue.get()
       if item is None:
           if batch:
               _flush_batch(cur, conn, batch)
               inserted_total += len(batch)
           if verbose:
               print(f"🗄️  Writer exiting. Inserted ~{inserted_total} rows.")
           conn.close()
           return
       batch.append(item)
       if len(batch) >= batch_size:
           _flush_batch(cur, conn, batch)
           inserted_total += len(batch)
           batch.clear()

def _flush_batch(cur, conn, batch):
   for meta in batch:
       try:
           cur.execute("""
               INSERT INTO files (
                   hostname, restorepoint_id, rp_timestamp, rp_status,
                   path, filename, extension, size,
                   modified, created, sha256, filetype,
                   is_executable, entropy, suspicious_structure,
                   magic_type, pe_timestamp, pe_sections
               ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
               ON CONFLICT (hostname, sha256) DO NOTHING
           """, (
               meta["hostname"], meta["restorepoint_id"], meta["rp_timestamp"], meta["rp_status"],
               meta["path"], meta["filename"], meta["extension"], meta["size"],
               meta["modified"], meta["created"], meta["sha256"], meta["filetype"],
               meta["is_executable"], meta["entropy"], meta["suspicious_structure"],
               meta["magic_type"], meta["pe_timestamp"], meta["pe_sections"]
           ))
       except Exception as e:
           print(f"❌ Failed to insert: {e}")
   conn.commit()

def main():
   args = parse_args()
   filetypes = [ft.strip().lower() for ft in args.filetypes.split(",")] if args.filetypes else DEFAULT_BINARY_EXTS
   excludes = [ex.strip() for ex in args.exclude.split(",")] if args.exclude else []

   dsn = dict(
       host=os.getenv("POSTGRES_HOST", "localhost"),
       port=int(os.getenv("POSTGRES_PORT", 5432)),
       user=os.getenv("POSTGRES_USER"),
       password=os.getenv("POSTGRES_PASSWORD"),
       dbname=os.getenv("POSTGRES_DB"),
   )

   # Start writer first so result_queue always has a consumer
   result_queue = multiprocessing.Queue(maxsize=5000)
   writer = multiprocessing.Process(target=db_writer, args=(result_queue, dsn, args.verbose))
   writer.start()

   print(f"[{args.hostname}] 🔍 Scanning {args.mount}...")
   all_files = get_files(args.mount, filetypes, args.maxsize, excludes)
   total = len(all_files)
   print(f"[{args.hostname}] 📦 {total} matching filters")
   if total == 0:
       result_queue.put(None)
       writer.join()
       return

   chunk_queue = multiprocessing.JoinableQueue()
   for i in range(0, total, CHUNK_SIZE):
       chunk_queue.put(all_files[i:i + CHUNK_SIZE])

   workers = []
   for _ in range(args.workers):
       p = multiprocessing.Process(
           target=worker,
           args=(chunk_queue, result_queue, args.hostname, args.restorepoint_id, args.rp_timestamp, args.rp_status)
       )
       p.start()
       workers.append(p)

   # Wait until all chunks were processed (task_done called by workers)
   chunk_queue.join()

   for p in workers:
       p.join()

   result_queue.put(None)
   writer.join()

   print(f"[{args.hostname}] ✅ Done.")

if __name__ == "__main__":
   main()
