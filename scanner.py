#!/usr/bin/env python3
import argparse
import os
import hashlib
import psycopg2
from dotenv import load_dotenv
import multiprocessing
from queue import Empty
from colorama import init, Fore, Style
import csv
import time
import sys
from datetime import datetime
import math
import yara

init(autoreset=True)
load_dotenv(dotenv_path=".env.local")

CHUNK_SIZE = 100
CONTENT_FILETYPES = [".txt", ".csv", ".log", ".doc", ".docx", ".pdf", ".rtf"]
DEFAULT_EXCLUDES = [
   "Windows\\WinSxS", "Windows\\Temp", "Windows\\SysWOW64",
   "Windows\\System32\\DriverStore", "Windows\\Servicing",
   "ProgramData\\Microsoft\\Windows Defender",
   "ProgramData\\Microsoft\\Windows Defender\\Platform",
   "System Volume Information", "Recovery", "Windows\\Logs",
   "Windows\\SoftwareDistribution\\Download", "Windows\\Prefetch",
   "Program Files\\Common Files\\Microsoft Shared",
   "Windows\\Microsoft.NET\\Framework64", "$Recycle.Bin",
   "appdata\\roaming\\microsoft\\systemcertificates\\my\\appcontainerusercertread",
   "Windows\\System32\\config\\systemprofile\\appdata\\roaming\\microsoft\\systemcertificates\\my\\appcontainerusercertread",
   "Windows\\ServiceProfiles\\LocalService\\AppData\\LocalLow\\Microsoft\\CryptnetUrlCache\\Content",
   "AppData\\LocalLow\\Microsoft\\CryptnetUrlCache\\Content",
   "AppData\\Local\\Packages\\Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy\\AC\\Microsoft\\CryptnetUrlCache\\Content"
]

def parse_args():
   parser = argparse.ArgumentParser(description="Scan backups for known malicious files.")
   parser.add_argument("--mount", required=True)
   parser.add_argument("--workers", type=int, default=max(1, multiprocessing.cpu_count() // 2))
   parser.add_argument("--filetypes")
   parser.add_argument("--maxsize", type=int)
   parser.add_argument("--exclude")
   parser.add_argument("--csv")
   parser.add_argument("--verbose", action="store_true")
   parser.add_argument("--logfile")
   parser.add_argument("--yara", choices=["off", "all", "suspicious", "content", "highentropy"], default="off")
   parser.add_argument("--hostname")
   parser.add_argument("--restore_point_id")
   parser.add_argument("--rp_timestamp")
   parser.add_argument("--rp_status")
   return parser.parse_args()

def get_db_conn():
   return psycopg2.connect(
       dbname=os.getenv("POSTGRES_DB"),
       user=os.getenv("POSTGRES_USER"),
       password=os.getenv("POSTGRES_PASSWORD"),
       host=os.getenv("POSTGRES_HOST"),
       port=os.getenv("POSTGRES_PORT", 5432)
   )

def init_db():
   conn = get_db_conn()
   cur = conn.cursor()
   cur.execute("""
       CREATE TABLE IF NOT EXISTS scan_findings (
           id SERIAL PRIMARY KEY,
           hostname TEXT,
           restore_point_id TEXT,
           rp_timestamp TEXT,
           rp_status TEXT,
           path TEXT,
           sha256 TEXT,
           detection TEXT,
           scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
       )
   """)
   cur.execute("CREATE INDEX IF NOT EXISTS idx_sha256 ON scan_findings(sha256)")
   conn.commit()
   conn.close()

def write_findings_to_db(results, args):
   conn = get_db_conn()
   cur = conn.cursor()
   for path, sha256, detection in results:
       cur.execute("""
           INSERT INTO scan_findings (
               hostname, restore_point_id, rp_timestamp, rp_status,
               path, sha256, detection
           ) VALUES (%s, %s, %s, %s, %s, %s, %s)
       """, (
           args.hostname or "", args.restore_point_id or "", args.rp_timestamp or "",
           args.rp_status or "", path, sha256 or "", detection
       ))
   conn.commit()
   conn.close()
   return len(results)

def log_message(msg, logfile):
   if logfile:
       with open(logfile, "a", encoding="utf-8") as f:
           f.write(f"{datetime.now().isoformat()} {msg}\n")

def calculate_entropy(filepath):
   try:
       with open(filepath, 'rb') as f:
           data = f.read(204800)
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

def get_files(root, filetypes, maxsize, excludes):
   result = []
   normalized_excludes = [ex.lower().replace("/", os.sep).replace("\\", os.sep) for ex in excludes]
   for dirpath, _, files in os.walk(root):
       norm_path = dirpath.lower()

       if any(ex in norm_path for ex in normalized_excludes):
           continue
       for name in files:
           path = os.path.join(dirpath, name)
           norm_full = path.lower()

           if any(ex in norm_full for ex in normalized_excludes):
               continue

           if filetypes and not any(norm_full.endswith(ft.lower()) for ft in filetypes):
               continue
           if maxsize:
               try:
                   if os.path.getsize(path) > maxsize * 1024 * 1024:
                       continue
               except:
                   continue
           result.append(path)
   return result

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

def load_hashes():
   conn = get_db_conn()
   cur = conn.cursor()
   cur.execute("SELECT sha256, name, standard_path FROM lolbas WHERE sha256 IS NOT NULL")
   lolbas_entries = cur.fetchall()
   cur.execute("SELECT sha256, file_name FROM malwarebazaar WHERE sha256 IS NOT NULL")
   malware_entries = cur.fetchall()
   conn.close()
   lolbas_hashes = {sha.lower(): name for sha, name, _ in lolbas_entries if sha}
   lolbas_paths = dict((name.lower(), path) for _, name, path in lolbas_entries if path)
   malware_hashes = {sha.lower(): name for sha, name in malware_entries if sha}
   return lolbas_hashes, malware_hashes, lolbas_paths

def normalize(p):
   return os.path.normpath(p).replace("\\", os.sep).lower()

def compile_yara_rules(path="yara_rules"):
   rules = {}
   for f in os.listdir(path):
       if f.endswith(".yar") or f.endswith(".yara"):
           rules[f] = os.path.join(path, f)
   return yara.compile(filepaths=rules) if rules else None

def worker(chunk_queue, result_queue, stats_queue, lol_hashes, mw_hashes, lol_paths, yara_rules, yara_mode, verbose, logfile):
   while True:
       try:
           chunk = chunk_queue.get(timeout=5)
       except Empty:
           break
       try:
           for path in chunk:
               filename = os.path.basename(path)
               lookup_name = filename.lower()
               norm_path = normalize(path)
               file_hash = sha256_file(path)
               suspicious = False
               entropy = None
               if yara_mode == "highentropy":
                   entropy = calculate_entropy(path)

               if lookup_name in lol_paths:
                   expected = normalize(lol_paths[lookup_name])
                   try:
                       expected_tail = os.path.normcase(expected).split("windows" + os.sep, 1)[-1]
                       actual_path = os.path.normcase(norm_path)
                       if expected_tail not in actual_path:
                           file_hash = file_hash or sha256_file(path)
                           msg = f"⚠️  LOLBAS OUT OF PLACE: {path} (expected {lol_paths[lookup_name]})"
                           print(f"\n{Fore.MAGENTA}{Style.BRIGHT}{msg}")
                           log_message(msg, logfile)
                           result_queue.put((path, file_hash, "lolbas_out_of_place"))
                           stats_queue.put("lolbas")
                           suspicious = True
                   except Exception as e:
                       print(f"⚠️ LOLBAS check failed for {path}: {e}")

               if file_hash:
                   if file_hash in mw_hashes:
                       msg = f"🐞 MATCH (MalwareBazaar) {path} → {mw_hashes[file_hash]}"
                       print(f"\n{Fore.RED}{Style.BRIGHT}{msg}")
                       log_message(msg, logfile)
                       result_queue.put((path, file_hash, mw_hashes[file_hash]))
                       stats_queue.put("hash")
                       suspicious = True
                   else:
                       stats_queue.put("clean")
                       if verbose:
                           print(f"\n{Fore.GREEN}✔ CLEAN: {path}")
               else:
                   msg = f"⚠️ File not readable: {path}"
                   print(f"\n{Fore.YELLOW}{msg}")
                   log_message(msg, logfile)
                   stats_queue.put("error")

               do_yara = yara_rules and (
                   yara_mode == "all"
                   or (yara_mode == "content" and any(path.lower().endswith(ft) for ft in CONTENT_FILETYPES))
                   or (yara_mode == "suspicious" and suspicious)
                   or (yara_mode == "highentropy" and entropy is not None and entropy >= 7.5)
               )

               if do_yara:
                   print(f"{Fore.BLUE}🔬 YARA scan on: {path}")
                   try:
                       matches = yara_rules.match(filepath=path)
                       for match in matches:
                           msg = f"❗ YARA MATCH: {path} → {match.rule}"
                           print(f"\n{Fore.BLUE}{Style.BRIGHT}{msg}")
                           log_message(msg, logfile)
                           result_queue.put((path, file_hash, f"YARA: {match.rule}"))
                           stats_queue.put("yara")
                   except Exception as e:
                       msg = f"⚠️ YARA scan failed for {path}: {e}"
                       print(f"\n{Fore.YELLOW}{msg}")
                       log_message(msg, logfile)
       finally:
           chunk_queue.task_done()

def monitor(stats_queue, total, stop_flag, result_stats):
   start = time.time()
   while not stop_flag.is_set() or not stats_queue.empty():
       time.sleep(5)
       while not stats_queue.empty():
           s = stats_queue.get()
           result_stats[s] = result_stats.get(s, 0) + 1
       scanned = sum(result_stats.values())
       elapsed = time.time() - start
       rate = scanned / elapsed * 60 if elapsed else 0
       remaining = total - scanned
       eta = remaining / (scanned / elapsed) if scanned and elapsed else 0
       percent = (scanned / total) * 100 if total else 0
       sys.stdout.write(
           f"\r⏱️ Scanned: {scanned}/{total} "
           f"| Hash Matches: {result_stats.get('hash', 0)} "
           f"| LOLBAS Out: {result_stats.get('lolbas', 0)} "
           f"| YARA Matches: {result_stats.get('yara', 0)} "
           f"| Errors: {result_stats.get('error', 0)} "
           f"({percent:.1f}%) → {rate:,.0f} files/min | ETA: {time.strftime('%H:%M:%S', time.gmtime(round(eta)))}"
       )
       sys.stdout.flush()
   print()

def collector(result_queue, collected_list, stop_flag):
   while not stop_flag.is_set() or not result_queue.empty():
       try:
           item = result_queue.get(timeout=0.5)
           collected_list.append(item)
       except Empty:
           continue

def main():
   args = parse_args()
   init_db()

   print(f"{Fore.CYAN}[{args.hostname}] 🔍 Scanning: {args.mount}")
   print(f"{Fore.CYAN}[{args.hostname}] ⚙️ Workers: {args.workers}")
   if args.logfile:
       print(f"{Fore.CYAN}[{args.hostname}] 📝 Logging to: {args.logfile}")
   if args.yara != "off":
       print(f"{Fore.CYAN}[{args.hostname}] 🔬 YARA mode: {args.yara}")

   filetypes = CONTENT_FILETYPES if args.yara == "content" else (args.filetypes.split(",") if args.filetypes else None)
   excludes = args.exclude.split(",") if args.exclude else DEFAULT_EXCLUDES

   all_files = get_files(args.mount, filetypes, args.maxsize, excludes)
   total = len(all_files)
   if total == 0:
       print(f"{Fore.YELLOW}⚠ No files found to scan. Check filters or exclusions.")
       return

   chunk_queue = multiprocessing.JoinableQueue()
   result_queue = multiprocessing.Queue(maxsize=5000)
   stats_queue = multiprocessing.Queue()
   manager = multiprocessing.Manager()
   result_stats = manager.dict()
   collected = manager.list()

   for i in range(0, total, CHUNK_SIZE):
       chunk = all_files[i:i + CHUNK_SIZE]
       chunk_queue.put(chunk)

   lol_hashes, mw_hashes, lol_paths = load_hashes()
   yara_rules = compile_yara_rules() if args.yara != "off" else None

   # Start monitor and collector
   stop_flag = multiprocessing.Event()
   monitor_proc = multiprocessing.Process(target=monitor, args=(stats_queue, total, stop_flag, result_stats))
   monitor_proc.start()

   collector_stop = multiprocessing.Event()
   collector_proc = multiprocessing.Process(target=collector, args=(result_queue, collected, collector_stop))
   collector_proc.start()

   # Start workers
   workers = []
   for _ in range(args.workers):
       p = multiprocessing.Process(
           target=worker,
           args=(chunk_queue, result_queue, stats_queue, lol_hashes, mw_hashes, lol_paths, yara_rules, args.yara, args.verbose, args.logfile)
       )
       p.start()
       workers.append(p)

   # Wait until all chunks are processed
   chunk_queue.join()
   for p in workers:
       p.join()

   # Stop monitor and collector
   stop_flag.set()
   collector_stop.set()
   monitor_proc.join()
   collector_proc.join()

   try:
       while True:
           collected.append(result_queue.get_nowait())
   except Empty:
       pass

   results = list(collected)

   # Optional CSV export
   if args.csv and results:
       base, ext = os.path.splitext(args.csv)
       timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
       final_name = f"{base}_{timestamp}{ext}"
       out_dir = os.path.dirname(final_name) or "."
       os.makedirs(out_dir, exist_ok=True)
       with open(final_name, "w", newline="", encoding="utf-8") as f:
           writer = csv.writer(f)
           writer.writerow(["Hostname", "RestorePointID", "RestorePointTime", "RestorePointStatus", "Path", "SHA256", "Detected as"])
           for row in results:
               path, sha256, detection = row
               writer.writerow([
                   args.hostname or "", args.restore_point_id or "", args.rp_timestamp or "",
                   args.rp_status or "", path, sha256 or "", detection
               ])
       print(f"{Fore.YELLOW}💾 Results saved to: {final_name}")

   if results:
       inserted = write_findings_to_db(results, args)
       print(f"{Fore.YELLOW}[{args.hostname}] 💾 Inserted {inserted} findings into DB")

   # Summary
   print(f"\n{Fore.GREEN}{Style.BRIGHT}[{args.hostname}] ✅ Scan complete.")
   print(f"{Style.BRIGHT}- Files scanned:       {total}")
   print(f"{Style.BRIGHT}- Malware matches:     {result_stats.get('hash', 0)}")
   print(f"{Style.BRIGHT}- LOLBAS out of place: {result_stats.get('lolbas', 0)}")
   print(f"{Style.BRIGHT}- YARA matches:        {result_stats.get('yara', 0)}")
   print(f"{Style.BRIGHT}- Read errors:         {result_stats.get('error', 0)}")
   print(f"{Style.BRIGHT}- Clean files:         {result_stats.get('clean', 0)}")

if __name__ == "__main__":
   main()
