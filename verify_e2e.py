
import asyncio
import os
import shutil
import subprocess
import time
from pathlib import Path

# Config
REPO_URL = "deb https://mirrors.syd.wacky.one/nginx noble nginx"
TMP_DIR = Path("./tmp_verify")
MIRROR_LIST = TMP_DIR / "mirror.list"
BASE_PATH = TMP_DIR / "base"
MIRROR_PATH = BASE_PATH / "mirror"
SKEL_PATH = BASE_PATH / "skel"
VAR_PATH = BASE_PATH / "var"

def setup():
    if TMP_DIR.exists():
        shutil.rmtree(TMP_DIR)
    TMP_DIR.mkdir()
    BASE_PATH.mkdir()
    
    config_content = f"""
set base_path    {BASE_PATH.absolute()}
set mirror_path  {MIRROR_PATH.absolute()}
set skel_path    {SKEL_PATH.absolute()}
set var_path     {VAR_PATH.absolute()}
set nthreads     5
set _autoclean   0
set check_local_hash 1

{REPO_URL}
"""
    with open(MIRROR_LIST, "w") as f:
        f.write(config_content)
    print(f"Created config at {MIRROR_LIST}")

def run_sync(label):
    print(f"\n--- Running Sync: {label} ---")
    start = time.time()
    # Using python -m to run
    cmd = ["python3", "-m", "apt_mirror.apt_mirror", str(MIRROR_LIST)]
    
    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1 # Line buffered
    )

    stdout_lines = []
    stderr_lines = []
    
    import threading

    def stream_reader(pipe, dest_list, prefix=""):
        for line in pipe:
            print(f"{prefix}{line}", end="")
            dest_list.append(line)

    t1 = threading.Thread(target=stream_reader, args=(process.stdout, stdout_lines, "[OUT] "))
    t2 = threading.Thread(target=stream_reader, args=(process.stderr, stderr_lines, "[ERR] "))
    
    t1.start()
    t2.start()
    
    process.wait()
    t1.join()
    t2.join()

    duration = time.time() - start
    
    full_stderr = "".join(stderr_lines)
    full_stdout = "".join(stdout_lines)

    # Filter logs for hash verification
    logging_lines = [line for line in stderr_lines] # Capture all log lines for checking
    
    # Look for status lines or specific events.
    hash_logs = [line for line in logging_lines if "Hash mismatch" in line]
    
    print(f"Exit Code: {process.returncode}")
    print(f"Duration: {duration:.2f}s")
    
    # Fake a result object for compatibility
    class Result:
        pass
    result = Result()
    result.returncode = process.returncode
    result.stdout = full_stdout
    result.stderr = full_stderr

    if result.returncode != 0:
        pass # Already printed via stream
         
    return result, hash_logs, result.stderr

def verify():
    setup()
    
    # 1. Initial Sync
    res1, logs1, stderr1 = run_sync("Initial Sync")
    if res1.returncode != 0:
        print("Initial sync failed!")
        return

    # Find loose debs
    deb_files = list(MIRROR_PATH.rglob("*.deb"))
    print(f"Downloaded {len(deb_files)} deb files.")
    if len(deb_files) == 0:
         print("DEBUG: contents of var path:")
         if VAR_PATH.exists():
             for log_file in VAR_PATH.iterdir():
                 print(f"--- Log: {log_file.name} ---")
                 if log_file.is_file():
                     print(log_file.read_text())
         else:
             print(f"DEBUG: var path {VAR_PATH} does not exist.")
             print("DEBUG: STDOUT:")
             print(result.stdout)
             print("DEBUG: STDERR:")
             print(result.stderr)
    
    if len(deb_files) < 3:
        print("Not enough files downloaded to verify!")
        return

    # 2. Modify State
    file_to_corrupt = deb_files[0]
    file_to_delete = deb_files[1]
    
    print(f"Corrupting: {file_to_corrupt.name}")
    with open(file_to_corrupt, "r+b") as f:
        f.seek(0)
        f.write(b"CORRUPT")
        
    print(f"Deleting: {file_to_delete.name}")
    file_to_delete.unlink()
    
    # 3. Second Sync
    res2, logs2, stderr2 = run_sync("Second Sync (Corruption & Deletion)")
    
    # Analysis
    print("\n--- Verification Analysis ---")
    
    # Check for "Hash mismatch [...]" in logs.
    # Corrupted file -> Should trigger mismatch increment.
    # Deleted file -> No check -> No mismatch increment.
    # Unchanged -> Match -> No mismatch increment.
    # Total mismatch count should be 1.
    
    mismatch_counts = []
    for line in logs2:
        # Format: ... Hash mismatch [1] ...
        try:
             if "Hash mismatch [" in line:
                 part = line.split("Hash mismatch [")[1].split("]")[0]
                 mismatch_counts.append(int(part))
        except (IndexError, ValueError):
             pass
             
    print(f"Mismatch counts found: {mismatch_counts}")
    
    if mismatch_counts:
        final_count = mismatch_counts[-1]
        print(f"Final mismatch count: {final_count}")
        if final_count == 1:
             print("PASS: Exactly 1 hash mismatch detected (corresponding to the corrupted file).")
        elif final_count > 1:
             print(f"FAIL: Too many mismatches ({final_count}). Did deleted file count?")
        else:
             print("FAIL: No mismatches detected.")
    else:
        print("FAIL: No 'Hash mismatch' log found.")
        
    # Check downloads
    downloaded_sizes = []
    for line in logs2:
         if "Downloaded [" in line:
              try:
                   part = line.split("Downloaded [")[1].split("]")[0]
                   downloaded_sizes.append(part)
              except IndexError:
                   pass
                   
    print(f"Downloaded sizes found: {downloaded_sizes}")
    if downloaded_sizes:
         last_downloaded = downloaded_sizes[-1]
         if last_downloaded != "0 B" and last_downloaded != "0.00 B":
              print("PASS: Re-download happened.")
         else:
              print("FAIL: No files re-downloaded.")
    else:
         print("FAIL: No download status log found.")

if __name__ == "__main__":
    verify()
