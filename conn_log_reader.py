import os
import time
import threading

# FIX-3: Encryption Blindness (inode-aware, non-blocking cache)
class ConnLogReader:
    def __init__(self, filepath="/opt/zeek/logs/current/conn.log", tail_mode=True):
        self.filepath = filepath
        self.tail_mode = tail_mode
        self.uid_cache = {}  # uid -> {"orig_bytes": int, "resp_bytes": int}
        self.running = True
        self.thread = None
        
    def start(self):
        self.thread = threading.Thread(target=self._tail_conn_log, daemon=True)
        self.thread.start()
        
    def stop(self):
        self.running = False
        
    def get_bytes(self, uid):
        return self.uid_cache.get(uid)
        
    def _tail_conn_log(self):
        while self.running:
            try:
                if not os.path.exists(self.filepath):
                    time.sleep(2)
                    continue

                with open(self.filepath, 'r') as f:
                    fields = []
                    last_ino = os.stat(self.filepath).st_ino
                    
                    while self.running:
                        cur_pos = f.tell()
                        line = f.readline()
                        
                        if not line:
                            if self.tail_mode:
                                try:
                                    st = os.stat(self.filepath)
                                    if st.st_ino != last_ino or st.st_size < cur_pos:
                                        break
                                except FileNotFoundError:
                                    break
                                time.sleep(0.5)
                                continue
                            else:
                                return
                                
                        line = line.strip()
                        if not line: continue
                        if line.startswith("#fields"):
                            fields = line.split('\t')[1:]
                            continue
                        if line.startswith("#"): continue
                        if not fields: continue
                        
                        row_values = line.split('\t')
                        if len(row_values) != len(fields): continue
                        
                        record_raw = dict(zip(fields, row_values))
                        uid = record_raw.get("uid")
                        orig_bytes = record_raw.get("orig_bytes", "-")
                        resp_bytes = record_raw.get("resp_bytes", "-")
                        
                        if uid and orig_bytes != "-" and resp_bytes != "-":
                            try:
                                self.uid_cache[uid] = {
                                    "orig_bytes": int(orig_bytes),
                                    "resp_bytes": int(resp_bytes)
                                }
                                if len(self.uid_cache) > 100000:
                                    keys_to_delete = list(self.uid_cache.keys())[:10000]
                                    for k in keys_to_delete:
                                        del self.uid_cache[k]
                            except ValueError:
                                pass
                                
                if not self.tail_mode:
                    break
            except Exception as e:
                time.sleep(2)
