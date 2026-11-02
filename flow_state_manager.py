import sqlite3
import pickle
import time
import os
import threading

# FIX-5: State Recovery
class FlowStateManager:
    def __init__(self, db_path="/var/lib/zeek-c2-hunter/state.db"):
        self.db_path = db_path
        self.conn = None
        self.checkpoint_thread = None
        self.running = False
        
    def _get_conn(self):
        if not self.conn:
            os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
            self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self.conn.execute('''
                CREATE TABLE IF NOT EXISTS flows (
                    flow_key TEXT PRIMARY KEY,
                    state_blob BLOB,
                    last_updated REAL
                )
            ''')
            self.conn.commit()
        return self.conn

    def start_checkpointing(self, get_flows_cb, interval=60):
        self.running = True
        self.checkpoint_thread = threading.Thread(target=self._checkpoint_loop, args=(get_flows_cb, interval), daemon=True)
        self.checkpoint_thread.start()

    def _checkpoint_loop(self, get_flows_cb, interval):
        self._get_conn()
        while self.running:
            time.sleep(interval)
            self.flush(get_flows_cb())

    def flush(self, flows_dict):
        conn = self._get_conn()
        now = time.time()
        cursor = conn.cursor()
        for flow_key, f_data in flows_dict.items():
            state_blob = pickle.dumps(f_data)
            cursor.execute('''
                INSERT OR REPLACE INTO flows (flow_key, state_blob, last_updated)
                VALUES (?, ?, ?)
            ''', (flow_key, state_blob, now))
        conn.commit()

    def restore(self, max_age=3600):
        try:
            conn = self._get_conn()
            cursor = conn.cursor()
            now = time.time()
            cursor.execute('SELECT flow_key, state_blob, last_updated FROM flows')
            restored_flows = {}
            for row in cursor.fetchall():
                flow_key, state_blob, last_updated = row
                if (now - last_updated) <= max_age:
                    try:
                        restored_flows[flow_key] = pickle.loads(state_blob)
                    except:
                        pass
            return restored_flows
        except Exception:
            return {}

    def stop(self, get_flows_cb):
        self.running = False
        if self.conn:
            self.flush(get_flows_cb())
            self.conn.close()
