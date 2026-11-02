import time

# FIX-4: NTP Vulnerability
class FlowTimer:
    def __init__(self):
        self._start_mono = time.monotonic()
        self._start_wall = time.time()
        
    def elapsed_seconds(self):
        return time.monotonic() - self._start_mono
        
    def wall_timestamp(self):
        return self._start_wall + self.elapsed_seconds()
