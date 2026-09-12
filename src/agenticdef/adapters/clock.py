from datetime import datetime, timezone
import time


class SystemClock:
    def monotonic(self): return time.monotonic()
    def utcnow(self): return datetime.now(timezone.utc).isoformat()
