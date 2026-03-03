import logging
import json
from datetime import datetime
from typing import List, Dict, Any

class ScanLogger:
    def __init__(self):
        self.entries: List[Dict] = []
        logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
        self.logger = logging.getLogger("BugBountyPlatform")

    def log(self, level: str, message: str, data: Any = None):
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": level,
            "message": message,
            "data": data
        }
        self.entries.append(entry)
        getattr(self.logger, level.lower(), self.logger.info)(message)

    def info(self, message: str, data: Any = None):
        self.log("INFO", message, data)

    def warning(self, message: str, data: Any = None):
        self.log("WARNING", message, data)

    def error(self, message: str, data: Any = None):
        self.log("ERROR", message, data)

    def finding(self, message: str, data: Any = None):
        self.log("FINDING", message, data)

    def get_entries(self) -> List[Dict]:
        return self.entries

    def export_json(self) -> str:
        return json.dumps(self.entries, indent=2)
