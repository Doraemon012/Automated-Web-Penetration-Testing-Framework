"""MongoDB persistence layer for scan history."""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from pymongo import ASCENDING, DESCENDING, MongoClient
from pymongo.collection import Collection


class ScanRepository:
    """Simple repository for persisting scan metadata and results."""

    def __init__(self, uri: str, db_name: str, collection_name: str):
        self._client = MongoClient(uri, serverSelectionTimeoutMS=5000)
        # Validate connectivity early to fail-fast during startup
        self._client.admin.command("ping")
        self._collection: Collection = self._client[db_name][collection_name]
        self._ensure_indexes()

    def _ensure_indexes(self) -> None:
        self._collection.create_index([("scan_id", ASCENDING)], unique=True)
        self._collection.create_index([("created_at", DESCENDING)])

    def upsert(self, document: Dict[str, Any]) -> None:
        scan_id = document["scan_id"]
        self._collection.update_one({"scan_id": scan_id}, {"$set": document}, upsert=True)

    def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        return self._collection.find_one({"scan_id": scan_id}, {"_id": False})

    def list_scans(self, limit: int = 20) -> List[Dict[str, Any]]:
        cursor = (
            self._collection.find({}, {"_id": False})
            .sort("created_at", DESCENDING)
            .limit(limit)
        )
        return list(cursor)
