"""MongoDB repository for user accounts."""
from __future__ import annotations

from typing import Any, Dict, Optional

from pymongo import ASCENDING, MongoClient
from pymongo.collection import Collection


class UserRepository:
    """Simple repository abstraction for managing users."""

    def __init__(self, uri: str, db_name: str, collection_name: str):
        self._client = MongoClient(uri, serverSelectionTimeoutMS=5000)
        self._client.admin.command("ping")
        self._collection: Collection = self._client[db_name][collection_name]
        self._ensure_indexes()

    def _ensure_indexes(self) -> None:
        self._collection.create_index([("email", ASCENDING)], unique=True)

    def create_user(self, email: str, hashed_password: str) -> Dict[str, Any]:
        document = {
            "email": email.lower(),
            "hashed_password": hashed_password,
        }
        self._collection.insert_one(document)
        return {"email": document["email"]}

    def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        return self._collection.find_one({"email": email.lower()}, {"_id": False})

    def email_exists(self, email: str) -> bool:
        return self._collection.count_documents({"email": email.lower()}, limit=1) > 0
