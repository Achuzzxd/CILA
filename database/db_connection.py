import os
from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv()

class DatabaseConnection:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(DatabaseConnection, cls).__new__(cls)
            mongo_url = os.getenv("DATABASE_URL", "mongodb://localhost:27017/")
            cls._instance.client = MongoClient(mongo_url)
            cls._instance.db = cls._instance.client["clia_db"]
        return cls._instance

def get_db():
    return DatabaseConnection().db
