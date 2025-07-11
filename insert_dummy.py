from pymongo import MongoClient

client = MongoClient("mongodb://localhost:27017/")
db = client["swadhin"]
collection = db["test"]

collection.insert_one({"name": "Bestii 💖", "type": "test", "status": "inserted"})
print("✅ Dummy data inserted into 'swadhin.test'")
