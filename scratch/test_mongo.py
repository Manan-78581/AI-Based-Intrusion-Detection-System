
import asyncio
from motor.motor_asyncio import AsyncIOMotorClient

async def test_mongo():
    try:
        client = AsyncIOMotorClient("mongodb://localhost:27017")
        await client.admin.command('ping')
        print("MongoDB is UP")
    except Exception as e:
        print(f"MongoDB is DOWN: {e}")

if __name__ == "__main__":
    asyncio.run(test_mongo())
