from stufio.core.migrations.base import MongoMigrationScript
from datetime import datetime

class CreateRateLimitStatus(MongoMigrationScript):
    name = "create_rate_limit_status"
    description = "Create user_rate_limits collection for tracking rate limit status"
    migration_type = "schema"
    order = 20
    
    async def run(self, db):
        # Check if collection exists already - if not, create it
        existing_collections = await db.list_collection_names()
        if "user_rate_limits" not in existing_collections:
            await db.create_collection("user_rate_limits")
        
        # Create indexes
        await db.command({
            "createIndexes": "user_rate_limits",
            "indexes": [
                {
                    "key": {"user_id": 1},
                    "name": "user_id_lookup",
                    "background": True
                },
                {
                    "key": {"is_limited": 1},
                    "name": "limited_status",
                    "background": True
                },
                {
                    "key": {"limited_until": 1},
                    "name": "limited_until_index",
                    "background": True,
                    "expireAfterSeconds": 0  # TTL index
                },
                {
                    "key": {"updated_at": 1},
                    "name": "updated_at_index",
                    "background": True
                }
            ]
        })
        
        # Create IP rate limit status collection
        if "ip_rate_limits" not in existing_collections:
            await db.create_collection("ip_rate_limits")
        
        # Create indexes for IP limits
        await db.command({
            "createIndexes": "ip_rate_limits",
            "indexes": [
                {
                    "key": {"ip": 1},
                    "name": "ip_lookup",
                    "unique": True,
                    "background": True
                },
                {
                    "key": {"is_limited": 1},
                    "name": "limited_status",
                    "background": True
                },
                {
                    "key": {"limited_until": 1},
                    "name": "limited_until_index",
                    "background": True,
                    "expireAfterSeconds": 0  # TTL index
                }
            ]
        })