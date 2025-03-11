from stufio.core.migrations.base import MongoMigrationScript
from datetime import datetime

class AddRateLimitOverrides(MongoMigrationScript):
    name = "add_rate_limit_overrides"
    description = "Add rate_limit_overrides collection with indexes"
    migration_type = "schema"
    order = 20
    
    async def run(self, db):
        # Check if collection exists already - if not, create it
        existing_collections = await db.list_collection_names()
        if "rate_limit_overrides" not in existing_collections:
            await db.create_collection("rate_limit_overrides")
        
        # Create indexes
        await db.command({
            "createIndexes": "rate_limit_overrides",
            "indexes": [
                {
                    "key": {"user_id": 1, "path": 1},
                    "name": "user_path_lookup",
                    "unique": True,
                    "background": True
                },
                {
                    "key": {"user_id": 1},
                    "name": "user_lookup",
                    "background": True
                },
                {
                    "key": {"expires_at": 1},
                    "name": "expires_at_index",
                    "background": True,
                    "expireAfterSeconds": 0  # TTL index based on the expires_at field
                }
            ]
        })
        
        # Insert some example overrides for testing
        # example_overrides = [
        #     {
        #         "user_id": "admin",
        #         "path": "*",
        #         "max_requests": 1000,
        #         "window_seconds": 60,
        #         "created_at": datetime.utcnow(),
        #         "expires_at": None,
        #         "created_by": "system",
        #         "reason": "Admin unlimited access"
        #     },
        #     {
        #         "user_id": "premium_user",
        #         "path": "/api/v1/domains/analysis",
        #         "max_requests": 100,
        #         "window_seconds": 60,
        #         "created_at": datetime.utcnow(),
        #         "expires_at": None,
        #         "created_by": "system",
        #         "reason": "Premium tier benefits"
        #     }
        # ]
        
        # for override in example_overrides:
        #     # Use update with upsert to avoid duplicates
        #     await db.rate_limit_overrides.update_one(
        #         {"user_id": override["user_id"], "path": override["path"]},
        #         {"$setOnInsert": override},
        #         upsert=True
        #     )