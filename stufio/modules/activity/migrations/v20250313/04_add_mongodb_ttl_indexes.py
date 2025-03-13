from stufio.core.migrations.base import MongoMigrationScript
import logging

class AddMongoRateLimitTTLIndexes(MongoMigrationScript):
    name = "add_mongodb_ttl_indexes"
    description = "Add TTL indexes to MongoDB rate limit collections"
    migration_type = "schema"
    order = 40
    
    async def run(self, db):
        try:
            # First, check what indexes already exist
            existing_indexes = await db.user_rate_limits.list_indexes().to_list(None)
            existing_index_names = [idx['name'] for idx in existing_indexes]
            
            # Create TTL index only if it doesn't exist
            if "limited_until_ttl" not in existing_index_names and "limited_until_index" not in existing_index_names:
                logging.info("Creating limited_until_ttl index")
                await db.command({
                    "createIndexes": "user_rate_limits",
                    "indexes": [
                        {
                            "key": {"limited_until": 1},
                            "name": "limited_until_ttl",
                            "expireAfterSeconds": 0  # Expire exactly at the time in limited_until
                        }
                    ]
                })
            else:
                logging.info("TTL index on limited_until already exists, skipping")
            
            # Create user_id index only if it doesn't exist with a unique constraint
            has_user_id_unique = False
            for idx in existing_indexes:
                if 'unique' in idx and idx.get('unique') and 'key' in idx and 'user_id' in idx['key']:
                    has_user_id_unique = True
                    break
            
            if not has_user_id_unique:
                logging.info("Creating unique user_id index")
                await db.command({
                    "createIndexes": "user_rate_limits",
                    "indexes": [
                        {
                            "key": {"user_id": 1},
                            "name": "user_id_idx",
                            "unique": True
                        }
                    ]
                })
            
            # Create is_limited index if needed
            if "is_limited_idx" not in existing_index_names and "limited_status" not in existing_index_names:
                logging.info("Creating is_limited index")
                await db.command({
                    "createIndexes": "user_rate_limits",
                    "indexes": [
                        {
                            "key": {"is_limited": 1},
                            "name": "is_limited_idx"
                        }
                    ]
                })
            
            return True
        except Exception as e:
            logging.error(f"Error creating indexes: {str(e)}")
            raise