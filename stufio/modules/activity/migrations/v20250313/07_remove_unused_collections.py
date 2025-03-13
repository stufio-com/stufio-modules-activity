from stufio.core.migrations.base import MongoMigrationScript
import logging

class RemoveUnusedCollections(MongoMigrationScript):
    name = "remove_unused_collections"
    description = "Remove unused MongoDB collections that were replaced by ClickHouse functionality"
    migration_type = "schema"
    order = 70
    
    async def run(self, db):
        try:
            # Check if collection exists
            existing_collections = await db.list_collection_names()
            
            # Remove ip_rate_limits MongoDB collection (now handled in ClickHouse)
            if "ip_rate_limits" in existing_collections:
                logging.info("Dropping unused ip_rate_limits MongoDB collection")
                await db.drop_collection("ip_rate_limits")
                
            return True
        except Exception as e:
            logging.error(f"Error removing unused collections: {str(e)}")
            raise