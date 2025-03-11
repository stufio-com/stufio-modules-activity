from motor.core import AgnosticDatabase
from stufio.core.migrations.base import MongoMigrationScript

class InitCollections(MongoMigrationScript):
    name = "init_collections"
    description = "Initialize collections for activity module"
    migration_type = "init"
    order = 10  # Low number ensures it runs first
    
    async def run(self, db: AgnosticDatabase) -> None:
        # Create collections with appropriate settings
        collections = [
            "user_security_profiles"
        ]
        
        for collection in collections:
            # Check if collection exists
            existing_collections = await db.list_collection_names()
            if collection not in existing_collections:
                # Create collection
                await db.create_collection(collection)