from motor.core import AgnosticDatabase
from stufio.core.migrations.base import MongoMigrationScript


class CreateIndexes(MongoMigrationScript):
    name = "create_indexes"
    description = "Create indexes for activity module collections"
    migration_type = "schema"
    order = 20

    async def run(self, db):
        # Create indexes on security profiles
        await db.command({
            "createIndexes": "user_security_profiles",
            "indexes": [
                {
                    "key": {"user_id": 1},
                    "name": "security_profile_lookup",
                    "unique": True
                }
            ]
        })
