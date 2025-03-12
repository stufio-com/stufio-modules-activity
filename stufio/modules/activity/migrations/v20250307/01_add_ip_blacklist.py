from stufio.core.migrations.base import MongoMigrationScript


class AddIPBlacklist(MongoMigrationScript):
    name = "add_ip_blacklist"
    description = "Add IP blacklist collection"
    migration_type = "schema"
    order = 10

    async def run(self, db):
        # Create IP blacklist collection
        existing_collections = await db.list_collection_names()
        if "user_ip_blacklist" not in existing_collections:
            await db.create_collection("user_ip_blacklist")

        # Create indexes
        await db.command(
            {
                "createIndexes": "user_ip_blacklist",
                "indexes": [
                    {"key": {"ip": 1}, "name": "ip_lookup", "unique": True},
                    {
                        "key": {"expires_at": 1},
                        "name": "expiration_ttl",
                        "expireAfterSeconds": 0,
                    },
                ],
            }
        )
