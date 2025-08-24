from stufio.core.migrations.base import MongoMigrationScript
from datetime import datetime
from stufio.core.config import get_settings

settings = get_settings()

class SeedRateLimitConfigs(MongoMigrationScript):
    name = "seed_rate_limit_configs"
    description = "Seed rate limit configurations from settings"
    migration_type = "data"
    order = 40

    async def run(self, db):
        # Create rate_limit_configs collection if it doesn't exist
        existing_collections = await db.list_collection_names()
        if "rate_limit_configs" not in existing_collections:
            await db.create_collection("rate_limit_configs")

        # Create or update indexes
        await db.command({
            "createIndexes": "rate_limit_configs",
            "indexes": [
                {
                    "key": {"endpoint": 1},
                    "name": "endpoint_lookup",
                    "unique": True
                },
                {
                    "key": {"active": 1},
                    "name": "active_configs"
                }
            ]
        })

        # Import default configs from settings
        now = datetime.utcnow()

        # Add global default config
        global_defaults = [
            {
                "endpoint": "*",  # Global default
                "max_requests": settings.activity_RATE_LIMIT_USER_MAX_REQUESTS,
                "window_seconds": settings.activity_RATE_LIMIT_USER_WINDOW_SECONDS,
                "active": True,
                "bypass_roles": ["admin", "system"],
                "description": "Global default rate limit",
                "created_at": now,
                "updated_at": now,
            }
        ]

        # Add configs from settings
        endpoint_configs = []
        for endpoint, config in settings.activity_RATE_LIMIT_ENDPOINTS.items():
            endpoint_configs.append({
                "endpoint": endpoint,
                "max_requests": config.get("max_requests", 100),
                "window_seconds": config.get("window_seconds", 60),
                "active": True,
                "bypass_roles": ["admin", "system"],
                "description": f"Rate limit for {endpoint}",
                "created_at": now,
                "updated_at": now
            })

        # Additional pre-defined rate limits for common endpoints
        additional_configs = [
            {
                "endpoint": "/api/v1/login*",
                "max_requests": 5,
                "window_seconds": 60,
                "active": True,
                "bypass_roles": ["admin", "system"],
                "description": "Login endpoint rate limit",
                "created_at": now,
                "updated_at": now
            },
            {
                "endpoint": "/api/v1/users*",
                "max_requests": 20,
                "window_seconds": 60,
                "active": True,
                "bypass_roles": ["admin", "system"],
                "description": "Users API rate limit",
                "created_at": now,
                "updated_at": now
            },
            {
                "endpoint": "/api/v1/domains*",
                "max_requests": 30,
                "window_seconds": 60,
                "active": True,
                "bypass_roles": ["admin", "system", "premium"],
                "description": "Domains API rate limit",
                "created_at": now,
                "updated_at": now
            }
        ]

        # Combine all configs
        all_configs = global_defaults + endpoint_configs + additional_configs

        # Upsert all configs
        for config in all_configs:
            await db.rate_limit_configs.update_one(
                {"endpoint": config["endpoint"]},
                {"$set": config},
                upsert=True
            )

        print(f"Seeded {len(all_configs)} rate limit configurations")
