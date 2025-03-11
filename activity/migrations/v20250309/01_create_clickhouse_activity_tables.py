from stufio.core.migrations.base import ClickhouseMigrationScript

class CreateActivityTables(ClickhouseMigrationScript):
    name = "create_activity_tables"
    description = "Create ClickHouse table rate_limit_counters"
    migration_type = "schema"
    order = 10
    
    async def run(self, db):
        # Create rate_limit_counters table
        await db.command("""
        CREATE TABLE IF NOT EXISTS rate_limit_counters (
            key String,
            type String,
            counter UInt32,
            window_start DateTime,
            last_request DateTime64(3),
            ip String,
            user_id String,
            endpoint String
        ) ENGINE = MergeTree()
        ORDER BY (key, window_start)
        TTL window_start + INTERVAL 1 DAY;
        """)