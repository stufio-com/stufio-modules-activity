from stufio.core.migrations.base import ClickhouseMigrationScript

class CreateRateLimitTables(ClickhouseMigrationScript):
    name = "create_rate_limit_tables"
    description = "Create ClickHouse tables for rate limiting"
    migration_type = "schema"
    order = 10
    
    async def run(self, db):
        # Create rate limits table
        await db.command("""
        CREATE TABLE IF NOT EXISTS rate_limits (
            timestamp DateTime64(3),
            date Date,
            key String,
            type String,
            counter UInt32,
            window_start DateTime64(3),
            window_end DateTime64(3),
            ip String NULL,
            user_id String NULL,
            endpoint String NULL
        ) ENGINE = MergeTree()
        PARTITION BY toYYYYMM(date)
        ORDER BY (key, window_start)
        TTL date + INTERVAL 1 DAY;
        """)
        
        # Create rate limit violations table
        await db.command("""
        CREATE TABLE IF NOT EXISTS rate_limit_violations (
            timestamp DateTime64(3),
            date Date,
            key String,
            type String,
            limit UInt32,
            attempts UInt32,
            user_id String NULL,
            client_ip String NULL,
            endpoint String NULL
        ) ENGINE = MergeTree()
        PARTITION BY toYYYYMM(date)
        ORDER BY (date, timestamp, type)
        TTL date + INTERVAL 1 MONTH;
        """)