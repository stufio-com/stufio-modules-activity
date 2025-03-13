from stufio.core.migrations.base import ClickhouseMigrationScript

class CreateSuspiciousActivityTable(ClickhouseMigrationScript):
    name = "create_suspicious_activity_table"
    description = "Create ClickHouse table for suspicious activity logs"
    migration_type = "schema"
    order = 50
    
    async def run(self, db):
        await db.command("""
        CREATE TABLE IF NOT EXISTS user_suspicious_activity_logs (
            timestamp DateTime64(3),
            date Date,
            user_id String,
            client_ip String,
            user_agent String,
            activity_type String,
            severity String,
            details String NULL,
            is_resolved Bool DEFAULT false,
            resolution_id String NULL
        ) ENGINE = MergeTree()
        PARTITION BY toYYYYMM(date)
        ORDER BY (user_id, timestamp)
        TTL date + INTERVAL 1 MONTH
        """)
