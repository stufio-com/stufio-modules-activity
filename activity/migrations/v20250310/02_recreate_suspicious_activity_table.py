from stufio.core.migrations.base import ClickhouseMigrationScript
from stufio.db.clickhouse import get_database_from_dsn

class RecreateSuspiciousActivityTable(ClickhouseMigrationScript):
    name = "recreate_suspicious_activity_table"
    description = "Drop and recreate the suspicious activity table with all required columns"
    migration_type = "schema"
    order = 20

    async def run(self, db):
        db_name = get_database_from_dsn()
        
        # Drop existing table if it exists
        await db.command(f"""
        DROP TABLE IF EXISTS `{db_name}`.`user_suspicious_activity_logs`
        """)

        # Create new table with all columns
        await db.command(f"""
        CREATE TABLE IF NOT EXISTS `{db_name}`.`user_suspicious_activity` (
            timestamp DateTime64(3),
            date Date,
            user_id String,
            client_ip String,
            user_agent String,
            path String,
            method String,
            status_code Int32,
            activity_type String,
            severity String,
            details String NULL,
            is_resolved Bool DEFAULT false,
            resolution_id String NULL
        ) ENGINE = MergeTree()
        PARTITION BY toYYYYMM(date)
        ORDER BY (user_id, timestamp)
        TTL toDateTime(date) + INTERVAL 1 MONTH
        SETTINGS allow_nullable_key=1
        """)
