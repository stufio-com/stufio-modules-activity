from clickhouse_connect.driver.asyncclient import AsyncClient
from stufio.core.migrations.base import ClickhouseMigrationScript

class CreateRequestLogTable(ClickhouseMigrationScript):
    name = "create_request_log_table"
    description = "Create ClickHouse tables for activity logging"
    migration_type = "schema"
    order = 30
    
    async def run(self, db: AsyncClient) -> None:
        # Create API logs table if it doesn't exist
        await db.command("""
        CREATE TABLE IF NOT EXISTS user_activity (
            timestamp DateTime64(3),
            date Date,
            user_id String,
            path String,
            method String,
            client_ip String,
            user_agent String,
            status_code UInt16,
            process_time Float32,
            is_authenticated UInt8
        ) ENGINE = MergeTree()
        PARTITION BY toYYYYMM(date)
        ORDER BY (date, timestamp, user_id, path)
        TTL date + INTERVAL 1 MONTH;
        """)