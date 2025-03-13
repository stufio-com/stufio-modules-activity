from clickhouse_connect.driver.asyncclient import AsyncClient
from stufio.core.migrations.base import ClickhouseMigrationScript

class CreateAnalyticsTables(ClickhouseMigrationScript):
    name = "create_analytics_tables"
    description = "Create ClickHouse tables for activity analytics"
    migration_type = "schema"
    order = 30
    
    async def run(self, db: AsyncClient) -> None:
        # Create user activity summary table
        await db.command("""
        CREATE TABLE IF NOT EXISTS user_activity_summary (
            day Date,
            user_id String,
            request_count UInt32,
            avg_response_time Float32,
            unique_endpoints UInt16,
            error_count UInt16
        ) ENGINE = SummingMergeTree()
        ORDER BY (day, user_id)
        PARTITION BY toYYYYMM(day)
        TTL day + INTERVAL 3 MONTH;
        """)
        
        # Create path statistics table
        await db.command("""
        CREATE TABLE IF NOT EXISTS user_activity_path_stat (
            day Date,
            path String,
            request_count UInt32,
            avg_response_time Float32,
            max_response_time Float32,
            error_rate Float32,
            unique_users UInt32
        ) ENGINE = SummingMergeTree()
        ORDER BY (day, path)
        PARTITION BY toYYYYMM(day)
        TTL day + INTERVAL 3 MONTH;
        """)
        
        # Create error statistics table
        await db.command("""
        CREATE TABLE IF NOT EXISTS user_activity_error_stat (
            day Date,
            path String,
            status_code UInt16,
            error_count UInt32,
            latest_occurrence DateTime64(3)
        ) ENGINE = ReplacingMergeTree(latest_occurrence)
        ORDER BY (day, path, status_code)
        PARTITION BY toYYYYMM(day)
        TTL day + INTERVAL 3 MONTH;
        """)