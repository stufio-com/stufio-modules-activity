from clickhouse_connect.driver.asyncclient import AsyncClient
from stufio.core.migrations.base import ClickhouseMigrationScript
from stufio.db.clickhouse import get_database_from_dsn

class CreateRateLimitViews(ClickhouseMigrationScript):
    name = "create_rate_limit_views"
    description = "Create materialized views for efficient rate limiting"
    migration_type = "schema"
    order = 10

    async def run(self, db: AsyncClient) -> None:
        # Execute all commands sequentially with proper awaits
        try:
            db_name = get_database_from_dsn()
            # Create IP-based rate limiting aggregated table
            await db.command(f"""
            CREATE TABLE IF NOT EXISTS `{db_name}`.`ip_rate_limits`
            (
                ip String,
                minute DateTime,
                request_count AggregateFunction(count, UInt64),
                PRIMARY KEY (ip, minute)
            )
            ENGINE = AggregatingMergeTree()
            ORDER BY (ip, minute)
            TTL minute + INTERVAL 1 DAY;
            """)

            # Create materialized view for IP-based rate limits
            await db.command(f"""
            CREATE MATERIALIZED VIEW IF NOT EXISTS `{db_name}`.`ip_rate_limits_mv`
            TO ip_rate_limits
            AS
            SELECT 
                client_ip AS ip,
                toStartOfMinute(timestamp) AS minute,
                countState() AS request_count
            FROM user_activity
            GROUP BY ip, minute;
            """)

            # Create user-based rate limiting aggregated table
            await db.command(f"""
            CREATE TABLE IF NOT EXISTS `{db_name}`.`user_rate_limits`
            (
                user_id String,
                path String,
                minute DateTime,
                request_count AggregateFunction(count, UInt64),
                PRIMARY KEY (user_id, path, minute)
            )
            ENGINE = AggregatingMergeTree()
            ORDER BY (user_id, path, minute)
            TTL minute + INTERVAL 1 DAY;
            """)

            # Create materialized view for user-based rate limits
            await db.command(f"""
            CREATE MATERIALIZED VIEW IF NOT EXISTS `{db_name}`.`user_rate_limits_mv`
            TO user_rate_limits
            AS
            SELECT 
                user_id,
                path,
                toStartOfMinute(timestamp) AS minute,
                countState() AS request_count
            FROM user_activity
            WHERE user_id != ''
            GROUP BY user_id, path, minute;
            """)

            # Create endpoint-based rate limiting aggregated table
            await db.command(f"""
            CREATE TABLE IF NOT EXISTS `{db_name}`.`endpoint_rate_limits`
            (
                path String,
                client_ip String,
                minute DateTime,
                request_count AggregateFunction(count, UInt64),
                PRIMARY KEY (path, client_ip, minute)
            )
            ENGINE = AggregatingMergeTree()
            ORDER BY (path, client_ip, minute)
            TTL minute + INTERVAL 1 DAY;
            """)

            # Create materialized view for endpoint-based rate limits
            await db.command(f"""
            CREATE MATERIALIZED VIEW IF NOT EXISTS `{db_name}`.`endpoint_rate_limits_mv`
            TO endpoint_rate_limits
            AS
            SELECT 
                path,
                client_ip,
                toStartOfMinute(timestamp) AS minute,
                countState() AS request_count
            FROM user_activity
            GROUP BY path, client_ip, minute;
            """)
        except Exception as e:
            # Explicitly log and re-raise so the migration system knows it failed
            import logging
            logging.error(f"Error creating rate limit views: {e}")
            raise
