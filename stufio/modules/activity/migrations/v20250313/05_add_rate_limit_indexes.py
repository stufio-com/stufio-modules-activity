from stufio.core.migrations.base import ClickhouseMigrationScript
from stufio.db.clickhouse import get_database_from_dsn
import logging

class AddRateLimitIndexes(ClickhouseMigrationScript):
    name = "add_rate_limit_indexes"
    description = "Add indexes to optimize rate limiting queries"
    migration_type = "schema"
    order = 50  # Run after creating tables/views

    async def _safe_execute(self, db, query, error_message):
        """Execute a command and handle the case where it might already exist"""
        try:
            await db.command(query)
            return True
        except Exception as e:
            if "already exists" in str(e):
                logging.info(f"Index already exists (this is OK): {error_message}")
                return True
            logging.error(f"Error executing query: {error_message} - {e}")
            return False

    async def run(self, db):
        success = True
        db_name = get_database_from_dsn()
        
        # Add indexes for rate_limit_violations table
        indexes = [
            ("idx_client_ip_timestamp", "client_ip, timestamp"),
            ("idx_user_id_timestamp", "user_id, timestamp"),
            ("idx_type_timestamp", "type, timestamp"),
        ]
        
        for idx_name, columns in indexes:
            success = success and await self._safe_execute(
                db,
                f"""
                ALTER TABLE `{db_name}`.`rate_limit_violations`
                ADD INDEX {idx_name} ({columns}) 
                TYPE minmax 
                GRANULARITY 3;
                """,
                f"Adding index {idx_name} to rate_limit_violations"
            )
        
        # Add projection for faster time-based lookups
        success = success and await self._safe_execute(
            db,
            f"""
            ALTER TABLE `{db_name}`.`rate_limit_violations`
            ADD PROJECTION proj_recent_violations
            (
                SELECT *
                ORDER BY timestamp
            );
            """,
            "Adding projection to rate_limit_violations"
        )
        
        # Try to materialize projection (this might fail if already materialized)
        await self._safe_execute(
            db,
            f"""
            ALTER TABLE `{db_name}`.`rate_limit_violations`
            MATERIALIZE PROJECTION proj_recent_violations;
            """,
            "Materializing projection on rate_limit_violations"
        )
        
        # Add indices to materialized view tables
        table_indices = [
            ("ip_rate_limits", "idx_ip_minute", "ip, minute"),
            ("user_rate_limits", "idx_user_path_minute", "user_id, path, minute"),
            ("endpoint_rate_limits", "idx_path_ip_minute", "path, client_ip, minute"),
        ]
        
        for table, idx_name, columns in table_indices:
            success = success and await self._safe_execute(
                db,
                f"""
                ALTER TABLE `{db_name}`.`{table}`
                ADD INDEX {idx_name} ({columns})
                TYPE minmax
                GRANULARITY 3;
                """,
                f"Adding index {idx_name} to {table}"
            )
        
        return success