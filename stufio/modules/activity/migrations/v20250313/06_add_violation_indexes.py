from stufio.core.migrations.base import ClickhouseMigrationScript
from stufio.db.clickhouse import get_database_from_dsn

class AddViolationIndexes(ClickhouseMigrationScript):
    name = "add_violation_indexes"
    description = "Add additional indexes for fast violation lookups"
    migration_type = "schema"
    order = 60

    async def run(self, db):
        try:
            db_name = get_database_from_dsn()
            
            # Add user-specific indexes for fast lookups
            await db.command(f"""
            ALTER TABLE `{db_name}`.`rate_limit_violations`
            ADD INDEX IF NOT EXISTS idx_user_path_timestamp (user_id, endpoint, timestamp) 
            TYPE minmax 
            GRANULARITY 3;
            """)
            
            # Add composite index for endpoint+ip lookups
            await db.command(f"""
            ALTER TABLE `{db_name}`.`rate_limit_violations`
            ADD INDEX IF NOT EXISTS idx_endpoint_ip_timestamp (endpoint, client_ip, timestamp) 
            TYPE minmax 
            GRANULARITY 3;
            """)
            
            # Add type-based index for segmentation
            await db.command(f"""
            ALTER TABLE `{db_name}`.`rate_limit_violations`
            ADD INDEX IF NOT EXISTS idx_type_timestamp (type, timestamp) 
            TYPE minmax 
            GRANULARITY 3;
            """)
            
            return True
        except Exception as e:
            import logging
            logging.error(f"Error adding violation indexes: {e}")
            raise