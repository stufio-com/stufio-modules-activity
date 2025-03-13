from stufio.core.migrations.base import ClickhouseMigrationScript

class CleanupLegacyRateTables(ClickhouseMigrationScript):
    name = "cleanup_legacy_rate_tables"
    description = "Remove legacy rate limit tables that are replaced by materialized views"
    migration_type = "schema"
    order = 30
    
    async def run(self, db):
        try:
            # We're keeping rate_limit_violations as it's still used
            # But rate_limits can be dropped since materialized views handle this now
            await db.command("""
            DROP TABLE IF EXISTS rate_limits;
            """)
            
            return True
        except Exception as e:
            import logging
            logging.error(f"Error cleaning up legacy rate tables: {e}")
            raise