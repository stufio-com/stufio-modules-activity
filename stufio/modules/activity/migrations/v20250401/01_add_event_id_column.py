from clickhouse_connect.driver.asyncclient import AsyncClient
from stufio.core.migrations.base import ClickhouseMigrationScript

class AddEventIdColumn(ClickhouseMigrationScript):
    name = "add_event_id_column"
    description = "Add event_id column to user_activity table and update its primary key"
    migration_type = "schema"
    order = 10
    
    async def run(self, db: AsyncClient) -> None:
        # Check if column already exists to avoid errors
        columns = await db.query("DESCRIBE TABLE user_activity")
        column_names = [row[0] for row in columns.result_rows]
        
        if 'event_id' not in column_names:
            # Add event_id column
            await db.command("""
            ALTER TABLE user_activity 
            ADD COLUMN IF NOT EXISTS event_id String DEFAULT generateUUIDv4();
            """)
            
            # Create a temporary table with the correct schema
            await db.command("""
            CREATE TABLE IF NOT EXISTS user_activity_new (
                event_id String,
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
            PRIMARY KEY (event_id)
            ORDER BY (timestamp, event_id)
            PARTITION BY toYYYYMM(date)
            TTL date + INTERVAL 1 MONTH;
            """)
            
            # Copy data from old table to new table
            await db.command("""
            INSERT INTO user_activity_new
            SELECT * FROM user_activity;
            """)
            
            # Rename tables to swap them
            await db.command("""
            RENAME TABLE 
                user_activity TO user_activity_old,
                user_activity_new TO user_activity;
            """)
            
            # Drop the old table
            await db.command("""
            DROP TABLE IF EXISTS user_activity_old;
            """)