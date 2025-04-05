from typing import List, Tuple
import logging
from clickhouse_connect.driver.asyncclient import AsyncClient
from stufio.crud.clickhouse_base import CRUDClickhouse
from ..models import UserActivity
from ..schemas import ErrorReport, PathStatistics

logger = logging.getLogger(__name__)

class CRUDAnalytics:
    """
    CRUD operations for analytics data in ClickHouse.
    Handles API requests logging, user behavior analysis, and performance metrics.
    """
    def __init__(self):
        """Initialize ClickHouse handler"""
        self.clickhouse = CRUDClickhouse(UserActivity)

    async def get_path_statistics(
        self,
        path: str = None,
        hours: int = 24
    ) -> List[PathStatistics]:
        """
        Get statistics for a specific API path or all paths
        
        Args:
            path: Optional specific path to analyze
            hours: Number of hours to analyze
            
        Returns:
            Dict with path statistics
        """
        try:
            where_clause = "WHERE date >= today() - 1"
            if path:
                where_clause += f" AND path = '{path}'"

            result = await self.clickhouse.client.query(
                f"""
                SELECT 
                    path,
                    count() AS request_count,
                    avg(process_time) AS avg_response_time,
                    max(process_time) AS max_response_time,
                    countIf(status_code >= 400) / count() AS error_rate,
                    uniq(user_id) AS unique_users
                FROM {UserActivity.get_table_name()}
                {where_clause}
                GROUP BY path
                ORDER BY request_count DESC
                LIMIT 100
                """
            )

            return list([PathStatistics(**row) for row in list(result.named_results())])
        except Exception as e:
            logger.error(f"Error getting path statistics: {str(e)}")
            return []

    async def get_error_report(
        self,
        *,
        days: int = 1
    ) -> List[ErrorReport]:
        """
        Get report of API errors
        
        Args:
            days: Number of days to analyze
            
        Returns:
            Dict with error report
        """
        try:
            result =  await self.clickhouse.client.query(
                """
                SELECT 
                    path,
                    status_code,
                    count() AS error_count,
                    max(timestamp) AS latest_occurrence
                FROM {table}
                WHERE date >= today() - {days} AND status_code >= 400
                GROUP BY path, status_code
                ORDER BY error_count DESC
                """,
                parameters={"days": days, "table": UserActivity.get_table_name()},
            )

            return list([ErrorReport(**row) for row in list(result.named_results())])
        except Exception as e:
            logger.error(f"Error getting error report: {str(e)}")
            return []

# Single instance for import
crud_analytics = CRUDAnalytics()
