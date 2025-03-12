import pytest
from datetime import datetime, timedelta
from motor.core import AgnosticDatabase
from clickhouse_connect.driver.asyncclient import AsyncClient
from unittest.mock import AsyncMock, MagicMock, patch

from stufio.modules.activity.crud.crud_activity import CRUDUserActivity
from stufio.modules.activity.models.activity import UserActivity, UserSecurityProfile


@pytest.fixture
def crud_activity():
    return CRUDUserActivity(UserActivity)


@pytest.mark.asyncio
async def test_create_activity(crud_activity):
    # Mock database
    db = AsyncMock(spec=AgnosticDatabase)
    db.__getitem__.return_value.insert_one.return_value = AsyncMock()

    # Test creating activity
    activity = await crud_activity.create_activity(
        db=db,
        user_id="test_user",
        path="/test",
        method="GET",
        client_ip="127.0.0.1",
        user_agent="test-agent",
        status_code=200,
        process_time=0.05,
    )

    # Verify activity created with correct values
    assert activity.user_id == "test_user"
    assert activity.path == "/test"
    assert activity.method == "GET"
    assert activity.status_code == 200

    # Verify database was called
    db.__getitem__.return_value.insert_one.assert_called_once()


@pytest.mark.asyncio
async def test_check_suspicious_activity(crud_activity):
    # Mock database with security profile
    db = AsyncMock(spec=AgnosticDatabase)

    # Mock finding security profile
    security_profile = UserSecurityProfile(
        user_id="test_user",
        known_ips=["127.0.0.1"],
        known_user_agents=["test-agent"],
        last_login=datetime.utcnow(),
        suspicious_activity_count=0,
    )

    with patch.object(crud_activity, "engine") as mock_engine:
        mock_engine.find.return_value = [security_profile]

        # Should not be suspicious (known IP and agent)
        result = await crud_activity.check_suspicious_activity(
            db=db, user_id="test_user", client_ip="127.0.0.1", user_agent="test-agent"
        )

        assert result is False
