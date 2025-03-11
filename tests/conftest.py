"""
Test configuration and fixtures for the activity module.
"""
import pytest
from fastapi import FastAPI, Request, Response
from fastapi.testclient import TestClient
from unittest.mock import AsyncMock, patch

from stufio.modules.activity.middleware.activity_tracking import (
    ActivityTrackingMiddleware,
)
from stufio.modules.activity import ActivityModule

@pytest.fixture
def activity_module():
    """Return an instance of the activity module."""
    return ActivityModule()


@pytest.fixture
def client(app_with_activity):
    """Return a TestClient for the app with activity module."""
    return TestClient(app_with_activity)

import pytest
from fastapi import FastAPI

@pytest.fixture
def app_with_middleware():
    app = FastAPI()
    app.add_middleware(ActivityTrackingMiddleware)

    @app.get("/test")
    async def test_endpoint():
        return {"status": "ok"}

    @app.get("/metrics")
    async def metrics_endpoint():
        return {"metrics": "data"}

    return app


def test_activity_tracking_middleware(app_with_middleware, monkeypatch):
    # Mock the record_activity method
    mock_record = AsyncMock()
    monkeypatch.setattr(
        "modules.activity.middleware.activity_tracking.ActivityTrackingMiddleware._record_activity",
        mock_record,
    )

    # Test client
    client = TestClient(app_with_middleware)

    # Make request to tracked endpoint
    response = client.get("/test", headers={"User-Agent": "test-agent"})
    assert response.status_code == 200

    # Activity should be recorded
    assert mock_record.called

    # Test exempted endpoint (metrics)
    mock_record.reset_mock()
    response = client.get("/metrics")
    assert response.status_code == 200

    # Activity should NOT be recorded for metrics endpoint
    assert not mock_record.called
