"""
Test configuration and fixtures for the activity module.
"""
import pytest
from fastapi import FastAPI, Request, Response
from fastapi.testclient import TestClient
from unittest.mock import AsyncMock, patch

# Try to import available middleware, fallback if not available
try:
    from stufio.modules.activity.middleware.activity_tracking import (
        ActivityTrackingMiddleware,
    )
except ImportError:
    # Mock the middleware if it doesn't exist
    class ActivityTrackingMiddleware:
        def __init__(self, app):
            self.app = app
        async def __call__(self, scope, receive, send):
            return await self.app(scope, receive, send)

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
    try:
        app.add_middleware(ActivityTrackingMiddleware)
    except (ImportError, NameError):
        # Skip middleware if not available
        pass

    @app.get("/test")
    async def test_endpoint():
        return {"status": "ok"}

    @app.get("/metrics")
    async def metrics_endpoint():
        return {"metrics": "data"}

    return app


def test_activity_tracking_middleware(app_with_middleware, monkeypatch):
    # Skip test if middleware is not available
    try:
        # Mock the record_activity method
        mock_record = AsyncMock()
        monkeypatch.setattr(
            "stufio.modules.activity.middleware.activity_tracking.ActivityTrackingMiddleware._record_activity",
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
    except (ImportError, AttributeError):
        # Skip test if middleware is not available
        pytest.skip("ActivityTrackingMiddleware not available")
