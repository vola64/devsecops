"""
Tests unitaires — Application FastAPI DevSecOps
"""
import pytest
from fastapi.testclient import TestClient

# Ajout du répertoire src au path Python
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from app import app

client = TestClient(app)


# ─── Tests endpoint racine ────────────────────────────────────────────────────
class TestRoot:
    def test_root_returns_200(self):
        response = client.get("/")
        assert response.status_code == 200

    def test_root_returns_json(self):
        response = client.get("/")
        data = response.json()
        assert "message" in data
        assert "version" in data
        assert "docs" in data

    def test_root_message_content(self):
        response = client.get("/")
        assert "DevSecOps" in response.json()["message"]


# ─── Tests health check ──────────────────────────────────────────────────────
class TestHealthCheck:
    def test_health_returns_200(self):
        response = client.get("/health")
        assert response.status_code == 200

    def test_health_status_is_healthy(self):
        response = client.get("/health")
        data = response.json()
        assert data["status"] == "healthy"

    def test_health_has_version(self):
        response = client.get("/health")
        data = response.json()
        assert "version" in data
        assert len(data["version"]) > 0

    def test_health_has_uptime(self):
        response = client.get("/health")
        data = response.json()
        assert "uptime_seconds" in data
        assert data["uptime_seconds"] >= 0


# ─── Tests liste des items ────────────────────────────────────────────────────
class TestListItems:
    def test_list_items_returns_200(self):
        response = client.get("/items")
        assert response.status_code == 200

    def test_list_items_returns_list(self):
        response = client.get("/items")
        assert isinstance(response.json(), list)

    def test_list_items_not_empty(self):
        response = client.get("/items")
        assert len(response.json()) >= 2

    def test_list_items_active_filter(self):
        response = client.get("/items?active_only=true")
        assert response.status_code == 200
        items = response.json()
        for item in items:
            assert item["is_active"] is True

    def test_list_items_schema(self):
        response = client.get("/items")
        item = response.json()[0]
        assert "id" in item
        assert "name" in item
        assert "price" in item
        assert "is_active" in item


# ─── Tests récupérer un item ──────────────────────────────────────────────────
class TestGetItem:
    def test_get_existing_item(self):
        response = client.get("/items/1")
        assert response.status_code == 200

    def test_get_item_correct_id(self):
        response = client.get("/items/1")
        data = response.json()
        assert data["id"] == 1

    def test_get_item_not_found(self):
        response = client.get("/items/9999")
        assert response.status_code == 404

    def test_get_item_not_found_detail(self):
        response = client.get("/items/9999")
        assert "detail" in response.json()

    def test_get_item_invalid_id_zero(self):
        response = client.get("/items/0")
        assert response.status_code == 422

    def test_get_item_invalid_id_negative(self):
        response = client.get("/items/-1")
        assert response.status_code == 422


# ─── Tests créer un item ──────────────────────────────────────────────────────
class TestCreateItem:
    def test_create_valid_item(self):
        payload = {"name": "Nouvel Item", "price": 15.99}
        response = client.post("/items", json=payload)
        assert response.status_code == 201

    def test_create_item_returns_item(self):
        payload = {"name": "Item Test", "price": 9.99}
        response = client.post("/items", json=payload)
        data = response.json()
        assert data["name"] == "Item Test"
        assert data["price"] == 9.99

    def test_create_item_with_description(self):
        payload = {
            "name": "Item Complet",
            "description": "Une description",
            "price": 19.99,
        }
        response = client.post("/items", json=payload)
        assert response.status_code == 201
        assert response.json()["description"] == "Une description"

    def test_create_item_negative_price_rejected(self):
        payload = {"name": "Item Invalide", "price": -5.0}
        response = client.post("/items", json=payload)
        assert response.status_code == 422

    def test_create_item_zero_price_rejected(self):
        payload = {"name": "Item Invalide", "price": 0}
        response = client.post("/items", json=payload)
        assert response.status_code == 422

    def test_create_item_empty_name_rejected(self):
        payload = {"name": "", "price": 10.0}
        response = client.post("/items", json=payload)
        assert response.status_code == 422

    def test_create_item_too_long_name_rejected(self):
        payload = {"name": "A" * 101, "price": 10.0}
        response = client.post("/items", json=payload)
        assert response.status_code == 422

    def test_create_item_auto_increments_id(self):
        payload1 = {"name": "Item Seq 1", "price": 1.0}
        payload2 = {"name": "Item Seq 2", "price": 2.0}
        r1 = client.post("/items", json=payload1)
        r2 = client.post("/items", json=payload2)
        assert r2.json()["id"] > r1.json()["id"]


# ─── Tests utilitaires (utils.py) ────────────────────────────────────────────
class TestUtils:
    def test_sanitize_removes_dangerous_chars(self):
        from utils import sanitize_input
        result = sanitize_input("Hello<script>alert('xss')</script>")
        assert "<script>" not in result
        assert "alert" not in result

    def test_sanitize_keeps_normal_text(self):
        from utils import sanitize_input
        result = sanitize_input("Hello World")
        assert result == "Hello World"

    def test_sanitize_strips_whitespace(self):
        from utils import sanitize_input
        result = sanitize_input("  test  ")
        assert result == "test"

    def test_sanitize_empty_after_clean_raises(self):
        from utils import sanitize_input
        with pytest.raises(ValueError):
            sanitize_input("<><><>")

    def test_mask_sensitive_masks_password(self):
        from utils import mask_sensitive
        data = {"username": "admin", "password": "secret123"}
        result = mask_sensitive(data)
        assert result["password"] == "***REDACTED***"
        assert result["username"] == "admin"

    def test_mask_sensitive_masks_token(self):
        from utils import mask_sensitive
        data = {"api_key": "abc123", "data": "visible"}
        result = mask_sensitive(data)
        assert result["api_key"] == "***REDACTED***"
        assert result["data"] == "visible"

    def test_mask_sensitive_nested(self):
        from utils import mask_sensitive
        data = {"config": {"secret": "hidden", "host": "localhost"}}
        result = mask_sensitive(data)
        assert result["config"]["secret"] == "***REDACTED***"
        assert result["config"]["host"] == "localhost"
