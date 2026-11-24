from backend.app.services.demo_services import DemoServiceRuntime


def test_order_flow_propagates_inventory_dependency_failure():
    services = DemoServiceRuntime()
    services.activate_scenario("inventory-dependency-latency")

    status, result = services.place_order("DEMO-001", 1, 999.0)

    assert status == 503
    assert result["failed_dependency"] == "inventory"
    assert result["dependency_error"]["error_code"] == "SUPPLIER_GATEWAY_TIMEOUT"


def test_payment_pool_fault_propagates_through_order_flow_and_can_be_reset():
    services = DemoServiceRuntime()
    services.activate_scenario("payment-pool-exhaustion")

    status, result = services.place_order("DEMO-001", 1, 999.0)
    assert status == 503
    assert result["failed_dependency"] == "payments"

    services.reset("payments")
    status, result = services.place_order("DEMO-001", 1, 999.0)
    assert status == 201
    assert result["status"] == "created"


def test_catalog_and_auth_faults_are_visible_on_their_service_endpoints():
    services = DemoServiceRuntime()
    services.activate_scenario("catalog-cache-stampede")
    status, catalog = services.list_products()
    assert status == 200 and catalog["status"] == "degraded"
    assert catalog["cache_hit_rate"] < 0.3

    services.activate_scenario("auth-memory-pressure")
    status, auth = services.issue_token()
    assert status == 503 and auth["error_code"] == "WORKER_OOM_RESTART"


def test_reset_all_services_clears_active_faults():
    services = DemoServiceRuntime()
    services.activate_scenario("payment-pool-exhaustion")
    services.activate_scenario("auth-memory-pressure")
    services.reset()
    assert all(item["status"] == "healthy" for item in services.statuses())
