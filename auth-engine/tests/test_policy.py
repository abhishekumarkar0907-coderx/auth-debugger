"""Tests for auth_engine.policy — action requirement registry."""

from auth_engine.policy import ActionPolicy, default_otel_demo_policy


class TestActionPolicy:
    def test_register_and_lookup(self):
        policy = ActionPolicy()
        policy.register(
            semantic_action="payments:charge",
            required_permissions=["payments:charge"],
            raw_span_names=["oteldemo.PaymentService/Charge"],
        )
        perms = policy.required_permissions_for(semantic_action="payments:charge")
        assert perms == frozenset({"payments:charge"})

    def test_resolve_span(self):
        policy = ActionPolicy()
        policy.register(
            semantic_action="payments:charge",
            raw_span_names=["oteldemo.PaymentService/Charge", "charge"],
        )
        assert policy.resolve_span("oteldemo.PaymentService/Charge") == "payments:charge"
        assert policy.resolve_span("charge") == "payments:charge"
        assert policy.resolve_span("unknown") is None

    def test_lookup_by_raw_span(self):
        policy = ActionPolicy()
        policy.register(
            semantic_action="payments:charge",
            required_permissions=["payments:charge"],
            raw_span_names=["oteldemo.PaymentService/Charge"],
        )
        perms = policy.required_permissions_for(
            raw_span_name="oteldemo.PaymentService/Charge"
        )
        assert perms == frozenset({"payments:charge"})

    def test_unknown_action_returns_none(self):
        policy = ActionPolicy()
        assert policy.required_permissions_for(semantic_action="unknown") is None
        assert policy.required_permissions_for(raw_span_name="unknown") is None

    def test_default_permission_is_action_name(self):
        """When no required_permissions is given, it defaults to the action name."""
        policy = ActionPolicy()
        policy.register(semantic_action="orders:read")
        req = policy.get_requirement("orders:read")
        assert req is not None
        assert req.required_permissions == frozenset({"orders:read"})

    def test_get_requirement(self):
        policy = ActionPolicy()
        policy.register(
            semantic_action="orders:create",
            description="Create an order",
        )
        req = policy.get_requirement("orders:create")
        assert req is not None
        assert req.description == "Create an order"

    def test_multiple_spans_same_action(self):
        policy = ActionPolicy()
        policy.register(
            semantic_action="cart:modify",
            raw_span_names=["CartService/AddItem", "CartService/EmptyCart"],
        )
        assert policy.resolve_span("CartService/AddItem") == "cart:modify"
        assert policy.resolve_span("CartService/EmptyCart") == "cart:modify"


class TestDefaultPolicy:
    def test_payments_charge_mapping(self):
        policy = default_otel_demo_policy()
        perms = policy.required_permissions_for(
            raw_span_name="oteldemo.PaymentService/Charge"
        )
        assert perms == frozenset({"payments:charge"})

    def test_charge_alias(self):
        policy = default_otel_demo_policy()
        assert policy.resolve_span("charge") == "payments:charge"

    def test_checkout_mapping(self):
        policy = default_otel_demo_policy()
        perms = policy.required_permissions_for(
            raw_span_name="oteldemo.CheckoutService/PlaceOrder"
        )
        assert perms == frozenset({"orders:create"})

    def test_products_mapping(self):
        policy = default_otel_demo_policy()
        perms = policy.required_permissions_for(
            raw_span_name="oteldemo.ProductCatalogService/GetProduct"
        )
        assert perms == frozenset({"products:read"})

    def test_all_actions_registered(self):
        policy = default_otel_demo_policy()
        expected_actions = {
            "payments:charge",
            "orders:create",
            "orders:read",
            "products:read",
            "cart:modify",
            "shipping:quote",
            "currency:convert",
            "email:send",
        }
        for action in expected_actions:
            assert policy.get_requirement(action) is not None, (
                f"Missing policy for: {action}"
            )
