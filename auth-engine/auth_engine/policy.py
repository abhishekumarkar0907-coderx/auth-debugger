"""
Deterministic action-requirement policy mappings.

Maps raw OTel span names and semantic action strings to the permissions
required to perform those operations.

This module is the single source of truth for "what authority does action X
require?"  No LLM, heuristic, or ML model is involved.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ActionRequirement:
    """The permissions required to perform a given action."""

    semantic_action: str
    required_permissions: frozenset[str]
    description: str = ""


class ActionPolicy:
    """
    Registry of action → required-permission mappings.

    Supports both raw span names and canonical semantic actions.
    """

    def __init__(self) -> None:
        # semantic_action → ActionRequirement
        self._by_action: dict[str, ActionRequirement] = {}
        # raw_span_name → semantic_action  (many-to-one)
        self._span_to_action: dict[str, str] = {}

    # ---- Registration -------------------------------------------------------

    def register(
        self,
        semantic_action: str,
        required_permissions: frozenset[str] | set[str] | list[str] | None = None,
        raw_span_names: list[str] | None = None,
        description: str = "",
    ) -> None:
        """Register an action with its required permissions and span aliases."""
        if required_permissions is None:
            perms = frozenset({semantic_action})
        else:
            perms = frozenset(required_permissions)

        req = ActionRequirement(
            semantic_action=semantic_action,
            required_permissions=perms,
            description=description,
        )
        self._by_action[semantic_action] = req

        if raw_span_names:
            for name in raw_span_names:
                self._span_to_action[name] = semantic_action

    # ---- Lookup -------------------------------------------------------------

    def resolve_span(self, raw_span_name: str) -> str | None:
        """Resolve a raw span name to its canonical semantic action."""
        return self._span_to_action.get(raw_span_name)

    def get_requirement(self, semantic_action: str) -> ActionRequirement | None:
        """Look up the requirement for a semantic action."""
        return self._by_action.get(semantic_action)

    def required_permissions_for(
        self, *, semantic_action: str | None = None, raw_span_name: str | None = None
    ) -> frozenset[str] | None:
        """
        Return the required permissions for the given action or span name.

        Returns ``None`` if the action is unknown.
        """
        action = semantic_action
        if action is None and raw_span_name is not None:
            action = self.resolve_span(raw_span_name)
        if action is None:
            return None
        req = self._by_action.get(action)
        if req is None:
            return None
        return req.required_permissions


# ---------------------------------------------------------------------------
# Default policy for the OTel Demo microservices
# ---------------------------------------------------------------------------


def default_otel_demo_policy() -> ActionPolicy:
    """
    Create an ``ActionPolicy`` pre-loaded with mappings for the canonical
    OTel Demo services used in this project.
    """
    policy = ActionPolicy()

    policy.register(
        semantic_action="payments:charge",
        required_permissions=["payments:charge"],
        raw_span_names=[
            "oteldemo.PaymentService/Charge",
            "charge",
        ],
        description="Charge a payment method on behalf of a user",
    )

    policy.register(
        semantic_action="orders:create",
        required_permissions=["orders:create"],
        raw_span_names=[
            "oteldemo.CheckoutService/PlaceOrder",
            "placeorder",
        ],
        description="Create a new order in the checkout flow",
    )

    policy.register(
        semantic_action="orders:read",
        required_permissions=["orders:read"],
        raw_span_names=[
            "oteldemo.OrderService/GetOrder",
            "getorder",
        ],
        description="Read order details",
    )

    policy.register(
        semantic_action="products:read",
        required_permissions=["products:read"],
        raw_span_names=[
            "oteldemo.ProductCatalogService/GetProduct",
            "oteldemo.ProductCatalogService/ListProducts",
        ],
        description="Read product catalog data",
    )

    policy.register(
        semantic_action="cart:modify",
        required_permissions=["cart:modify"],
        raw_span_names=[
            "oteldemo.CartService/AddItem",
            "oteldemo.CartService/EmptyCart",
        ],
        description="Modify the user's shopping cart",
    )

    policy.register(
        semantic_action="shipping:quote",
        required_permissions=["shipping:quote"],
        raw_span_names=[
            "oteldemo.ShippingService/GetQuote",
            "oteldemo.ShippingService/ShipOrder",
        ],
        description="Get a shipping quote or trigger shipping",
    )

    policy.register(
        semantic_action="currency:convert",
        required_permissions=["currency:convert"],
        raw_span_names=[
            "oteldemo.CurrencyService/Convert",
            "oteldemo.CurrencyService/GetSupportedCurrencies",
        ],
        description="Convert currencies",
    )

    policy.register(
        semantic_action="email:send",
        required_permissions=["email:send"],
        raw_span_names=[
            "oteldemo.EmailService/SendOrderConfirmation",
        ],
        description="Send email notifications",
    )

    return policy
