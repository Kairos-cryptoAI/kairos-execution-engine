"""Synthetic, offline market IOC envelope checks: fixtures grant no venue authority."""

import hashlib
import json
from datetime import UTC, datetime
from decimal import Decimal
from types import MappingProxyType

import pytest
from kairos_core.enums import Side

from kairos_execution import market_ioc_admission as module
from kairos_execution.managed_signer import ManagedSigningRequestV1
from kairos_execution.market_ioc_admission import (
    MarketIocAdmission,
    MarketIocEntryRequestV1,
    VerifiedMarketIocEnvelopeV1,
    check_market_ioc_bounds,
)
from kairos_execution.market_ioc_admission import (
    validate_market_ioc_ack as validate_market_ioc_ack_core,
)
from kairos_execution.production_readiness import canonical_digest
from tests.test_production_lifecycle_binding import _decision, _scope


class SyntheticVerifier:
    source_id = "fixture:synthetic"

    def __init__(self, envelope):
        self.envelope = envelope
        self.calls = 0

    def verify(self, request, *, context, decision, now_ms):
        self.calls += 1
        return self.envelope


class DynamicSyntheticEnvelopeVerifier:
    """Pure test helper; it is never a qualified EVEDEX source."""

    source_id = "fixture:dynamic-synthetic"

    def __init__(self, observed_at_ms):
        self.observed_at_ms = observed_at_ms

    def verify(self, request, *, context, decision, now_ms):
        price_e8 = int(Decimal(str(decision.worst_entry_price)) * 100_000_000)
        quantity_e8 = int(Decimal(str(decision.quantity)) * 100_000_000)
        return VerifiedMarketIocEnvelopeV1(
            source_id=self.source_id,
            proof_sha256=request.proof_sha256,
            request_sha256=canonical_digest(request),
            context_sha256=canonical_digest(context),
            decision_sha256=canonical_digest(decision),
            observed_at_ms=self.observed_at_ms,
            valid_until_ms=self.observed_at_ms + 2_000,
            minimum_fill_price_e8=price_e8,
            maximum_fill_price_e8=price_e8,
            maximum_base_quantity_e8=quantity_e8,
            maximum_fees_usd=Decimal(str(decision.estimated_fees_usd)),
            fee_usdt_usd_upper_bound=Decimal("1.01"),
            cash_notional_cap_enforced=True,
            base_quantity_includes_rounding=True,
            price_bounds_cover_each_fill=True,
            fees_include_entry_and_stop_exit=True,
            bounds_enforced_through_terminal_ioc=True,
        )


@pytest.fixture
def inputs():
    decision = _decision()
    context, _ = _scope(decision)
    request = MarketIocEntryRequestV1(
        source_id=SyntheticVerifier.source_id,
        proof_sha256="a" * 64,
        cash_quantity_e8=1_000_000_000,
    )
    envelope = VerifiedMarketIocEnvelopeV1(
        source_id=request.source_id,
        proof_sha256=request.proof_sha256,
        request_sha256=canonical_digest(request),
        context_sha256=canonical_digest(context),
        decision_sha256=canonical_digest(decision),
        observed_at_ms=10_000,
        valid_until_ms=12_000,
        minimum_fill_price_e8=10_000_000_000,
        maximum_fill_price_e8=10_051_000_000,
        maximum_base_quantity_e8=10_000_000,
        maximum_fees_usd=Decimal("0.009"),
        fee_usdt_usd_upper_bound=Decimal("1.01"),
        cash_notional_cap_enforced=True,
        base_quantity_includes_rounding=True,
        price_bounds_cover_each_fill=True,
        fees_include_entry_and_stop_exit=True,
        bounds_enforced_through_terminal_ioc=True,
    )
    return request, envelope, context, decision


def _signed_request(decision, client_order_id, request):
    context, _ = _scope(decision)
    return ManagedSigningRequestV1(
        request_id="synthetic-request",
        context=context,
        manual_request_sha256="a" * 64,
        custody_receipt_sha256="b" * 64,
        operation="New market order",
        message_json=json.dumps(
            {
                "id": client_order_id,
                "instrument": decision.venue_symbol,
                "side": "BUY" if decision.intent.side is Side.LONG else "SELL",
                "timeInForce": "IOC",
                "cashQuantity": request.cash_quantity_e8,
                "leverage": 1,
                "chainId": 42161,
            }
        ),
        expires_at=datetime(2027, 1, 1, tzinfo=UTC),
    )


def validate_market_ioc_ack(response, *, decision, client_order_id, request, envelope, signed_request=None):
    return validate_market_ioc_ack_core(
        response,
        decision=decision,
        client_order_id=client_order_id,
        request=request,
        envelope=envelope,
        signed_request=signed_request or _signed_request(decision, client_order_id, request),
    )


def check(inputs, *, request=None, envelope=None, context=None, decision=None, now_ms=11_000):
    original_request, original_envelope, original_context, original_decision = inputs
    return check_market_ioc_bounds(
        request or original_request,
        envelope or original_envelope,
        context=context or original_context,
        decision=decision or original_decision,
        now_ms=now_ms,
    )


def test_unregistered_verifier_is_refused_before_it_can_speak(inputs):
    request, envelope, context, decision = inputs
    verifier = SyntheticVerifier(envelope)
    admission = MarketIocAdmission(verifier)
    assert dict(module._QUALIFIED_MARKET_IOC_SOURCE_TYPES) == {}
    assert not admission.registered
    with pytest.raises(ValueError, match="unavailable"):
        admission.verify(request, context=context, decision=decision, now_ms=11_000)
    assert verifier.calls == 0


def test_only_fixture_registered_source_and_exact_type_can_verify(monkeypatch, inputs):
    request, envelope, context, decision = inputs
    monkeypatch.setattr(
        module,
        "_QUALIFIED_MARKET_IOC_SOURCE_TYPES",
        MappingProxyType({SyntheticVerifier.source_id: SyntheticVerifier}),
    )
    verifier = SyntheticVerifier(envelope)
    admission = MarketIocAdmission(verifier)
    assert admission.registered
    assert admission.verify(request, context=context, decision=decision, now_ms=11_000) == envelope
    assert verifier.calls == 1

    class Impostor(SyntheticVerifier):
        pass

    impostor = Impostor(envelope)
    with pytest.raises(ValueError, match="unavailable"):
        MarketIocAdmission(impostor).verify(request, context=context, decision=decision, now_ms=11_000)
    assert impostor.calls == 0


@pytest.mark.parametrize("now_ms", [9_999, 12_000, 12_001])
def test_future_or_expired_envelope_refused(inputs, now_ms):
    with pytest.raises(ValueError, match="clocks"):
        check(inputs, now_ms=now_ms)


@pytest.mark.parametrize(
    "changes",
    [
        {"source_id": "fixture:other"},
        {"proof_sha256": "b" * 64},
        {"request_sha256": "b" * 64},
        {"context_sha256": "b" * 64},
        {"decision_sha256": "b" * 64},
        {"valid_until_ms": 12_001},
        {"minimum_fill_price_e8": 10_051_000_001},
    ],
)
def test_scope_clock_and_reversed_price_mutations_refused(inputs, changes):
    with pytest.raises(ValueError, match="scope, clocks or price"):
        check(inputs, envelope=inputs[1].model_copy(update=changes))


def test_mutating_request_context_or_decision_invalidates_bound_proof(inputs):
    request, _, context, decision = inputs
    mutations = [
        {"request": request.model_copy(update={"cash_quantity_e8": 999_999_999})},
        {"context": context.model_copy(update={"source_set_sha256": "f" * 64})},
        {"decision": decision.model_copy(update={"quantity": 0.09})},
    ]
    for mutation in mutations:
        with pytest.raises(ValueError, match="scope, clocks or price"):
            check(inputs, **mutation)


@pytest.mark.parametrize(
    "changes",
    [
        {"maximum_base_quantity_e8": 10_000_001},
        {"minimum_fill_price_e8": 9_999_999_999},
        {"maximum_fill_price_e8": 10_051_000_001},
        {"maximum_fees_usd": Decimal("0.009775500000000002")},
    ],
)
def test_quantity_cash_price_and_fee_cannot_exceed_approved_envelope(inputs, changes):
    with pytest.raises(ValueError, match="immutable Core Risk envelope"):
        check(inputs, envelope=inputs[1].model_copy(update=changes))


@pytest.mark.parametrize(
    "changes",
    [
        {"minimum_fill_price_e8": 9_500_000_000, "maximum_base_quantity_e8": 10_000_000},
        {"maximum_fill_price_e8": 10_500_000_000},
        {"cash_notional_cap_enforced": False},
        {"base_quantity_includes_rounding": False},
        {"price_bounds_cover_each_fill": False},
        {"fees_include_entry_and_stop_exit": False},
        {"bounds_enforced_through_terminal_ioc": False},
    ],
)
def test_stop_target_or_missing_whole_order_assertions_rejected(inputs, changes):
    with pytest.raises(ValueError):
        check(inputs, envelope=inputs[1].model_copy(update=changes))


def test_terminal_ioc_enforcement_cannot_be_omitted(inputs):
    values = inputs[1].model_dump(mode="python")
    del values["bounds_enforced_through_terminal_ioc"]
    with pytest.raises(ValueError):
        VerifiedMarketIocEnvelopeV1.model_validate(values)


def test_fill_touching_stop_or_target_is_refused_even_if_other_bounds_hold(inputs):
    request, envelope, _, decision = inputs
    at_stop = request.model_copy(update={"cash_quantity_e8": 950_000_000})
    stop_envelope = envelope.model_copy(
        update={"request_sha256": canonical_digest(at_stop), "minimum_fill_price_e8": 9_500_000_000}
    )
    with pytest.raises(ValueError, match="immutable Core Risk envelope"):
        check(inputs, request=at_stop, envelope=stop_envelope)

    nearer_target = decision.model_copy(
        update={"exit_plan": decision.exit_plan.model_copy(update={"target_price": 100.4})}
    )
    target_envelope = envelope.model_copy(
        update={
            "decision_sha256": canonical_digest(nearer_target),
            "maximum_fill_price_e8": 10_040_000_000,
        }
    )
    with pytest.raises(ValueError, match="immutable Core Risk envelope"):
        check(inputs, decision=nearer_target, envelope=target_envelope)


def test_original_envelope_cannot_be_renewed_or_substituted(monkeypatch, inputs):
    request, envelope, context, decision = inputs
    monkeypatch.setattr(
        module,
        "_QUALIFIED_MARKET_IOC_SOURCE_TYPES",
        MappingProxyType({SyntheticVerifier.source_id: SyntheticVerifier}),
    )
    verifier = SyntheticVerifier(envelope.model_copy(update={"maximum_fees_usd": Decimal("0.008")}))
    with pytest.raises(ValueError, match="verification failed closed"):
        MarketIocAdmission(verifier).verify(
            request, context=context, decision=decision, now_ms=11_000, expected=envelope
        )


def test_short_geometry_uses_inverse_stop_target_and_worst_price(inputs):
    request, envelope, context, decision = inputs
    short = decision.model_copy(
        update={
            "intent": decision.intent.model_copy(update={"side": Side.SHORT}),
            "exit_plan": decision.exit_plan.model_copy(update={"stop_price": 105.0, "target_price": 95.0}),
            "worst_entry_price": 100.0,
        }
    )
    short_envelope = envelope.model_copy(
        update={"decision_sha256": canonical_digest(short), "maximum_fill_price_e8": 10_010_000_000}
    )
    assert check(inputs, decision=short, envelope=short_envelope) == short_envelope
    with pytest.raises(ValueError, match="immutable Core Risk envelope"):
        check(
            inputs,
            decision=short,
            envelope=short_envelope.model_copy(update={"minimum_fill_price_e8": 9_999_999_999}),
        )


def test_ack_new_is_not_fill_and_partial_fill_must_match_envelope(inputs):
    request, envelope, _, decision = inputs
    ack = {
        "id": "fixture-id",
        "instrument": decision.venue_symbol,
        "side": "BUY",
        "type": "MARKET",
        "timeInForce": "IOC",
        "cashQuantity": "10",
        "quantity": "0.1",
        "unFilledQuantity": "0.1",
        "status": "NEW",
        "fee": [],
    }
    assert validate_market_ioc_ack(
        ack, decision=decision, client_order_id="fixture-id", request=request, envelope=envelope
    ) == ("fixture-id", "NEW", 0.0, None)
    partial = {
        **ack,
        "status": "PARTIALLY_FILLED",
        "unFilledQuantity": "0.05",
        "filledAvgPrice": "100",
        "fee": [{"coin": "USDT", "quantity": 0.001}],
    }
    assert validate_market_ioc_ack(
        partial, decision=decision, client_order_id="fixture-id", request=request, envelope=envelope
    ) == ("fixture-id", "PARTIALLY_FILLED", 0.05, 100.0)
    for changes in (
        {"filledAvgPrice": "101"},
        {"fee": [{"coin": "USDT", "quantity": 0.01}]},
        {"unFilledQuantity": "0.2"},
        {"cashQuantity": "11"},
    ):
        with pytest.raises(ValueError):
            validate_market_ioc_ack(
                {**partial, **changes},
                decision=decision,
                client_order_id="fixture-id",
                request=request,
                envelope=envelope,
            )


def test_zero_fill_cancel_cannot_hide_an_explicit_fee_over_the_envelope(inputs):
    request, envelope, _, decision = inputs
    ack = {
        "id": "fixture-id",
        "instrument": decision.venue_symbol,
        "side": "BUY",
        "type": "MARKET",
        "timeInForce": "IOC",
        "cashQuantity": "10",
        "quantity": "0.1",
        "unFilledQuantity": "0.1",
        "status": "CANCELED",
        "fee": [],
    }
    assert validate_market_ioc_ack(
        ack, decision=decision, client_order_id="fixture-id", request=request, envelope=envelope
    ) == ("fixture-id", "CANCELED", 0.0, None)
    with pytest.raises(ValueError):
        validate_market_ioc_ack(
            {**ack, "fee": [{"coin": "USDT", "quantity": 0.00900001}]},
            decision=decision,
            client_order_id="fixture-id",
            request=request,
            envelope=envelope,
        )


@pytest.mark.parametrize(
    "mutation",
    [
        {"side": "SELL"},
        {"instrument": "ETHUSD"},
        {"type": "LIMIT"},
        {"timeInForce": "GTC"},
        {"cashQuantity": "10.00000001"},
        {"quantity": "0.10000001"},
        {"unFilledQuantity": "-1"},
        {"filledAvgPrice": "99.99"},
        {"filledAvgPrice": "100.51000001"},
        {"fee": [{"coin": "USDT", "quantity": -1}]},
        {"status": "FILLED"},
        {"status": "UNRECOGNIZED"},
    ],
)
def test_partial_ack_rejects_scope_wrong_side_or_out_of_bounds(inputs, mutation):
    request, envelope, _, decision = inputs
    partial = {
        "id": "fixture-id",
        "instrument": decision.venue_symbol,
        "side": "BUY",
        "type": "MARKET",
        "timeInForce": "IOC",
        "cashQuantity": "10",
        "quantity": "0.1",
        "unFilledQuantity": "0.05",
        "status": "PARTIALLY_FILLED",
        "filledAvgPrice": "100",
        "fee": [{"coin": "USDT", "quantity": 0.001}],
    }
    with pytest.raises(ValueError):
        validate_market_ioc_ack(
            {**partial, **mutation},
            decision=decision,
            client_order_id="fixture-id",
            request=request,
            envelope=envelope,
        )


@pytest.mark.parametrize("missing", ["cashQuantity", "quantity", "unFilledQuantity", "filledAvgPrice", "fee"])
def test_partial_ack_requires_economic_fields(inputs, missing):
    request, envelope, _, decision = inputs
    partial = {
        "id": "fixture-id",
        "instrument": decision.venue_symbol,
        "side": "BUY",
        "type": "MARKET",
        "timeInForce": "IOC",
        "cashQuantity": "10",
        "quantity": "0.1",
        "unFilledQuantity": "0.05",
        "status": "PARTIALLY_FILLED",
        "filledAvgPrice": "100",
        "fee": [{"coin": "USDT", "quantity": 0.001}],
    }
    del partial[missing]
    with pytest.raises(ValueError):
        validate_market_ioc_ack(
            partial, decision=decision, client_order_id="fixture-id", request=request, envelope=envelope
        )


def _openapi_market_partial(decision):
    # Response shape from the public OpenAPI. timeInForce is intentionally
    # absent: it is established from the immutable original request instead.
    return {
        "id": "fixture-id",
        "user": "fixture-account",
        "instrument": decision.venue_symbol,
        "type": "MARKET",
        "side": "BUY",
        "status": "PARTIALLY_FILLED",
        "rejectedReason": "",
        "quantity": 0.1,
        "limitPrice": 0,
        "stopPrice": None,
        "group": "manually",
        "unFilledQuantity": 0.05,
        "cashQuantity": 10,
        "filledAvgPrice": 100,
        "realizedPnL": 0,
        "fee": [{"coin": "USDT", "quantity": 0.001}],
        "triggeredAt": None,
        "createdAt": "2026-11-08T00:00:00Z",
        "updatedAt": "2026-11-08T00:00:00Z",
    }


def test_openapi_market_ack_uses_original_ioc_request_and_array_fee(inputs):
    request, envelope, _, decision = inputs
    response = _openapi_market_partial(decision)
    assert validate_market_ioc_ack(
        response, decision=decision, client_order_id="fixture-id", request=request, envelope=envelope
    ) == ("fixture-id", "PARTIALLY_FILLED", 0.05, 100.0)
    response["timeInForce"] = "GTC"
    with pytest.raises(ValueError):
        validate_market_ioc_ack(
            response, decision=decision, client_order_id="fixture-id", request=request, envelope=envelope
        )


@pytest.mark.parametrize(
    "mutation",
    [
        {"timeInForce": "FOK"},
        {"id": "other-id"},
        {"cashQuantity": 100},
        {"instrument": "ETHUSD"},
        {"side": "SELL"},
        {"leverage": 2},
    ],
)
def test_absent_ack_tif_cannot_hide_substituted_signed_request(inputs, mutation):
    request, envelope, _, decision = inputs
    signed = _signed_request(decision, "fixture-id", request)
    message = json.loads(signed.message_json)
    message.update(mutation)
    signed = signed.model_copy(update={"message_json": json.dumps(message)})
    with pytest.raises(ValueError, match="original signed"):
        validate_market_ioc_ack(
            _openapi_market_partial(decision),
            decision=decision,
            client_order_id="fixture-id",
            request=request,
            envelope=envelope,
            signed_request=signed,
        )


@pytest.mark.parametrize(
    "fee",
    [
        None,
        0.001,
        {},
        [{"coin": "USDT", "quantity": None}],
        [{"coin": "USDT", "quantity": -1}],
        [{"coin": "USDT", "quantity": True}],
        [{"coin": "USDT", "quantity": float("nan")}],
    ],
)
def test_partial_unknown_or_unqualified_reported_fees_remain_unresolved(inputs, fee):
    request, envelope, _, decision = inputs
    with pytest.raises(ValueError):
        validate_market_ioc_ack(
            {**_openapi_market_partial(decision), "fee": fee},
            decision=decision,
            client_order_id="fixture-id",
            request=request,
            envelope=envelope,
        )


@pytest.mark.parametrize("fee", [[], [{"coin": "BTC", "quantity": 0.001}]])
def test_unpriced_or_unpublished_fee_is_unknown_but_does_not_block_protection(inputs, fee):
    request, envelope, _, decision = inputs
    response = {**_openapi_market_partial(decision), "fee": fee}
    assert module._reported_fee_upper_usd(response, envelope=envelope) is None
    assert (
        validate_market_ioc_ack(
            response, decision=decision, client_order_id="fixture-id", request=request, envelope=envelope
        )[2]
        == 0.05
    )


def test_legacy_envelope_roundtrips_without_inventing_fx_rate(inputs):
    request, envelope, _, decision = inputs
    values = envelope.model_dump(mode="python")
    del values["fee_usdt_usd_upper_bound"]
    legacy = VerifiedMarketIocEnvelopeV1.model_validate(values)
    assert legacy.fee_usdt_usd_upper_bound is None
    assert legacy.model_dump(mode="python") == values
    old_json = envelope.model_dump(mode="json")
    del old_json["fee_usdt_usd_upper_bound"]
    expected_digest = hashlib.sha256(
        json.dumps(old_json, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    assert canonical_digest(legacy) == expected_digest
    response = _openapi_market_partial(decision)
    assert module._reported_fee_upper_usd(response, envelope=legacy) is None
    assert (
        validate_market_ioc_ack(
            response, decision=decision, client_order_id="fixture-id", request=request, envelope=legacy
        )[2]
        == 0.05
    )


def test_reported_usdt_is_converted_with_attested_conservative_upper_bound(inputs):
    request, envelope, _, decision = inputs
    response = _openapi_market_partial(decision)
    response["fee"] = [{"coin": "USDT", "quantity": 0.00895}]
    # 0.00895 USDT * 1.01 USD/USDT exceeds the 0.009 USD cap.
    with pytest.raises(ValueError, match="fee exceeds"):
        validate_market_ioc_ack(
            response, decision=decision, client_order_id="fixture-id", request=request, envelope=envelope
        )
    # A rounded binary64 number at the cap is not evidence of exact raw JSON.
    response["fee"] = [{"coin": "USDT", "quantity": 0.009}]
    with pytest.raises(ValueError, match="fee exceeds"):
        validate_market_ioc_ack(
            response,
            decision=decision,
            client_order_id="fixture-id",
            request=request,
            envelope=envelope.model_copy(update={"fee_usdt_usd_upper_bound": Decimal(1)}),
        )
