"""Concrete, unsigned upstream producer preparation from native captures.

This is an engineering preparation bridge only. It does not sign, register,
qualify a producer, authenticate raw market/bar context, arm a service, or grant
account/owner/operator/Risk authority.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING, Any, Literal

from kairos_core.contracts import VenueQualityV1, canonical_json_bytes, canonical_sha256
from kairos_core.enums import EvedexProfile, SystemMode

if TYPE_CHECKING:
    from kairos_quant.runtime_venue_gate import (  # type: ignore[import-not-found,import-untyped]
        VenueGatePolicy,
    )
from kairos_risk.live import LiveRiskScopeV1  # type: ignore[import-untyped]

from .production_binance_capture import BinanceDepthCaptureV1
from .production_inputs import LiveInputProducerTrustV1, LiveInputStageReceiptV1, SignedLiveInputsEnvelopeV1
from .production_native_capture_store import (
    NativeCaptureSessionReader,
    NativeCaptureSessionSink,
    NativeCaptureStoredObservation,
)
from .production_native_composition import NativeUpstreamCompositionResult
from .production_native_inputs import (
    NativeCallRecordPair,
    native_call_receipts,
    prepare_native_input_envelope,
    read_native_budgeted_call,
)
from .production_native_source_stages import (
    NativeMacroStageProjection,
    NativeSourceStageProjection,
    project_native_binance_reference_stage,
    project_native_composition_stages,
    project_native_macro_stages,
    project_native_source_stages,
)
from .production_transport import parse_raw_response_capture


class NativeProducerPreparationError(ValueError):
    """Existing component evidence cannot form one exact unsigned preparation."""


@dataclass(frozen=True, slots=True)
class NativeCaptureSelection:
    """Exact create-only observation IDs selected for one composition attempt."""

    text_source_observation_ids: tuple[str, ...]
    evedex_instrument_observation_id: str
    evedex_book_observation_id: str
    binance_observation_id: str
    macro_input_observation_id: str | None = None
    macro_output_observation_id: str | None = None

    def __post_init__(self) -> None:
        if (
            not isinstance(self.text_source_observation_ids, tuple)
            or any(not isinstance(value, str) for value in self.text_source_observation_ids)
            or not isinstance(self.evedex_instrument_observation_id, str)
            or not isinstance(self.evedex_book_observation_id, str)
            or not isinstance(self.binance_observation_id, str)
            or (
                self.macro_input_observation_id is not None
                and not isinstance(self.macro_input_observation_id, str)
            )
            or (
                self.macro_output_observation_id is not None
                and not isinstance(self.macro_output_observation_id, str)
            )
        ):
            raise NativeProducerPreparationError("capture selection must contain exact string IDs")
        values = (
            *self.text_source_observation_ids,
            self.evedex_instrument_observation_id,
            self.evedex_book_observation_id,
            self.binance_observation_id,
            *(
                value
                for value in (self.macro_input_observation_id, self.macro_output_observation_id)
                if value
            ),
        )
        if (
            not 1 <= len(self.text_source_observation_ids) <= 2
            or any(len(value) != 32 for value in values)
            or any(any(char not in "0123456789abcdef" for char in value) for value in values)
            or len(set(values)) != len(values)
            or ((self.macro_input_observation_id is None) != (self.macro_output_observation_id is None))
        ):
            raise NativeProducerPreparationError("capture selection identities are malformed or reused")


@dataclass(frozen=True, slots=True)
class NativeProductionInputPreparation:
    """Unsigned existing-envelope preparation; never a qualified producer."""

    envelope: SignedLiveInputsEnvelopeV1
    calls: tuple[NativeCallRecordPair, ...]
    venue_capture_id: str
    live_ready: Literal[False] = False
    registered: Literal[False] = False


class NativeProductionInputPreparer:
    """Join preexisting native captures, composition, and the existing verifier schema."""

    def __init__(
        self,
        *,
        sink: NativeCaptureSessionSink,
        reader: NativeCaptureSessionReader,
        trust: LiveInputProducerTrustV1,
        scope: LiveRiskScopeV1,
        venue_policy: VenueGatePolicy,
        clock_ms: Any,
    ) -> None:
        from kairos_quant.runtime_venue_gate import VenueGatePolicy

        if (
            type(sink) is not NativeCaptureSessionSink
            or type(reader) is not NativeCaptureSessionReader
            or sink.directory != reader.directory
            or type(trust) is not LiveInputProducerTrustV1
            or type(scope) is not LiveRiskScopeV1
            or type(venue_policy) is not VenueGatePolicy
            or not callable(clock_ms)
        ):
            raise TypeError("exact native store, pinned trust/scope, venue policy and clock are required")
        self.sink = sink
        self.reader = reader
        self.trust = trust
        self.scope = scope
        self.venue_policy = venue_policy
        self.clock_ms = clock_ms
        self._last_ms: int | None = None
        self._validate_trust_scope()
        self._validate_venue_policy()

    def _validate_trust_scope(self) -> None:
        if (
            self.trust.purpose != "LIVE_UPSTREAM_INPUT_CAPTURE"
            or self.trust.source_set_sha256 != self.scope.source_set_sha256
            or self.trust.policy_sha256 != self.scope.policy_sha256
        ):
            raise NativeProducerPreparationError("pinned producer trust differs from frozen Risk scope")

    def _validate_venue_policy(self) -> None:
        policy = self.venue_policy
        # The explicit preparation policy may be stricter, never looser than
        # the existing shared gate defaults or the unchanged LIVE ceilings.
        defaults = type(policy)()
        if (
            policy.assessed_notional_usd < defaults.assessed_notional_usd
            or policy.maximum_abs_basis_bps > defaults.maximum_abs_basis_bps
            or policy.maximum_spread_bps > defaults.maximum_spread_bps
            or policy.maximum_slippage_bps > defaults.maximum_slippage_bps
            or policy.maximum_book_age_ms > defaults.maximum_book_age_ms
            or policy.maximum_timestamp_skew_ms > min(defaults.maximum_timestamp_skew_ms, 2_000)
            or policy.maximum_latency_ms > defaults.maximum_latency_ms
            or policy.measurement_ttl_ms > defaults.measurement_ttl_ms
            or policy.taker_fee_bps < defaults.taker_fee_bps
        ):
            raise NativeProducerPreparationError("venue policy loosens an existing production ceiling")

    def _now(self, *, not_before_ms: int) -> int:
        value = self.clock_ms()
        if (
            type(value) is not int
            or value < not_before_ms
            or (self._last_ms is not None and value < self._last_ms)
        ):
            raise NativeProducerPreparationError("preparation clock is invalid, stale or moved backwards")
        self._last_ms = value
        return value

    def prepare(
        self,
        *,
        composition: NativeUpstreamCompositionResult,
        selection: NativeCaptureSelection,
        system_mode: SystemMode,
        calls: tuple[NativeCallRecordPair, ...] = (),
    ) -> NativeProductionInputPreparation:
        """Return the existing unsigned input envelope from exact persisted evidence.

        ``calls`` are only optional Text/Review call pairs already captured in
        this same session. Their caller-supplied captured clocks are discarded;
        the persisted completion witness supplies the preparation clock.
        """
        if (
            type(composition) is not NativeUpstreamCompositionResult
            or type(selection) is not NativeCaptureSelection
            or type(system_mode) is not SystemMode
            or not isinstance(calls, tuple)
            or len(calls) > 5
            or any(type(pair) is not NativeCallRecordPair for pair in calls)
        ):
            raise TypeError("exact native composition, capture selection and explicit mode are required")
        intent = composition.review.intent
        venue_symbol = self.scope.venue_symbol_for(intent.symbol)
        from kairos_quant.runtime_venue_gate import PROD_SYMBOL_MAP

        binance_symbol = next(
            (signal for signal, venue in PROD_SYMBOL_MAP.items() if venue == venue_symbol), None
        )
        if (
            binance_symbol is None
            or len([pair for pair in self.scope.approved_prod_symbols if pair[0] == intent.symbol]) != 1
        ):
            raise NativeProducerPreparationError("composition symbol is outside the exact frozen PROD scope")

        source_projection = project_native_source_stages(
            reader=self.reader,
            rss_observation_ids=selection.text_source_observation_ids,
            evedex_instrument_observation_id=selection.evedex_instrument_observation_id,
            evedex_book_observation_id=selection.evedex_book_observation_id,
            venue_symbol=venue_symbol,
        )
        rss_names: list[str] = []
        for stage in source_projection.stages:
            if stage.stage == "TEXT_SOURCE":
                if stage.source_name is None:
                    raise NativeProducerPreparationError("captured Text source has no original identity")
                rss_names.append(stage.source_name)
        if tuple(sorted(rss_names)) != tuple(sorted(self.trust.expected_text_source_names)):
            raise NativeProducerPreparationError(
                "captured native Text sources differ from pinned source identities"
            )
        binance_stage = project_native_binance_reference_stage(
            reader=self.reader,
            observation_id=selection.binance_observation_id,
            expected_symbol=binance_symbol,
        )

        macro_projection: NativeMacroStageProjection | None = None
        if composition.allocation is None:
            if selection.macro_input_observation_id is not None:
                raise NativeProducerPreparationError("absent native allocation cannot select Macro captures")
        else:
            if selection.macro_input_observation_id is None or selection.macro_output_observation_id is None:
                raise NativeProducerPreparationError(
                    "native allocation requires its original Macro input/output pair"
                )
            macro_projection = project_native_macro_stages(
                reader=self.reader,
                input_observation_id=selection.macro_input_observation_id,
                output_observation_id=selection.macro_output_observation_id,
                expected_allocation=composition.allocation,
            )

        evedex_capture = self._read_selected(selection.evedex_book_observation_id)
        binance_capture = self._read_selected(selection.binance_observation_id)
        evedex_book, evedex_elapsed = self._evedex_book(evedex_capture.record, venue_symbol)
        binance_book, binance_elapsed = self._binance_book(binance_capture.record, binance_symbol)
        raw_source_stages = (*source_projection.stages, binance_stage)
        pre_venue_projection = project_native_composition_stages(
            composition=composition,
            reader=self.reader,
            source_stages=raw_source_stages,
            macro_stages=macro_projection.stages if macro_projection is not None else (),
        )
        checked_calls = self._check_calls(
            supplied=calls,
            macro_calls=macro_projection.calls if macro_projection is not None else (),
            composition=composition,
            stages=pre_venue_projection.stages,
        )
        source_floor = max(
            evedex_capture.witness.acknowledged_at_ms,
            binance_capture.witness.acknowledged_at_ms,
            self._http_clock(evedex_capture.record, "received_at"),
            self._binance_capture_clock(binance_capture.record, "received_at_ms"),
            *(stage.captured_at_ms for stage in source_projection.stages),
            binance_stage.captured_at_ms,
        )
        calculation_at_ms = self._now(not_before_ms=source_floor)
        from kairos_quant.runtime_venue_gate import build_venue_quality

        quality = build_venue_quality(
            binance=binance_book,
            evedex=evedex_book,
            venue_symbol=venue_symbol,
            observed_at_ms=calculation_at_ms,
            latency_ms=math.ceil(max(evedex_elapsed, binance_elapsed)),
            policy=self.venue_policy,
            profile=EvedexProfile.PROD,
        )
        if quality.observed_at_ms != calculation_at_ms:
            raise NativeProducerPreparationError("venue calculation would retime an original book timestamp")
        venue_capture_id = self._persist_venue_quality(
            quality=quality,
            evedex_id=selection.evedex_book_observation_id,
            evedex_record=evedex_capture.record,
            binance_id=selection.binance_observation_id,
            binance_record=binance_capture.record,
        )
        venue_stored = self._read_selected(venue_capture_id)
        venue_stage = LiveInputStageReceiptV1(
            stage="VENUE_QUALITY",
            receipt_id=f"native-venue-quality-{venue_capture_id}",
            source_name="native-quant-venue-gate",
            status="CAPTURED",
            source_timestamp_ms=quality.observed_at_ms,
            persisted_at_ms=venue_stored.witness.acknowledged_at_ms,
            captured_at_ms=venue_stored.witness.acknowledged_at_ms,
            content_sha256=hashlib.sha256(canonical_json_bytes(quality)).hexdigest(),
            content_base64=base64.b64encode(canonical_json_bytes(quality)).decode("ascii"),
        )

        raw_source_stages = (*raw_source_stages, venue_stage)
        composed_projection: NativeSourceStageProjection = project_native_composition_stages(
            composition=composition,
            reader=self.reader,
            source_stages=raw_source_stages,
            macro_stages=macro_projection.stages if macro_projection is not None else (),
        )
        max_persisted = max(
            stage.captured_at_ms for stage in composed_projection.stages if stage.status == "CAPTURED"
        )
        observed_at_ms = self._now(not_before_ms=max(max_persisted, quality.observed_at_ms))
        manifest = {
            "version": "kairos.live-inputs-producer-envelope.v1",
            "producer_id": self.trust.producer_id,
            "source_id": self.trust.source_id,
            "purpose": self.trust.purpose,
            "registration_id": self.trust.registration_id,
            "capture_implementation_id": self.trust.capture_implementation_id,
            "capture_implementation_sha256": self.trust.capture_implementation_sha256,
            "source_set_sha256": self.trust.source_set_sha256,
            "policy_sha256": self.trust.policy_sha256,
            "scope_sha256": self.scope.scope_sha256,
            "observed_at_ms": observed_at_ms,
            "route": composition.route.model_dump(mode="json"),
            "review": composition.review.model_dump(mode="json"),
            "context": composition.context.model_dump(mode="json"),
            "venue": quality.model_dump(mode="json"),
            "allocation": composition.allocation.model_dump(mode="json") if composition.allocation else None,
            "system_mode": system_mode.value,
            "stages": [stage.model_dump(mode="json") for stage in composed_projection.stages],
            "signature_base64": base64.b64encode(bytes(64)).decode("ascii"),
        }
        try:
            prepared = prepare_native_input_envelope(
                retained_manifest=canonical_json_bytes(manifest),
                calls=checked_calls,
            )
        except Exception as exc:
            raise NativeProducerPreparationError(
                "existing native LIVE-input preflight refused preparation"
            ) from exc
        if (
            prepared.review != composition.review
            or prepared.context != composition.context
            or prepared.route != composition.route
            or prepared.allocation != composition.allocation
            or prepared.venue != quality
            or prepared.signature_base64 != base64.b64encode(bytes(64)).decode("ascii")
        ):
            raise NativeProducerPreparationError("prepared envelope differs from exact native composition")
        return NativeProductionInputPreparation(prepared, checked_calls, venue_capture_id)

    def _read_selected(self, observation_id: str) -> NativeCaptureStoredObservation:
        stored = self.reader.read(observation_id)
        if (
            type(stored) is not NativeCaptureStoredObservation
            or stored.witness.observation_id != observation_id
            or stored.witness.record_sha256 != hashlib.sha256(stored.record).hexdigest()
            or stored.witness.record_bytes != len(stored.record)
        ):
            raise NativeProducerPreparationError(
                "selected capture does not have its exact persistence witness"
            )
        return stored

    @staticmethod
    def _http_clock(raw: bytes, field: str) -> int:
        try:
            value = json.loads(raw)[field]
            from datetime import UTC, datetime

            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.utcoffset() != UTC.utcoffset(parsed) or parsed.microsecond % 1_000:
                raise ValueError
            delta = parsed - datetime(1970, 1, 1, tzinfo=UTC)
            return (delta.days * 86_400 + delta.seconds) * 1_000 + delta.microseconds // 1_000
        except Exception as exc:
            raise NativeProducerPreparationError("original EVEDEX HTTP clock is malformed") from exc

    @staticmethod
    def _binance_capture_clock(raw: bytes, field: str) -> int:
        try:
            capture = BinanceDepthCaptureV1.model_validate_json(raw)
            return capture.received_at_ms if field == "received_at_ms" else capture.requested_at_ms
        except Exception as exc:
            raise NativeProducerPreparationError("original Binance capture clock is malformed") from exc

    @staticmethod
    def _evedex_book(raw: bytes, venue_symbol: str):
        from kairos_quant.venue_comparison import (  # type: ignore[import-not-found,import-untyped]
            parse_evedex_book,
        )

        capture = _canonical_capture(raw)
        received = NativeProductionInputPreparer._http_clock(raw, "received_at")
        requested = NativeProductionInputPreparer._http_clock(raw, "requested_at")
        query = json.loads(capture["query_json"])
        try:
            max_level = int(query["maxLevel"])
            payload = parse_raw_response_capture(
                capture,
                source="depth",
                expected_query={"maxLevel": max_level},
                instrument=venue_symbol,
            )
            book = parse_evedex_book(
                venue_symbol,
                payload,
                latency_ms=float(received - requested),
            )
        except Exception as exc:
            raise NativeProducerPreparationError(
                "captured EVEDEX book fails native fixed-route parsing"
            ) from exc
        return book, float(received - requested)

    @staticmethod
    def _binance_book(raw: bytes, symbol: str):
        from kairos_quant.venue_comparison import (
            parse_binance_book,  # type: ignore[import-not-found,import-untyped]
        )

        try:
            capture = BinanceDepthCaptureV1.model_validate_json(raw)
            body = base64.b64decode(capture.body_base64, validate=True)
            payload = _unique_json_object(body)
            book = parse_binance_book(
                symbol,
                payload,
                latency_ms=float(capture.received_at_ms - capture.requested_at_ms),
            )
        except Exception as exc:
            raise NativeProducerPreparationError(
                "captured Binance book fails native fixed-source parsing"
            ) from exc
        return book, float(capture.received_at_ms - capture.requested_at_ms)

    def _persist_venue_quality(
        self,
        *,
        quality: VenueQualityV1,
        evedex_id: str,
        evedex_record: bytes,
        binance_id: str,
        binance_record: bytes,
    ) -> str:
        policy_sha256 = hashlib.sha256(canonical_json_bytes(asdict(self.venue_policy))).hexdigest()
        observation_id = hashlib.sha256(
            f"native-venue-quality:{self.scope.scope_sha256}:{evedex_id}:{binance_id}:{policy_sha256}".encode()
        ).hexdigest()[:32]
        record = canonical_json_bytes(
            {
                "version": "kairos.native-venue-quality-measurement.v1",
                "capture_scope": "NATIVE_DERIVED_MEASUREMENT_NOT_AUTHORITY",
                "observation_id": observation_id,
                "policy_sha256": policy_sha256,
                "scope_sha256": self.scope.scope_sha256,
                "parents": [
                    {"observation_id": evedex_id, "record_sha256": hashlib.sha256(evedex_record).hexdigest()},
                    {
                        "observation_id": binance_id,
                        "record_sha256": hashlib.sha256(binance_record).hexdigest(),
                    },
                ],
                "observed_at_ms": quality.observed_at_ms,
                "venue_quality": quality.model_dump(mode="json"),
            }
        )
        try:
            self.sink.create_only(observation_id, record)
        except Exception as exc:
            raise NativeProducerPreparationError(
                "derived venue measurement was not create-only persisted"
            ) from exc
        stored = self._read_selected(observation_id)
        if stored.record != record or stored.witness.acknowledged_at_ms < quality.observed_at_ms:
            raise NativeProducerPreparationError("venue measurement persistence witness is not causal")
        return observation_id

    def _check_calls(
        self,
        *,
        supplied: tuple[NativeCallRecordPair, ...],
        macro_calls: tuple[NativeCallRecordPair, ...],
        composition: NativeUpstreamCompositionResult,
        stages: tuple[LiveInputStageReceiptV1, ...],
    ) -> tuple[NativeCallRecordPair, ...]:
        from .production_native_inputs import verify_native_call_receipts

        by_stage = {stage.stage: stage for stage in stages}
        text_stage = by_stage["TEXT_AGGREGATE"]
        review_provenance = composition.review.model_provenance
        result: list[NativeCallRecordPair] = list(macro_calls)
        seen_call_ids = {
            read_native_budgeted_call(pair.attempt_record, pair.completion_record).call_id for pair in result
        }
        expected_text = text_stage.output_origin == "NATIVE_MODEL"
        expected_review = review_provenance is not None
        text_request_ids: set[str] = set()
        if expected_text:
            expected_signals = [signal.model_dump(mode="json") for signal in composition.text_signals]
            for observation_id in self.reader.observation_ids():
                # A missing/partial persistence pair is never an unrelated
                # parse error to skip. Its unknown outcome must remain fenced.
                stored = self._read_selected(observation_id)
                try:
                    extraction = _unique_json_object(stored.record)
                except (ValueError, TypeError, UnicodeError):
                    extraction = None
                if extraction is None:
                    continue
                output = extraction.get("output")
                if (
                    extraction.get("kind") == "SENTIMENT_EXTRACTION"
                    and isinstance(output, dict)
                    and isinstance(output.get("base64"), str)
                ):
                    try:
                        parsed_output = _unique_json_object(base64.b64decode(output["base64"], validate=True))
                    except (ValueError, TypeError, UnicodeError) as exc:
                        raise NativeProducerPreparationError(
                            "persisted Text extraction has malformed native output"
                        ) from exc
                    model_result = extraction.get("model_result")
                    request_id = model_result.get("request_id") if isinstance(model_result, dict) else None
                    if parsed_output.get("signals") == expected_signals and isinstance(request_id, str):
                        text_request_ids.add(request_id)
            if len(text_request_ids) != 1:
                raise NativeProducerPreparationError(
                    "native Text aggregate lacks one exact extraction request identity"
                )
        text_count = 0
        review_count = 0
        for pair in supplied:
            call = read_native_budgeted_call(pair.attempt_record, pair.completion_record)
            if call.call_id in seen_call_ids:
                raise NativeProducerPreparationError("native budgeted call identity is duplicated")
            seen_call_ids.add(call.call_id)
            started_id = hashlib.sha256(f"llm:{call.call_id}:started".encode()).hexdigest()[:32]
            completed_id = hashlib.sha256(f"llm:{call.call_id}:completed".encode()).hexdigest()[:32]
            started = self._read_selected(started_id)
            completed = self._read_selected(completed_id)
            if (
                started.record != pair.attempt_record
                or completed.record != pair.completion_record
                or started.witness.acknowledged_at_ms < call.started_at_ms
                or completed.witness.acknowledged_at_ms < call.committed_at_ms
            ):
                raise NativeProducerPreparationError(
                    "caller-supplied model records are not exact persisted originals"
                )
            if call.native_workload == "text_scouts" and expected_text:
                expected_digest = text_stage.content_sha256
                if pair.bound_output_sha256 != expected_digest or call.request_id not in text_request_ids:
                    raise NativeProducerPreparationError(
                        "Text call is not bound to the exact composed aggregate"
                    )
                text_count += 1
            elif call.native_workload in {"aggregator_normal", "aggregator_conflict"} and expected_review:
                provenance = review_provenance
                if provenance is None:
                    raise NativeProducerPreparationError("review provenance disappeared during call join")
                if (
                    pair.bound_output_sha256 != canonical_sha256(composition.review.model_dump(mode="json"))
                    or call.request_id != provenance.request_id
                    or call.reservation_id != provenance.budget_reservation_id
                    or call.provider != provenance.provider
                    or call.model != provenance.model
                    or call.reasoning_effort != provenance.reasoning_effort
                    or hashlib.sha256(call.prompt).hexdigest() != provenance.prompt_sha256
                    or hashlib.sha256(call.response).hexdigest() != provenance.response_sha256
                ):
                    raise NativeProducerPreparationError(
                        "review call does not bind exact persisted review provenance"
                    )
                review_count += 1
            else:
                raise NativeProducerPreparationError(
                    "an unselected or fallback model call cannot be promoted"
                )
            result.append(
                NativeCallRecordPair(
                    attempt_record=pair.attempt_record,
                    completion_record=pair.completion_record,
                    bound_output_sha256=pair.bound_output_sha256,
                    captured_at_ms=completed.witness.acknowledged_at_ms,
                )
            )
        if text_count != int(expected_text) or review_count != int(expected_review):
            raise NativeProducerPreparationError("native model output lacks its exact persisted call pair")
        if len(result) > 5:
            raise NativeProducerPreparationError("native model call inventory exceeds the existing bound")
        verify_native_call_receipts(
            tuple(
                receipt
                for pair in result
                for receipt in native_call_receipts(
                    attempt_record=pair.attempt_record,
                    completion_record=pair.completion_record,
                    captured_at_ms=pair.captured_at_ms,
                    bound_output_sha256=pair.bound_output_sha256,
                )
            )
        )
        return tuple(result)


def _canonical_capture(raw: bytes) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except Exception as exc:
        raise NativeProducerPreparationError("retained EVEDEX capture wrapper is invalid JSON") from exc
    if not isinstance(value, dict) or canonical_json_bytes(value) != raw:
        raise NativeProducerPreparationError("retained EVEDEX capture wrapper is not canonical")
    return value


def _unique_json_object(raw: bytes) -> dict[str, Any]:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON field")
            result[key] = value
        return result

    payload = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(payload, dict):
        raise ValueError("book source JSON root must be an object")
    return payload


__all__ = [
    "NativeCaptureSelection",
    "NativeProductionInputPreparation",
    "NativeProductionInputPreparer",
    "NativeProducerPreparationError",
]
