"""Internal, fail-closed capability for low-level live venue mutations.

The supported factory deliberately does not issue this capability while LIVE
is disabled. A future LIVE release must add issuance only after validating its
release-readiness and manual-arming gates.
"""

from __future__ import annotations

_AUTHORIZATION_SEAL = object()


class LiveMutationAuthorizationError(PermissionError):
    """A live exchange mutation was attempted without release authorization."""


class LiveMutationAuthorization:
    """Opaque capability accepted by low-level live adapters.

    Direct construction is rejected. The private issuer is reserved for a
    future readiness-checked factory and offline adapter tests; it is not used
    by the current production code path.
    """

    __slots__ = ("_seal",)

    def __init__(self, seal: object | None = None) -> None:
        if seal is not _AUTHORIZATION_SEAL:
            raise TypeError("live mutation authorization is issued by the release gate")
        self._seal = seal


def _issue_live_mutation_authorization() -> LiveMutationAuthorization:
    """Private capability issuer; current production code intentionally never calls it."""

    return LiveMutationAuthorization(_AUTHORIZATION_SEAL)


def require_live_mutation_authorization(
    authorization: LiveMutationAuthorization | None,
    *,
    operation: str,
) -> None:
    """Fail closed unless the caller holds an issued capability."""

    if (
        type(authorization) is not LiveMutationAuthorization
        or authorization._seal is not _AUTHORIZATION_SEAL
    ):
        raise LiveMutationAuthorizationError(
            f"live mutation {operation} is disabled without LIVE release authorization"
        )
