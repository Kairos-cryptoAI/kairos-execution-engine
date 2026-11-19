"""Admission status of EVEDEX native protection on the production venue."""

# A full-position native take-profit executed in the entry direction and grew a short.
# Re-enable admission when the venue provides a verified position-reducing bracket.
EVEDEX_NATIVE_PROTECTION_UNAVAILABLE = (
    "EVEDEX native stop-loss/take-profit is not qualified to reduce positions on production"
)
