"""Exception hierarchy for authev_core."""


class CoreError(Exception):
    """Base class for all authev_core errors."""


class CoreFormatError(CoreError):
    """Input is malformed (wrong length, bad encoding, bad structure)."""


class CoreVerifyError(CoreError):
    """Authentication failed (bad signature, bad AEAD tag)."""
