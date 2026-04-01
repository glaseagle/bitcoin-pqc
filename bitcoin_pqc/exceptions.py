"""Custom exception hierarchy for bitcoin-pqc."""


class BitcoinPQCError(Exception):
    """Base exception for all bitcoin-pqc errors."""


class KeyError_(BitcoinPQCError):
    """Key generation or loading failure."""


class InvalidKeyError(BitcoinPQCError):
    """Key material is malformed or has wrong length."""


class SignatureError(BitcoinPQCError):
    """Signing operation failed."""


class VerificationError(BitcoinPQCError):
    """Signature verification failed (not merely invalid — actually errored)."""


class InvalidSignatureError(BitcoinPQCError):
    """Signature is cryptographically invalid."""


class AddressError(BitcoinPQCError):
    """Address encoding or decoding failure."""


class BadChecksumError(AddressError):
    """Base58Check checksum mismatch."""


class UnknownVersionError(AddressError):
    """Unrecognised address version byte."""


class TransactionError(BitcoinPQCError):
    """Transaction construction or serialisation error."""


class ScriptSigParseError(TransactionError):
    """Failed to parse scriptSig from a transaction input."""


class StorageError(BitcoinPQCError):
    """Key file read/write failure."""


class DecryptionError(StorageError):
    """Wrong passphrase or corrupted key file."""


class DerivationError(BitcoinPQCError):
    """HD key derivation failure."""
