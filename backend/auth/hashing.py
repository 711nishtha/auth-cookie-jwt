from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError

# Argon2id: winner of Password Hashing Competition.
# Resistant to GPU cracking (memory-hard) and side-channel attacks.
# Parameters exceed OWASP minimums: memory=64MB, iterations=3, parallelism=2
_ph = PasswordHasher(
    time_cost=3,        # iterations
    memory_cost=65536,  # 64 MB RAM per hash — raises cost of parallel attacks
    parallelism=2,
    hash_len=32,
    salt_len=16,
)


def hash_password(plaintext: str) -> str:
    """Return argon2id hash. Never call with empty string — validate upstream."""
    return _ph.hash(plaintext)


def verify_password(plaintext: str, hashed: str) -> bool:
    """
    Constant-time verification via argon2 internals.
    Returns False on any verification failure rather than raising —
    callers must not distinguish 'wrong password' from 'invalid hash format'
    to avoid oracle attacks.
    """
    try:
        return _ph.verify(hashed, plaintext)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(hashed: str) -> bool:
    """True if stored hash was created with outdated parameters — rehash on next login."""
    return _ph.check_needs_rehash(hashed)
