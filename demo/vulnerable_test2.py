import hashlib

def hash_password(password):
    """Weak hash — Semgrep WILL catch this."""
    return hashlib.md5(password.encode()).hexdigest()

def verify(password, stored):
    return hashlib.md5(password.encode()).hexdigest() == stored