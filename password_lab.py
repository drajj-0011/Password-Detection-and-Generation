import math
import re
import secrets


MIN_LENGTH = 12
MAX_LENGTH = 32


CHAR_SETS = {
    "upper": "ABCDEFGHJKLMNPQRSTUVWXYZ",
    "lower": "abcdefghijkmnopqrstuvwxyz",
    "number": "23456789",
    "special": "!@#$%&*+-=?",
}

COMMON_PATTERNS = [
    re.compile(r"password", re.I),
    re.compile(r"qwerty", re.I),
    re.compile(r"12345"),
    re.compile(r"abc123", re.I),
    re.compile(r"letmein", re.I),
    re.compile(r"admin", re.I),
    re.compile(r"^(.)\1+$"),
]

LABELS = ["Very weak", "Weak", "Fair", "Good", "Strong", "Excellent"]


def run_checks(password: str) -> dict:
    """Return a dict of rule name -> True/False."""
    return {
        "length": len(password) >= 12,
        "upper": bool(re.search(r"[A-Z]", password)),
        "lower": bool(re.search(r"[a-z]", password)),
        "number": bool(re.search(r"\d", password)),
        "special": bool(re.search(r"[^A-Za-z0-9]", password)),
        "unique": len(password) > 0
        and not any(p.search(password) for p in COMMON_PATTERNS),
    }


def character_pool_size(password: str) -> int:
    """Size of the character pool the password appears to draw from."""
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"[0-9]", password):
        pool += 10
    if re.search(r"[^A-Za-z0-9]", password):
        pool += 32
    return pool


def estimate_entropy(password: str) -> int:
    """Rough entropy in bits: length * log2(pool size).

    This is the size of the search space, not a guarantee. A short, common
    password can score high here while still being easy to guess.
    """
    pool = character_pool_size(password)
    if not password or not pool:
        return 0
    return round(len(password) * math.log2(pool))


def _hint_for(score: int) -> str:
    if score <= 2:
        return ("This password may be easier to guess. Try making it longer "
                "and adding character types you have not used.")
    if score <= 4:
        return ("Good progress. More length and a less predictable mix can "
                "make a password harder to guess.")
    return ("It meets several useful criteria. Prefer a unique password for "
            "every account and store it in a password manager.")


def analyze_password(password: str) -> dict:
    """Analyze a password and return everything the UI needs."""
    if not password:
        return {
            "length": 0,
            "checks": run_checks(""),
            "pool": 0,
            "entropy": 0,
            "score": 0,
            "label": "Waiting for input",
            "hint": ("A longer, varied password is generally harder to guess. "
                     "Type above to see which characteristics your password has."),
        }

    checks = run_checks(password)
    score = sum(checks.values())
    if len(password) >= 16:
        score = min(5, score + 1)

    return {
        "length": len(password),
        "checks": checks,
        "pool": character_pool_size(password),
        "entropy": estimate_entropy(password),
        "score": score,
        "label": LABELS[min(5, score)],
        "hint": _hint_for(score),
    }



def generate_password(length: int = 20, use=("upper", "lower", "number", "special")) -> str:
    """Generate a random password with Python's `secrets` module.

    `secrets` draws from the operating system's cryptographically secure
    random source, unlike `random`, which must never be used for passwords.
    At least one character from every selected set is guaranteed.
    """
    keys = [k for k in use if k in CHAR_SETS]
    if not keys:
        raise ValueError("Select at least one character type.")
    if not MIN_LENGTH <= length <= MAX_LENGTH:
        raise ValueError(f"Length must be between {MIN_LENGTH} and {MAX_LENGTH}.")

    pool = "".join(CHAR_SETS[k] for k in keys)
    chars = [secrets.choice(CHAR_SETS[k]) for k in keys]  # one from each set
    chars += [secrets.choice(pool) for _ in range(length - len(chars))]
    secrets.SystemRandom().shuffle(chars)  
    return "".join(chars)


if __name__ == "__main__":
    pw = generate_password(20)
    print("Generated:", pw)
    print("Analysis: ", analyze_password(pw))
