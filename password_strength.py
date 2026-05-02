"""
Module 4: Password Strength Analyzer
======================================
Evaluates passwords based on:
  - Length
  - Character diversity (uppercase, lowercase, digits, symbols)
  - Shannon entropy
  - Dictionary / common-password detection
  - Pattern detection (keyboard walks, repeated chars, date patterns)

Returns a score 0-10, a grade, and actionable suggestions.
"""

import re
import math
import string


# ── Top-500 weak password list (abridged for size; extend as needed) ───────────
WEAK_PASSWORDS = {
    "password", "123456", "12345678", "qwerty", "abc123", "monkey",
    "1234567", "letmein", "trustno1", "dragon", "master", "sunshine",
    "princess", "welcome", "shadow", "superman", "michael", "football",
    "batman", "iloveyou", "admin", "login", "passw0rd", "pa$$word",
    "administrator", "1234", "12345", "111111", "1111111", "000000",
    "password1", "password123", "qwerty123", "qwertyuiop", "asdfgh",
    "zxcvbn", "pass", "test", "guest", "root", "toor", "changeme",
    "hello", "azerty", "soleil", "abc", "aaa", "aaaaaa", "654321",
    "123123", "qazwsx", "q1w2e3r4", "1q2w3e4r", "zxcvbnm",
}

# ── Keyboard walk patterns (sequences to penalise) ────────────────────────────
KEYBOARD_WALKS = [
    "qwerty", "qwertyuiop", "asdfgh", "asdfghjkl", "zxcvbn",
    "1qaz", "2wsx", "3edc", "4rfv", "qazwsx", "1q2w3e",
    "abcdef", "abcdefgh", "zyxwvu",
]

# ── Common date patterns ───────────────────────────────────────────────────────
DATE_RE = re.compile(r"(19|20)\d{2}|"           # year
                     r"\d{1,2}[/-]\d{1,2}|"      # mm/dd or dd/mm
                     r"\d{8}")                    # DDMMYYYY


class PasswordStrengthAnalyzer:
    """Comprehensive password strength analysis engine."""

    def analyze(self, password: str) -> dict:
        """
        Analyse a password and return a full report dict.

        Keys returned
        -------------
        password, score (0-10), grade, entropy, length,
        has_upper, has_lower, has_digits, has_symbols,
        issues, suggestions
        """
        issues = []
        suggestions = []
        score = 0

        # ── 1. Length scoring ──────────────────────────────────────────────────
        length = len(password)
        if length < 6:
            issues.append("Too short (< 6 chars)")
            suggestions.append("Use at least 12 characters")
        elif length < 8:
            score += 1
            suggestions.append("Aim for 12+ characters")
        elif length < 12:
            score += 2
            suggestions.append("Consider 16+ characters for high-security accounts")
        elif length < 16:
            score += 3
        else:
            score += 4   # max 4 pts for length

        # ── 2. Character diversity ─────────────────────────────────────────────
        has_lower   = bool(re.search(r"[a-z]", password))
        has_upper   = bool(re.search(r"[A-Z]", password))
        has_digit   = bool(re.search(r"\d",    password))
        has_symbol  = bool(re.search(r"[^a-zA-Z\d]", password))

        diversity_score = sum([has_lower, has_upper, has_digit, has_symbol])
        score += diversity_score  # max 4 pts

        if not has_lower:
            issues.append("No lowercase letters")
            suggestions.append("Add lowercase letters")
        if not has_upper:
            issues.append("No uppercase letters")
            suggestions.append("Add uppercase letters")
        if not has_digit:
            issues.append("No digits")
            suggestions.append("Add numbers")
        if not has_symbol:
            issues.append("No special characters")
            suggestions.append("Add symbols like !@#$%^&*")

        # ── 3. Entropy ────────────────────────────────────────────────────────
        charset_size = 0
        if has_lower:   charset_size += 26
        if has_upper:   charset_size += 26
        if has_digit:   charset_size += 10
        if has_symbol:  charset_size += 33

        entropy = length * math.log2(charset_size) if charset_size > 0 else 0

        if entropy >= 60:
            score += 2
        elif entropy >= 40:
            score += 1

        # ── 4. Penalise weak patterns ─────────────────────────────────────────
        pw_lower = password.lower()

        # Common password check
        if pw_lower in WEAK_PASSWORDS:
            score = max(0, score - 4)
            issues.append("Found in common password list")
            suggestions.append("Avoid commonly used passwords")

        # Keyboard walk check
        for walk in KEYBOARD_WALKS:
            if walk in pw_lower:
                score = max(0, score - 2)
                issues.append(f"Contains keyboard pattern '{walk}'")
                suggestions.append("Avoid sequential keyboard patterns")
                break

        # Repeated characters check (e.g. "aaaa", "1111")
        if re.search(r"(.)\1{3,}", password):
            score = max(0, score - 1)
            issues.append("Contains 4+ repeated characters")
            suggestions.append("Avoid repeating the same character")

        # Date pattern check
        if DATE_RE.search(password):
            score = max(0, score - 1)
            issues.append("Contains date-like pattern")
            suggestions.append("Avoid birth dates or years in passwords")

        # All same case
        if password.isalpha() and (password.islower() or password.isupper()):
            score = max(0, score - 1)
            issues.append("All alphabetic, single case")
            suggestions.append("Mix uppercase and lowercase letters")

        # All digits
        if password.isdigit():
            score = max(0, score - 2)
            issues.append("Contains only digits")
            suggestions.append("Mix letters and symbols with digits")

        # ── 5. Clamp and grade ────────────────────────────────────────────────
        score = max(0, min(10, score))
        grade = self._grade(score)

        # De-duplicate suggestions
        suggestions = list(dict.fromkeys(suggestions))

        return {
            "password":     password,
            "score":        score,
            "grade":        grade,
            "entropy":      round(entropy, 2),
            "length":       length,
            "has_upper":    has_upper,
            "has_lower":    has_lower,
            "has_digits":   has_digit,
            "has_symbols":  has_symbol,
            "charset_size": charset_size,
            "issues":       issues,
            "suggestions":  suggestions,
        }

    def _grade(self, score: int) -> str:
        if score <= 2:  return "F – Very Weak"
        if score <= 4:  return "D – Weak"
        if score <= 6:  return "C – Moderate"
        if score <= 8:  return "B – Strong"
        return               "A – Very Strong"

    def bulk_analyze(self, passwords: list) -> list:
        """Analyze a list of passwords and return all results."""
        return [self.analyze(pw) for pw in passwords]

    def policy_check(self, password: str, policy: dict = None) -> dict:
        """
        Check whether a password meets a configurable policy.

        Default policy:
          min_length=12, require_upper=True, require_lower=True,
          require_digits=True, require_symbols=True, min_entropy=50
        """
        policy = policy or {
            "min_length":       12,
            "require_upper":    True,
            "require_lower":    True,
            "require_digits":   True,
            "require_symbols":  True,
            "min_entropy":      50,
            "block_common":     True,
        }

        result = self.analyze(password)
        violations = []

        if result["length"] < policy["min_length"]:
            violations.append(f"Too short: {result['length']} < {policy['min_length']}")
        if policy["require_upper"] and not result["has_upper"]:
            violations.append("Missing uppercase letter")
        if policy["require_lower"] and not result["has_lower"]:
            violations.append("Missing lowercase letter")
        if policy["require_digits"] and not result["has_digits"]:
            violations.append("Missing digit")
        if policy["require_symbols"] and not result["has_symbols"]:
            violations.append("Missing symbol")
        if result["entropy"] < policy["min_entropy"]:
            violations.append(f"Low entropy: {result['entropy']:.1f} < {policy['min_entropy']}")
        if policy["block_common"] and password.lower() in WEAK_PASSWORDS:
            violations.append("Password is in the common password list")

        return {
            "password":   password,
            "passes":     len(violations) == 0,
            "violations": violations,
            "strength":   result,
        }
