"""
Module 3: Brute-Force Simulator
=================================
Two modes:
  1. Time estimator  — calculates how long it would take to crack a password
                       given modern hardware hash rates.
  2. Dictionary attack simulator — tries wordlist against hashed targets
                                   (works on hashes you generated yourself).

This module only operates on data you own or are authorised to test.
"""

import hashlib
import time
import math


# ── Approximate hash rates (hashes/second on mid-range GPU – H100 class) ──────
# These are conservative estimates used for educational awareness.
HASH_RATES = {
    "md5":    60_000_000_000,   # ~60 GH/s
    "sha1":   20_000_000_000,   # ~20 GH/s
    "sha256":  9_000_000_000,   # ~9 GH/s
    "sha512":  3_000_000_000,   # ~3 GH/s
    "ntlm":   80_000_000_000,   # ~80 GH/s
    "bcrypt":     20_000,       # ~20 kH/s  (intentionally slow KDF)
    "sha512crypt": 100_000,     # ~100 kH/s (crypt-based, salted)
}

# ── Character set sizes ────────────────────────────────────────────────────────
CHARSETS = {
    "digits":           10,
    "lowercase":        26,
    "uppercase":        26,
    "lower+digits":     36,
    "upper+lower":      52,
    "alphanumeric":     62,
    "full_ascii":       95,
}


class BruteForceSimulator:
    """Simulate and estimate brute-force password cracking."""

    # ── Mode 1: Time Estimator ────────────────────────────────────────────────

    def estimate_crack_time(self, password: str, algorithm: str = "sha256") -> dict:
        """
        Estimate how long it would take to brute-force a given password.

        Parameters
        ----------
        password  : the plaintext password to evaluate
        algorithm : hashing algorithm name

        Returns
        -------
        dict with crack time estimates and strength hints
        """
        algorithm = algorithm.lower()
        length = len(password)
        charset_size = self._detect_charset_size(password)
        keyspace = charset_size ** length
        hps = HASH_RATES.get(algorithm, HASH_RATES["sha256"])

        # Average = keyspace / 2 / hps  (expected value)
        avg_seconds = (keyspace / 2) / hps
        worst_seconds = keyspace / hps

        return {
            "password":        password,
            "length":          length,
            "charset_size":    charset_size,
            "keyspace":        keyspace,
            "algorithm":       algorithm,
            "hashes_per_second": hps,
            "avg_seconds":     avg_seconds,
            "worst_seconds":   worst_seconds,
            "avg_time_human":  self._human_time(avg_seconds),
            "worst_time_human": self._human_time(worst_seconds),
            "strength_hint":   self._strength_hint(avg_seconds),
        }

    def _detect_charset_size(self, password: str) -> int:
        """Estimate the effective character set size."""
        size = 0
        if any(c.islower() for c in password): size += 26
        if any(c.isupper() for c in password): size += 26
        if any(c.isdigit() for c in password): size += 10
        if any(not c.isalnum() for c in password): size += 33  # symbols
        return max(size, 10)

    def _human_time(self, seconds: float) -> str:
        """Convert seconds to human-readable duration."""
        if seconds < 1:
            ms = seconds * 1000
            if ms < 1:
                return f"{ms*1000:.2f} microseconds"
            return f"{ms:.2f} milliseconds"
        if seconds < 60:
            return f"{seconds:.2f} seconds"
        if seconds < 3600:
            return f"{seconds/60:.2f} minutes"
        if seconds < 86400:
            return f"{seconds/3600:.2f} hours"
        if seconds < 31536000:
            return f"{seconds/86400:.2f} days"
        if seconds < 31536000 * 1000:
            return f"{seconds/31536000:.2f} years"
        if seconds < 31536000 * 1_000_000:
            return f"{seconds/31536000/1000:.2f} thousand years"
        return f"{seconds/31536000:.2e} years"

    def _strength_hint(self, avg_seconds: float) -> str:
        """Return a qualitative strength label based on cracking time."""
        if avg_seconds < 1:          return "🔴 Extremely Weak  (instant)"
        if avg_seconds < 60:         return "🔴 Very Weak       (< 1 minute)"
        if avg_seconds < 3600:       return "🟠 Weak            (< 1 hour)"
        if avg_seconds < 86400:      return "🟠 Fair            (< 1 day)"
        if avg_seconds < 2592000:    return "🟡 Moderate        (< 1 month)"
        if avg_seconds < 31536000:   return "🟢 Strong          (< 1 year)"
        if avg_seconds < 3.15e9:     return "🟢 Very Strong     (< 100 years)"
        return                              "🟢 Excellent       (> 100 years)"

    # ── Mode 2: Dictionary Attack ─────────────────────────────────────────────

    def dictionary_attack(self, targets: list, wordlist: list) -> list:
        """
        Simulate a dictionary attack against a list of hashed targets.

        Targets must be dicts with at minimum:
          { 'username': str, 'algorithm': str, 'hash': str }
        where 'hash' is a hex digest (not a crypt/shadow hash).

        Parameters
        ----------
        targets  : list of target dicts (from HashExtractor or demo_targets())
        wordlist : list of plaintext password candidates

        Returns
        -------
        list of result dicts
        """
        results = []
        for target in targets:
            result = self._attack_single(target, wordlist)
            results.append(result)
        return results

    def _attack_single(self, target: dict, wordlist: list) -> dict:
        """Try each word in the wordlist against one target hash."""
        username  = target.get("username", "unknown")
        algorithm = target.get("algorithm", "SHA-256").lower()
        target_hash = target.get("hash", "")

        # Skip locked or disabled accounts
        if target.get("locked") or target_hash in ("*", "!"):
            return {
                "username": username,
                "cracked":  False,
                "plaintext": None,
                "attempts": 0,
                "time_taken": 0.0,
                "note": "Account locked/disabled",
            }

        # Normalise algorithm name
        alg = self._normalise_alg(algorithm)
        if alg is None:
            return {
                "username": username,
                "cracked":  False,
                "plaintext": None,
                "attempts": 0,
                "time_taken": 0.0,
                "note": f"Unsupported algorithm for simulation: {algorithm}",
            }

        start = time.perf_counter()
        attempts = 0

        for word in wordlist:
            try:
                candidate_hash = hashlib.new(alg, word.encode()).hexdigest()
                attempts += 1
                if candidate_hash == target_hash:
                    elapsed = time.perf_counter() - start
                    return {
                        "username":  username,
                        "cracked":   True,
                        "plaintext": word,
                        "attempts":  attempts,
                        "time_taken": elapsed,
                        "note": "",
                    }
            except Exception:
                continue

        elapsed = time.perf_counter() - start
        return {
            "username":  username,
            "cracked":   False,
            "plaintext": None,
            "attempts":  attempts,
            "time_taken": elapsed,
            "note": "Not found in wordlist",
        }

    def _normalise_alg(self, algorithm: str) -> str:
        """Map display algorithm names to hashlib names."""
        mapping = {
            "md5":    "md5",
            "sha-256": "sha256", "sha256":  "sha256",
            "sha-512": "sha512", "sha512":  "sha512",
            "sha-1":  "sha1",   "sha1":    "sha1",
            "ntlm":   "md4",
        }
        return mapping.get(algorithm.lower())

    # ── Demo targets ──────────────────────────────────────────────────────────

    def demo_targets(self) -> list:
        """
        Return a small set of synthetic targets with known plaintexts.
        Hashes are SHA-256 of the password, created here for demo purposes.
        """
        known = [
            ("alice_test",   "password"),
            ("bob_test",     "123456"),
            ("charlie_test", "letmein"),
            ("diana_test",   "Tr0ub4dor"),      # not in common lists — harder
            ("eve_test",     "qwerty"),
        ]
        targets = []
        for username, plaintext in known:
            h = hashlib.sha256(plaintext.encode()).hexdigest()
            targets.append({
                "username":  username,
                "algorithm": "sha256",
                "hash":      h,
                "locked":    False,
                "_plaintext_for_verification": plaintext,  # only for demo transparency
            })
        return targets

    # ── Incremental (keyspace) estimator ─────────────────────────────────────

    def keyspace_report(self, max_length: int = 10) -> list:
        """
        Show keyspace sizes and estimated crack times for passwords
        of increasing length with full ASCII charset.
        """
        rows = []
        hps = HASH_RATES["sha256"]
        for length in range(1, max_length + 1):
            keyspace = 95 ** length
            avg_sec = (keyspace / 2) / hps
            rows.append({
                "length":      length,
                "keyspace":    keyspace,
                "avg_time":    self._human_time(avg_sec),
                "strength":    self._strength_hint(avg_sec),
            })
        return rows
