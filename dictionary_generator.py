"""
Module 1: Dictionary Generator
================================
Generates custom wordlists using:
  - Name + DOB combinations
  - Keyboard patterns
  - Common passwords
  - Leet-speak, uppercase variations, and appended numbers
"""

import itertools


# ── Common base passwords ──────────────────────────────────────────────────────
COMMON_PASSWORDS = [
    "password", "123456", "12345678", "qwerty", "abc123",
    "monkey", "1234567", "letmein", "trustno1", "dragon",
    "master", "sunshine", "princess", "welcome", "shadow",
    "superman", "michael", "football", "batman", "iloveyou",
    "admin", "login", "passw0rd", "pa$$word", "administrator",
]

# ── Keyboard walk patterns ─────────────────────────────────────────────────────
KEYBOARD_PATTERNS = [
    "qwerty", "qwertyuiop", "asdfgh", "asdfghjkl",
    "zxcvbn", "zxcvbnm", "1qaz2wsx", "!QAZ2wsx",
    "qazwsx", "1q2w3e4r", "1q2w3e4r5t",
]

# ── Leet-speak substitution table ─────────────────────────────────────────────
LEET_MAP = {
    "a": ["a", "@", "4"],
    "e": ["e", "3"],
    "i": ["i", "1", "!"],
    "o": ["o", "0"],
    "s": ["s", "$", "5"],
    "t": ["t", "7"],
    "l": ["l", "1"],
    "g": ["g", "9"],
}

# ── Number suffixes ────────────────────────────────────────────────────────────
NUMBER_SUFFIXES = [
    "1", "12", "123", "1234", "12345", "123456",
    "0", "00", "007", "01", "99", "2023", "2024", "2025",
    "!", "@", "#",
]


class DictionaryGenerator:
    """Generates targeted wordlists for password security testing."""

    def generate(self, name: str = "", dob: str = "",
                 extra_keywords: list = None) -> list:
        """
        Build a wordlist from the given inputs.

        Parameters
        ----------
        name            : base name or username (e.g. 'alice')
        dob             : date of birth as DDMMYYYY (e.g. '01011990')
        extra_keywords  : additional words to mutate (e.g. ['company', 'project'])

        Returns
        -------
        Deduplicated list of candidate passwords
        """
        wordlist = set()
        extra_keywords = extra_keywords or []

        # Collect base words
        bases = []
        if name:
            bases.append(name.lower())
            bases.append(name.capitalize())
        if dob:
            bases.extend(self._dob_variants(dob))
        bases.extend([k.lower() for k in extra_keywords])
        bases.extend([k.capitalize() for k in extra_keywords])

        # Common passwords
        wordlist.update(COMMON_PASSWORDS)
        wordlist.update(KEYBOARD_PATTERNS)

        # Name + DOB combos
        if name and dob:
            wordlist.update(self._name_dob_combos(name, dob))

        # Mutations on each base
        for base in bases:
            wordlist.update(self._mutations(base))

        # Name + extra keyword combos
        if name and extra_keywords:
            for kw in extra_keywords:
                for combo in [f"{name}{kw}", f"{kw}{name}",
                               f"{name.capitalize()}{kw}",
                               f"{name}{kw.capitalize()}"]:
                    wordlist.update(self._mutations(combo))

        return sorted(wordlist)

    # ── Private helpers ────────────────────────────────────────────────────────

    def _dob_variants(self, dob: str) -> list:
        """Return multiple date formats from a DDMMYYYY string."""
        variants = [dob]
        if len(dob) == 8:
            dd, mm, yyyy = dob[:2], dob[2:4], dob[4:]
            yy = yyyy[2:]
            variants += [
                f"{dd}{mm}{yyyy}", f"{yyyy}{mm}{dd}", f"{dd}{mm}{yy}",
                f"{mm}{dd}{yyyy}", f"{yyyy}", f"{yy}",
                f"{dd}-{mm}-{yyyy}", f"{dd}/{mm}/{yyyy}",
            ]
        return variants

    def _name_dob_combos(self, name: str, dob: str) -> list:
        """Combine name and date fragments."""
        combos = []
        dob_vars = self._dob_variants(dob)
        for dv in dob_vars:
            combos += [
                f"{name}{dv}", f"{name.capitalize()}{dv}",
                f"{dv}{name}", f"{dv}{name.capitalize()}",
            ]
        return combos

    def _mutations(self, word: str) -> list:
        """Apply leet-speak, case, and suffix mutations to a word."""
        results = set()

        # Base variations
        variations = {
            word,
            word.lower(),
            word.upper(),
            word.capitalize(),
            word.title(),
        }

        # Leet-speak on lowercase version
        leet_versions = self._apply_leet(word.lower())
        variations.update(leet_versions)

        # Add number/symbol suffixes to each variation
        for v in list(variations):
            results.add(v)
            for suffix in NUMBER_SUFFIXES:
                results.add(f"{v}{suffix}")
                results.add(f"{suffix}{v}")

        return results

    def _apply_leet(self, word: str) -> list:
        """
        Generate leet-speak variants.
        Limits combinations to avoid exponential explosion.
        """
        # Build per-character replacement options
        options = []
        for ch in word:
            options.append(LEET_MAP.get(ch, [ch]))

        # Limit total combos
        total = 1
        for o in options:
            total *= len(o)
            if total > 500:
                # Return partial leet only (single substitutions)
                results = set()
                for i, ch in enumerate(word):
                    for sub in LEET_MAP.get(ch, [ch]):
                        results.add(word[:i] + sub + word[i+1:])
                return list(results)

        return ["".join(p) for p in itertools.product(*options)]
