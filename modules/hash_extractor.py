"""
Module 2: Hash Extractor / Parser
===================================
Handles:
  - Parsing Linux /etc/shadow file format
  - Hashing passwords with common algorithms (MD5, SHA-256, SHA-512, NTLM)
  - Identifying hash algorithms from prefix strings

Note: Requires root/admin privileges to read actual system files.
      This module operates on files you own or have explicit authorization to test.
"""

import hashlib
import hmac
import os
import re
# import crypt  # available on Linux/macOS; not needed for Windows demo


# ── Algorithm identifier map (shadow file prefix → name) ──────────────────────
SHADOW_ALGORITHM_MAP = {
    "$1$":  "MD5",
    "$2a$": "bcrypt",
    "$2b$": "bcrypt",
    "$2y$": "bcrypt",
    "$5$":  "SHA-256",
    "$6$":  "SHA-512",
    "$y$":  "yescrypt",
    "$7$":  "scrypt",
    "":     "DES (legacy)",
    "!":    "LOCKED",
    "*":    "DISABLED",
}

# ── Demo shadow entries (safe fake data for offline testing) ───────────────────
DEMO_SHADOW_ENTRIES = """\
root:$6$rounds=5000$salt123$hashedvalue1234567890abcdefghijklmnopqrstuvwxyz01234567890abcdef:19000:0:99999:7:::
alice:$6$salt456$hashedvalue9876543210zyxwvutsrqponmlkjihgfedcba09876543210zyxwvut:19100:0:99999:7:::
bob:$1$saltweak$abc123hashedpassword1234567:19200:0:99999:7:::
charlie:$5$saltnew$sha256hashexamplevalue123456789012345678901234567890123456789:19300:0:99999:7:::
dave:!$6$saltlock$lockedhashvalue123456789012345678901234567890123456789012345:19400:0:99999:7:::
eve:*:19500:0:99999:7:::
frank:$6$saltsimple$simplehashforfrankaccount123456789012345678901234567890:19600:0:99999:7:::
"""


class HashExtractor:
    """Parse and analyse password hash files; hash passwords for comparison."""

    # ── Shadow file parsing ────────────────────────────────────────────────────

    def parse_shadow_file(self, filepath: str = None) -> list:
        """
        Parse a Linux /etc/shadow-format file.

        Parameters
        ----------
        filepath : path to shadow file. Pass None to use built-in demo data.

        Returns
        -------
        list of dicts with keys: username, algorithm, salt, hash, locked
        """
        if filepath is None:
            lines = DEMO_SHADOW_ENTRIES.strip().splitlines()
            print("[*] Using built-in demo shadow data (no real credentials).")
        else:
            if not os.path.exists(filepath):
                print(f"[!] File not found: {filepath}. Falling back to demo data.")
                return self.parse_shadow_file(None)
            with open(filepath, "r") as f:
                lines = f.readlines()

        entries = []
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parsed = self._parse_shadow_line(line)
            if parsed:
                entries.append(parsed)

        return entries

    def _parse_shadow_line(self, line: str) -> dict:
        """Parse one line of a shadow file."""
        parts = line.split(":")
        if len(parts) < 2:
            return None

        username = parts[0]
        pw_field = parts[1]

        locked = pw_field.startswith("!") or pw_field == "*"
        algorithm = self._identify_algorithm(pw_field)

        # Extract salt and hash from $id$salt$hash format
        salt, hash_value = "", pw_field
        if pw_field.startswith("$"):
            segments = pw_field.split("$")
            # segments: ['', id, salt, hash]  (or more for modern algorithms)
            if len(segments) >= 4:
                salt = segments[2]
                hash_value = segments[-1]

        return {
            "username":  username,
            "algorithm": algorithm,
            "salt":      salt,
            "hash":      hash_value,
            "full_hash": pw_field,
            "locked":    locked,
            "last_changed": parts[2] if len(parts) > 2 else "",
        }

    def _identify_algorithm(self, pw_field: str) -> str:
        """Return algorithm name from shadow hash field."""
        for prefix, name in SHADOW_ALGORITHM_MAP.items():
            if pw_field.startswith(prefix):
                return name
        return "Unknown"

    # ── Password hashing ───────────────────────────────────────────────────────

    def hash_password(self, password: str, algorithm: str = "sha256") -> str:
        """
        Hash a plaintext password using the specified algorithm.

        Supported: md5, sha1, sha256, sha512, ntlm
        """
        algorithm = algorithm.lower()
        pw_bytes = password.encode("utf-8")

        if algorithm == "md5":
            return hashlib.md5(pw_bytes).hexdigest()
        elif algorithm == "sha1":
            return hashlib.sha1(pw_bytes).hexdigest()
        elif algorithm == "sha256":
            return hashlib.sha256(pw_bytes).hexdigest()
        elif algorithm == "sha512":
            return hashlib.sha512(pw_bytes).hexdigest()
        elif algorithm == "ntlm":
            return self._ntlm_hash(password)
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")

    def _ntlm_hash(self, password: str) -> str:
        """Compute NTLM (NT) hash — used in Windows credential storage."""
        # NTLM = MD4 of UTF-16LE encoded password
        # Python's hashlib doesn't include MD4 in newer versions;
        # use the 'hashlib' with OpenSSL or fallback message.
        try:
            h = hashlib.new("md4", password.encode("utf-16-le"))
            return h.hexdigest()
        except ValueError:
            # OpenSSL may not expose MD4 in some distros
            return "[MD4 not available — install openssl-legacy or use hashlib with MD4 support]"

    # ── Hash identification ────────────────────────────────────────────────────

    def identify_hash_type(self, hash_str: str) -> str:
        """Guess the hash type from its length and prefix."""
        length = len(hash_str)
        if hash_str.startswith("$6$"):   return "sha512crypt (Linux)"
        if hash_str.startswith("$5$"):   return "sha256crypt (Linux)"
        if hash_str.startswith("$1$"):   return "md5crypt (Linux)"
        if hash_str.startswith("$2"):    return "bcrypt"
        if hash_str.startswith("$y$"):   return "yescrypt"
        if length == 32:                 return "MD5 (hex)"
        if length == 40:                 return "SHA-1 (hex)"
        if length == 64:                 return "SHA-256 (hex)"
        if length == 128:                return "SHA-512 (hex)"
        return "Unknown"

    # ── Windows SAM info ──────────────────────────────────────────────────────

    @staticmethod
    def windows_sam_info() -> str:
        """Return educational notes on Windows SAM hash extraction."""
        return """
Windows SAM (Security Account Manager) Hash Extraction
======================================================
Location : C:\\Windows\\System32\\config\\SAM
           C:\\Windows\\System32\\config\\SYSTEM  (needed for SYSKEY decryption)

Offline method (requires physical/admin access to own lab machine):
  1. Boot from live USB or use VSS shadow copy
  2. Export hives:
       reg save HKLM\\SAM    sam.hive
       reg save HKLM\\SYSTEM system.hive
  3. Use impacket-secretsdump (Python) on the exported hives:
       python secretsdump.py -sam sam.hive -system system.hive LOCAL

Hash format returned: USERNAME:RID:LM_HASH:NT_HASH:::
  - LM hash  : legacy DES-based (often empty/disabled on modern Windows)
  - NT hash  : MD4(UTF-16LE(password)) — same as NTLM

Defence tip: Disable LM authentication via Group Policy.
             Enable Credential Guard to protect LSASS memory.
"""
