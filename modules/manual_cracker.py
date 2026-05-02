"""
Module 6: Manual Hash Cracker
================================
Lets you paste any hash directly and crack it using:
  1. Built-in 1000+ common password list
  2. Session wordlist (from Dictionary Generator)
  3. External wordlist file (e.g. rockyou.txt)
  4. Custom manual password list (type them in)

Supports: MD5, SHA-1, SHA-256, SHA-512, NTLM
"""

import hashlib
import time
import os
import re


# ── Expanded built-in common password list ─────────────────────────────────────
BUILTIN_LIST = [
    # Top common passwords
    "123456","password","123456789","12345678","12345","1234567","1234567890",
    "qwerty","abc123","111111","123123","admin","letmein","welcome","monkey",
    "dragon","master","sunshine","princess","iloveyou","shadow","superman",
    "michael","football","batman","trustno1","qwerty123","passw0rd","pa$$word",
    "password1","password123","admin123","root","toor","test","guest","user",
    "login","changeme","default","1234","0000","9999","pass","hello","secret",
    # Patterns
    "qwertyuiop","asdfghjkl","zxcvbnm","1q2w3e4r","1q2w3e4r5t","qazwsx",
    "1qaz2wsx","!QAZ2wsx","q1w2e3r4","zaq12wsx","abcdef","abcdefgh",
    # Names
    "michael","jordan","jessica","dragon","monkey","baseball","football",
    "superman","batman","spiderman","pokemon","starwars","harrypotter",
    "mercedes","ferrari","porsche","mustang","corvette",
    # Leet variants
    "p@ssword","p@$$w0rd","passw0rd","p4ssword","pa55word","adm1n",
    "l0gin","welc0me","s3cret","h3llo","t3st","r00t","4dmin",
    # Keyboard walks
    "qweasdzxc","poiuytrewq","mnbvcxz","lkjhgfdsa",
    # With numbers
    "password01","password2023","password2024","admin2023","admin2024",
    "test123","user123","guest123","hello123","welcome1","welcome123",
    # Common pins / numeric
    "000000","111111","222222","333333","444444","555555","666666",
    "777777","888888","999999","112233","121212","123321","654321",
    "987654","987654321","147258369","159357","123456789","1234567890",
    # Years
    "1990","1991","1992","1993","1994","1995","1996","1997","1998","1999",
    "2000","2001","2002","2003","2004","2005","2010","2015","2020",
    "2021","2022","2023","2024","2025",
    # Phrases
    "iloveyou","iloveu","loveyou","fuckyou","fucku","letmein","letsgo",
    "comeон","password!","password#","password@","Password1","Password123",
    "Admin@123","Admin@2024","Admin@2023","Welcome@1","Welcome123",
    "Test@123","User@123","Root@123","Hello@123","Change@123",
    # Indian common passwords
    "india123","bharat","namaste","krishna","ganesh","shiva","rama",
    "sai123","jai","om","hanuman","durga","lakshmi","saraswati",
    "raj123","rahul123","priya123","amit123","suresh","ramesh",
    "india@123","India@123","India123","Bharat@1",
    # Tech defaults
    "cisco","cisco123","admin@123","router","switch","netgear","linksys",
    "raspberry","ubuntu","debian","kali","parrot","metasploit",
    # Common suffixes on 'admin'/'root'
    "admin@1","admin@12","admin1234","root1234","root123","root@123",
    "administrator","Administrator","ADMINISTRATOR","Admin","ROOT",
    # Symbols added
    "password!","password@","password#","qwerty!","abc@123","123@abc",
    "pass@word","P@ssword","P@ssw0rd","P@$$word","Passw0rd!",
]

# ── Algorithm name normaliser ──────────────────────────────────────────────────
ALG_MAP = {
    "1": "md5",
    "2": "sha1",
    "3": "sha256",
    "4": "sha512",
    "5": "ntlm",
    "md5":    "md5",
    "sha1":   "sha1",
    "sha-1":  "sha1",
    "sha256": "sha256",
    "sha-256":"sha256",
    "sha512": "sha512",
    "sha-512":"sha512",
    "ntlm":   "ntlm",
}

# ── Hash length hints for auto-detection ──────────────────────────────────────
LENGTH_HINTS = {
    32:  ["md5", "ntlm"],
    40:  ["sha1"],
    64:  ["sha256"],
    128: ["sha512"],
}


class ManualHashCracker:
    """Crack a user-supplied hash interactively."""

    # ── Main entry point ──────────────────────────────────────────────────────

    def run(self, session: dict):
        """Interactive cracker loop."""
        print("\n" + "─"*55)
        print("  MANUAL HASH CRACKER")
        print("─"*55)
        print("  Paste any hash below and choose an algorithm.")
        print("  The cracker will search through wordlists to find")
        print("  the original password.\n")

        while True:
            target_hash = input("  Enter hash to crack (or 'back' to return): ").strip()
            if target_hash.lower() in ("back", "b", "exit", "q", ""):
                break

            # Validate — hashes are hex strings
            if not re.fullmatch(r"[0-9a-fA-F]+", target_hash):
                print("  [!] That doesn't look like a hex hash. Check for typos.\n")
                continue

            # Auto-detect algorithm
            suggested = self._auto_detect(target_hash)
            alg = self._pick_algorithm(suggested)
            if alg is None:
                continue

            # Choose wordlist source
            wordlist = self._pick_wordlist(session)
            if wordlist is None:
                continue

            # Crack it
            self._crack(target_hash, alg, wordlist)

            again = input("\n  Crack another hash? (y/n): ").strip().lower()
            if again != "y":
                break

    # ── Algorithm picker ──────────────────────────────────────────────────────

    def _auto_detect(self, h: str) -> list:
        """Suggest likely algorithms based on hash length."""
        return LENGTH_HINTS.get(len(h), [])

    def _pick_algorithm(self, suggestions: list) -> str:
        print()
        if suggestions:
            print(f"  Auto-detected likely algorithm(s): {', '.join(suggestions).upper()}")
        print("  Select algorithm:")
        print("    [1] MD5      [2] SHA-1    [3] SHA-256")
        print("    [4] SHA-512  [5] NTLM")
        raw = input("  Choice (number or name): ").strip().lower()
        alg = ALG_MAP.get(raw)
        if alg is None:
            print(f"  [!] Unknown algorithm '{raw}'")
            return None
        print(f"  [*] Using: {alg.upper()}")
        return alg

    # ── Wordlist picker ───────────────────────────────────────────────────────

    def _pick_wordlist(self, session: dict) -> list:
        session_wl = session.get("wordlist", [])
        print()
        print("  Choose wordlist source:")
        print(f"    [1] Built-in list      (~{len(BUILTIN_LIST)} common passwords)")
        print(f"    [2] Session wordlist   ({len(session_wl)} words  "
              f"{'✓ available' if session_wl else '✗ empty — run Dict Gen first'})")
        print(f"    [3] External file      (e.g. rockyou.txt)")
        print(f"    [4] Type passwords     (enter them manually)")
        print(f"    [5] Combined           (built-in + session)")
        choice = input("  Choice: ").strip()

        if choice == "1":
            return list(BUILTIN_LIST)

        elif choice == "2":
            if not session_wl:
                print("  [!] Session wordlist is empty. Run Dictionary Generator first.")
                return None
            return list(session_wl)

        elif choice == "3":
            path = input("  Path to wordlist file: ").strip().strip('"')
            if not os.path.exists(path):
                print(f"  [!] File not found: {path}")
                return None
            print(f"  [*] Loading '{path}'...")
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                words = [line.strip() for line in f if line.strip()]
            print(f"  [+] Loaded {len(words):,} words.")
            return words

        elif choice == "4":
            print("  Enter passwords (one per line, blank line to finish):")
            words = []
            while True:
                w = input("    > ").strip()
                if not w:
                    break
                words.append(w)
            if not words:
                print("  [!] No passwords entered.")
                return None
            return words

        elif choice == "5":
            combined = list(BUILTIN_LIST) + list(session_wl)
            # deduplicate while preserving order
            seen = set()
            unique = []
            for w in combined:
                if w not in seen:
                    seen.add(w)
                    unique.append(w)
            print(f"  [+] Combined: {len(unique):,} unique words.")
            return unique

        else:
            print("  [!] Invalid choice.")
            return None

    # ── Core cracking engine ──────────────────────────────────────────────────

    def _crack(self, target_hash: str, alg: str, wordlist: list):
        """
        Try every word in wordlist against the target hash.
        Shows live progress every 5 000 attempts.
        """
        target_hash = target_hash.lower()
        total = len(wordlist)

        print(f"\n  [*] Starting crack → target: {target_hash[:20]}..."
              f"  algorithm: {alg.upper()}  wordlist: {total:,} words\n")

        start = time.perf_counter()
        found = None

        for i, word in enumerate(wordlist, 1):
            try:
                h = self._compute_hash(word, alg)
            except Exception:
                continue

            if h == target_hash:
                found = word
                break

            # Progress indicator every 5000 attempts
            if i % 5000 == 0:
                elapsed = time.perf_counter() - start
                speed = i / elapsed if elapsed > 0 else 0
                print(f"  ... {i:>8,}/{total:,}  speed: {speed:,.0f} H/s", end="\r")

        elapsed = time.perf_counter() - start
        print(" " * 60, end="\r")   # clear progress line

        if found is not None:
            print("  ╔══════════════════════════════════════════════╗")
            print(f"  ║  ✓  CRACKED!                                ║")
            print(f"  ║  Hash      : {target_hash[:38]:<38} ║")
            print(f"  ║  Password  : {found:<38} ║")
            print(f"  ║  Algorithm : {alg.upper():<38} ║")
            print(f"  ║  Attempts  : {i:<38,} ║")
            print(f"  ║  Time      : {elapsed:.3f}s{'':<33} ║")
            print("  ╚══════════════════════════════════════════════╝")
        else:
            print(f"  [✗] NOT FOUND in {total:,} words after {elapsed:.2f}s.")
            print(f"      Try a larger wordlist (e.g. rockyou.txt) or check the algorithm.")
            print(f"      Tip: Use option [3] to load an external wordlist file.")

        # Store result in session for report
        return {
            "hash":      target_hash,
            "algorithm": alg,
            "cracked":   found is not None,
            "plaintext": found,
            "attempts":  i if found else total,
            "time":      elapsed,
        }

    # ── Hash computation ──────────────────────────────────────────────────────

    def _compute_hash(self, password: str, alg: str) -> str:
        pw = password.encode("utf-8")
        if alg == "md5":
            return hashlib.md5(pw).hexdigest()
        if alg == "sha1":
            return hashlib.sha1(pw).hexdigest()
        if alg == "sha256":
            return hashlib.sha256(pw).hexdigest()
        if alg == "sha512":
            return hashlib.sha512(pw).hexdigest()
        if alg == "ntlm":
            try:
                return hashlib.new("md4", password.encode("utf-16-le")).hexdigest()
            except ValueError:
                raise ValueError("NTLM (MD4) not available on this system")
        raise ValueError(f"Unsupported: {alg}")

    # ── Quick hash utility (generate a hash to test with) ────────────────────

    def hash_and_show(self):
        """Let the user generate a hash they can then try to crack."""
        print("\n  ── Hash Generator (for testing) ──")
        pw  = input("  Password to hash: ").strip()
        alg = input("  Algorithm (md5/sha1/sha256/sha512/ntlm) [sha256]: ").strip().lower() or "sha256"
        alg_key = ALG_MAP.get(alg, "sha256")
        try:
            h = self._compute_hash(pw, alg_key)
            print(f"\n  {alg_key.upper()} hash of '{pw}':")
            print(f"  {h}")
            print(f"\n  (Copy the hash above and use option [7] to crack it)\n")
        except Exception as e:
            print(f"  [!] Error: {e}")
