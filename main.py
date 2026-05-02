#!/usr/bin/env python3
"""
Password Cracking & Credential Attack Suite
============================================
Educational toolkit for password policy testing and credential security assessment.
Run only in authorized, controlled lab environments.
"""

import sys
import os

# Make sure modules are importable
sys.path.insert(0, os.path.dirname(__file__))

from modules.dictionary_generator   import DictionaryGenerator
from modules.hash_extractor         import HashExtractor
from modules.brute_force_simulator  import BruteForceSimulator
from modules.password_strength      import PasswordStrengthAnalyzer
from modules.report_generator       import ReportGenerator
from modules.manual_cracker         import ManualHashCracker


BANNER = """
╔══════════════════════════════════════════════════════════════╗
║       Password Cracking & Credential Attack Suite            ║
║       Educational Use Only – Authorized Environments         ║
╚══════════════════════════════════════════════════════════════╝
"""

MENU = """
┌─────────────────────────────────────────┐
│  [1] Dictionary Generator               │
│  [2] Hash Extractor / Parser            │
│  [3] Brute-Force Simulator              │
│  [4] Password Strength Analyzer         │
│  [5] Generate Audit Report              │
│  [6] Run Full Demo (all modules)        │
│  ─────────────────────────────────────  │
│  [7] Manual Hash Cracker  ← NEW        │
│  [8] Generate Hash (for testing) ← NEW │
│  ─────────────────────────────────────  │
│  [0] Exit                               │
└─────────────────────────────────────────┘
"""


def main():
    print(BANNER)

    # Shared session data so report can collect results from all modules
    session = {
        "wordlist":        [],
        "hashes":          [],
        "crack_results":   [],
        "strength_results": [],
    }

    while True:
        print(MENU)
        choice = input("Select option: ").strip()

        if choice == "1":
            run_dictionary_generator(session)
        elif choice == "2":
            run_hash_extractor(session)
        elif choice == "3":
            run_brute_force(session)
        elif choice == "4":
            run_strength_analyzer(session)
        elif choice == "5":
            run_report(session)
        elif choice == "6":
            run_full_demo(session)
        elif choice == "7":
            cracker = ManualHashCracker()
            cracker.run(session)
        elif choice == "8":
            cracker = ManualHashCracker()
            cracker.hash_and_show()
        elif choice == "0":
            print("\n[*] Exiting. Stay ethical!\n")
            sys.exit(0)
        else:
            print("[!] Invalid choice. Try again.")


# ─── Module runners ────────────────────────────────────────────────────────────

def run_dictionary_generator(session):
    print("\n══ Dictionary Generator ══")
    gen = DictionaryGenerator()

    name   = input("Enter base name/word (e.g. 'alice'): ").strip() or "admin"
    dob    = input("Enter date of birth (DDMMYYYY) or press Enter to skip: ").strip()
    extra  = input("Extra keywords, comma-separated (or Enter to skip): ").strip()
    keywords = [k.strip() for k in extra.split(",")] if extra else []

    wordlist = gen.generate(name=name, dob=dob, extra_keywords=keywords)
    session["wordlist"] = wordlist

    out_file = "wordlist.txt"
    with open(out_file, "w") as f:
        f.write("\n".join(wordlist))

    print(f"\n[+] Generated {len(wordlist)} words → saved to '{out_file}'")
    print(f"    Preview (first 15): {wordlist[:15]}")


def run_hash_extractor(session):
    print("\n══ Hash Extractor / Parser ══")
    extractor = HashExtractor()

    print("  [a] Parse a shadow-format file")
    print("  [b] Hash a password (demo)")
    sub = input("Choice: ").strip().lower()

    if sub == "a":
        path = input("Path to shadow file (or press Enter for built-in demo): ").strip()
        entries = extractor.parse_shadow_file(path if path else None)
        session["hashes"] = entries
        print(f"\n[+] Parsed {len(entries)} entries:")
        for e in entries:
            print(f"    User: {e['username']:15s}  Algorithm: {e['algorithm']:8s}  Hash: {e['hash'][:30]}...")

    elif sub == "b":
        pw  = input("Enter password to hash: ").strip()
        alg = input("Algorithm (md5 / sha256 / sha512 / ntlm) [sha256]: ").strip() or "sha256"
        result = extractor.hash_password(pw, alg)
        print(f"\n[+] {alg.upper()} hash of '{pw}':\n    {result}")
        session["hashes"].append({"username": "demo", "algorithm": alg,
                                  "hash": result, "plaintext": pw})


def run_brute_force(session):
    print("\n══ Brute-Force Simulator ══")
    sim = BruteForceSimulator()

    print("  [a] Estimate time to crack a password")
    print("  [b] Dictionary attack on sample hashes")
    sub = input("Choice: ").strip().lower()

    if sub == "a":
        pw  = input("Enter password to estimate: ").strip()
        alg = input("Hash algorithm (md5 / sha256 / sha512) [sha256]: ").strip() or "sha256"
        result = sim.estimate_crack_time(pw, alg)
        session["crack_results"].append(result)
        _print_estimate(result)

    elif sub == "b":
        wordlist = session.get("wordlist") or []
        if not wordlist:
            print("[!] No wordlist in session. Run Dictionary Generator first, or load a file.")
            path = input("Path to wordlist file (or Enter to use default list): ").strip()
            if path and os.path.exists(path):
                with open(path) as f:
                    wordlist = [l.strip() for l in f if l.strip()]
            else:
                wordlist = ["password", "123456", "admin", "letmein", "qwerty"]

        hashes = session.get("hashes") or []
        if not hashes:
            print("[!] No hashes in session. Run Hash Extractor first, or use demo targets.")
            hashes = sim.demo_targets()

        results = sim.dictionary_attack(hashes, wordlist)
        session["crack_results"].extend(results)
        print(f"\n[+] Dictionary attack complete. {len(results)} target(s) tested.")
        for r in results:
            status = f"CRACKED → '{r['plaintext']}'" if r["cracked"] else "NOT CRACKED"
            print(f"    {r['username']:15s}  {status}  ({r['attempts']} attempts, {r['time_taken']:.3f}s)")


def run_strength_analyzer(session):
    print("\n══ Password Strength Analyzer ══")
    analyzer = PasswordStrengthAnalyzer()

    passwords = []
    print("Enter passwords to analyze (one per line, blank line to finish):")
    while True:
        pw = input("  > ").strip()
        if not pw:
            break
        passwords.append(pw)

    if not passwords:
        passwords = ["Password1", "123456", "Tr0ub4dor&3", "correcthorsebatterystaple"]
        print(f"[*] Using demo passwords: {passwords}")

    for pw in passwords:
        result = analyzer.analyze(pw)
        session["strength_results"].append(result)
        _print_strength(result)


def run_report(session):
    print("\n══ Audit Report Generator ══")
    gen = ReportGenerator()
    filename = gen.generate(session)
    print(f"\n[+] Audit report saved → '{filename}'")


def run_full_demo(session):
    print("\n\n══════════════  FULL DEMO  ══════════════\n")

    # 1. Dictionary
    gen = DictionaryGenerator()
    session["wordlist"] = gen.generate(name="alice", dob="01011990",
                                        extra_keywords=["company", "welcome"])
    print(f"[1] Dictionary Generator: {len(session['wordlist'])} words created.")

    # 2. Hash Extractor
    extractor = HashExtractor()
    session["hashes"] = extractor.parse_shadow_file(None)   # built-in demo
    print(f"[2] Hash Extractor: {len(session['hashes'])} shadow entries parsed.")

    # 3. Brute-Force Simulator
    sim = BruteForceSimulator()
    session["crack_results"] = sim.dictionary_attack(session["hashes"], session["wordlist"])
    cracked = sum(1 for r in session["crack_results"] if r["cracked"])
    print(f"[3] Brute-Force Simulator: {cracked}/{len(session['crack_results'])} passwords cracked.")

    # 4. Strength Analyzer
    analyzer = PasswordStrengthAnalyzer()
    demo_pws = ["password", "Admin@2024", "Tr0ub4dor&3", "123456789", "G7#kLmP2!q"]
    session["strength_results"] = [analyzer.analyze(pw) for pw in demo_pws]
    print(f"[4] Strength Analyzer: {len(demo_pws)} passwords analyzed.")

    # 5. Report
    gen = ReportGenerator()
    filename = gen.generate(session)
    print(f"[5] Report Generator: Audit saved → '{filename}'")
    print("\n[✓] Full demo complete. Open the report to view results.\n")


# ─── Helpers ───────────────────────────────────────────────────────────────────

def _print_estimate(r):
    print(f"""
    Password      : {r['password']}
    Length        : {r['length']}
    Character set : {r['charset_size']} chars
    Keyspace      : {r['keyspace']:,}
    Algorithm     : {r['algorithm'].upper()} ({r['hashes_per_second']:,} H/s)
    Avg time      : {r['avg_time_human']}
    Worst case    : {r['worst_time_human']}
    Strength hint : {r['strength_hint']}
    """)


def _print_strength(r):
    bar = "█" * r["score"] + "░" * (10 - r["score"])
    print(f"""
    Password   : {r['password']}
    Score      : [{bar}] {r['score']}/10  ({r['grade']})
    Entropy    : {r['entropy']:.1f} bits
    Issues     : {', '.join(r['issues']) if r['issues'] else 'None'}
    Suggestions: {', '.join(r['suggestions']) if r['suggestions'] else 'None'}
    """)


if __name__ == "__main__":
    main()
