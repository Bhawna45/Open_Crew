"""
Module 5: Report Generator
============================
Produces a complete security audit report in plain text format
summarising results from all modules run in the session.
"""

import datetime
import os


class ReportGenerator:
    """Generate a security audit report from session data."""

    def generate(self, session: dict, output_path: str = None) -> str:
        """
        Build and save the audit report.

        Parameters
        ----------
        session     : dict with keys wordlist, hashes, crack_results,
                      strength_results
        output_path : file to write; defaults to timestamped name

        Returns
        -------
        Path of the saved report file
        """
        if output_path is None:
            ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = f"audit_report_{ts}.txt"

        lines = self._build_report(session)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

        return output_path

    # ── Report builder ────────────────────────────────────────────────────────

    def _build_report(self, session: dict) -> list:
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        lines = []

        lines += self._header(now)
        lines += self._section_dictionary(session.get("wordlist", []))
        lines += self._section_hashes(session.get("hashes", []))
        lines += self._section_crack(session.get("crack_results", []))
        lines += self._section_strength(session.get("strength_results", []))
        lines += self._section_summary(session)
        lines += self._section_mitigations()
        lines += self._footer()

        return lines

    # ── Sections ──────────────────────────────────────────────────────────────

    def _header(self, timestamp: str) -> list:
        return [
            "=" * 70,
            "     PASSWORD CRACKING & CREDENTIAL ATTACK SUITE – AUDIT REPORT",
            "=" * 70,
            f"  Generated : {timestamp}",
            f"  Purpose   : Educational / Authorised Security Assessment",
            f"  Scope     : Controlled lab environment only",
            "=" * 70,
            "",
        ]

    def _section_dictionary(self, wordlist: list) -> list:
        lines = [
            "─" * 70,
            "  SECTION 1: DICTIONARY GENERATOR",
            "─" * 70,
        ]
        if not wordlist:
            lines.append("  No wordlist generated this session.")
        else:
            lines.append(f"  Total words generated : {len(wordlist):,}")
            lines.append(f"  Sample (first 20)     :")
            chunk = wordlist[:20]
            for i in range(0, len(chunk), 5):
                lines.append("    " + "  ".join(chunk[i:i+5]))
        lines.append("")
        return lines

    def _section_hashes(self, hashes: list) -> list:
        lines = [
            "─" * 70,
            "  SECTION 2: HASH EXTRACTION / PARSING",
            "─" * 70,
        ]
        if not hashes:
            lines.append("  No hashes extracted this session.")
        else:
            lines.append(f"  Total entries parsed : {len(hashes)}")
            lines.append("")
            lines.append(f"  {'Username':<20} {'Algorithm':<12} {'Locked':<8}")
            lines.append(f"  {'─'*20} {'─'*12} {'─'*8}")
            for h in hashes:
                locked = "YES" if h.get("locked") else "no"
                lines.append(f"  {h.get('username',''):<20} {h.get('algorithm',''):<12} {locked:<8}")

        # Algorithm distribution
        if hashes:
            alg_counts = {}
            for h in hashes:
                alg = h.get("algorithm", "Unknown")
                alg_counts[alg] = alg_counts.get(alg, 0) + 1
            lines.append("")
            lines.append("  Algorithm distribution:")
            for alg, count in sorted(alg_counts.items()):
                risk = self._alg_risk(alg)
                lines.append(f"    {alg:<15} {count:>3} account(s)  [{risk}]")
        lines.append("")
        return lines

    def _section_crack(self, results: list) -> list:
        lines = [
            "─" * 70,
            "  SECTION 3: BRUTE-FORCE / DICTIONARY ATTACK RESULTS",
            "─" * 70,
        ]
        if not results:
            lines.append("  No attack simulation run this session.")
        else:
            cracked   = [r for r in results if r.get("cracked")]
            uncracked = [r for r in results if not r.get("cracked")]

            lines.append(f"  Targets tested   : {len(results)}")
            lines.append(f"  Passwords cracked: {len(cracked)}  ({self._pct(len(cracked),len(results))}%)")
            lines.append(f"  Not cracked      : {len(uncracked)}")
            lines.append("")

            if cracked:
                lines.append("  ⚠ CRACKED ACCOUNTS:")
                lines.append(f"  {'Username':<20} {'Password':<20} {'Attempts':>10} {'Time':>8}")
                lines.append(f"  {'─'*20} {'─'*20} {'─'*10} {'─'*8}")
                for r in cracked:
                    lines.append(f"  {r['username']:<20} {r['plaintext']:<20} "
                                  f"{r['attempts']:>10,} {r['time_taken']:>7.3f}s")

        lines.append("")
        return lines

    def _section_strength(self, results: list) -> list:
        lines = [
            "─" * 70,
            "  SECTION 4: PASSWORD STRENGTH ANALYSIS",
            "─" * 70,
        ]
        if not results:
            lines.append("  No passwords analysed this session.")
        else:
            lines.append(f"  {'Password':<25} {'Score':>6} {'Grade':<22} {'Entropy':>8}")
            lines.append(f"  {'─'*25} {'─'*6} {'─'*22} {'─'*8}")
            for r in results:
                pw_display = r["password"][:24] + "…" if len(r["password"]) > 24 else r["password"]
                lines.append(f"  {pw_display:<25} {r['score']:>5}/10  "
                              f"{r['grade']:<22} {r['entropy']:>7.1f} bits")

            # Aggregate stats
            scores = [r["score"] for r in results]
            avg_score = sum(scores) / len(scores) if scores else 0
            weak = sum(1 for s in scores if s <= 4)
            lines.append("")
            lines.append(f"  Average score  : {avg_score:.1f}/10")
            lines.append(f"  Weak passwords : {weak}/{len(results)} ({self._pct(weak,len(results))}%)")

            # Common issues
            all_issues = []
            for r in results:
                all_issues.extend(r.get("issues", []))
            if all_issues:
                issue_counts = {}
                for issue in all_issues:
                    issue_counts[issue] = issue_counts.get(issue, 0) + 1
                lines.append("")
                lines.append("  Most common issues:")
                for issue, count in sorted(issue_counts.items(), key=lambda x: -x[1])[:5]:
                    lines.append(f"    • {issue} ({count}×)")

        lines.append("")
        return lines

    def _section_summary(self, session: dict) -> list:
        lines = [
            "─" * 70,
            "  SECTION 5: EXECUTIVE SUMMARY",
            "─" * 70,
        ]

        hashes   = session.get("hashes", [])
        crack    = session.get("crack_results", [])
        strength = session.get("strength_results", [])

        risk_level = self._overall_risk(crack, strength)
        lines.append(f"  Overall risk level : {risk_level}")
        lines.append("")

        findings = []
        if crack:
            cracked_count = sum(1 for r in crack if r.get("cracked"))
            if cracked_count:
                findings.append(f"  ⚠  {cracked_count} password(s) cracked by dictionary attack.")
        if strength:
            weak = sum(1 for r in strength if r["score"] <= 4)
            if weak:
                findings.append(f"  ⚠  {weak} password(s) scored 4/10 or below (Weak or Very Weak).")
        if hashes:
            weak_algs = [h for h in hashes if h.get("algorithm") in ("MD5", "SHA-1", "DES (legacy)")]
            if weak_algs:
                findings.append(f"  ⚠  {len(weak_algs)} account(s) use weak/legacy hashing algorithms.")

        if findings:
            lines.append("  Key Findings:")
            lines.extend(findings)
        else:
            lines.append("  No critical findings detected in this session.")

        lines.append("")
        return lines

    def _section_mitigations(self) -> list:
        return [
            "─" * 70,
            "  SECTION 6: RECOMMENDED MITIGATIONS",
            "─" * 70,
            "",
            "  PASSWORD POLICY",
            "  • Enforce minimum length of 12–16 characters.",
            "  • Require uppercase, lowercase, digits, and symbols.",
            "  • Reject passwords found in common/breached password lists.",
            "  • Implement account lockout after 5–10 failed attempts.",
            "  • Set password expiry to 90 days for sensitive accounts.",
            "",
            "  HASHING & STORAGE",
            "  • Use bcrypt, Argon2id, or scrypt — never plain MD5/SHA-1.",
            "  • Always use a unique per-user random salt.",
            "  • Increase work factor as hardware improves.",
            "",
            "  AUTHENTICATION HARDENING",
            "  • Enable Multi-Factor Authentication (MFA) wherever possible.",
            "  • Monitor failed login attempts and alert on anomalies.",
            "  • Disable LM hashes on Windows via Group Policy.",
            "  • Use Credential Guard to protect LSASS memory.",
            "  • Audit privileged accounts quarterly.",
            "",
            "  USER EDUCATION",
            "  • Train users to use passphrases (e.g. 4-word random phrases).",
            "  • Recommend a password manager (Bitwarden, 1Password, KeePass).",
            "  • Warn against password reuse across sites.",
            "",
        ]

    def _footer(self) -> list:
        return [
            "=" * 70,
            "  END OF REPORT",
            "  This report was generated in a controlled educational environment.",
            "  Unauthorised use of these techniques is illegal and unethical.",
            "=" * 70,
        ]

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _pct(self, part: int, total: int) -> str:
        if total == 0: return "0"
        return f"{part/total*100:.0f}"

    def _alg_risk(self, alg: str) -> str:
        if alg in ("MD5", "SHA-1", "DES (legacy)"): return "HIGH RISK – upgrade immediately"
        if alg in ("SHA-256", "SHA-512"):             return "MEDIUM – use adaptive KDF instead"
        if alg in ("bcrypt", "sha512crypt"):          return "OK – verify work factor"
        if alg in ("yescrypt", "Argon2"):             return "GOOD"
        if alg in ("LOCKED", "DISABLED"):             return "Account disabled"
        return "Unknown"

    def _overall_risk(self, crack: list, strength: list) -> str:
        cracked_count = sum(1 for r in crack if r.get("cracked"))
        weak_count    = sum(1 for r in strength if r.get("score", 10) <= 4)

        if cracked_count > 0 or weak_count > 2:
            return "🔴 HIGH – Immediate action required"
        if weak_count > 0:
            return "🟠 MEDIUM – Improvements recommended"
        return "🟢 LOW – Policies appear adequate"
