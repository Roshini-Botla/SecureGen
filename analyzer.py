import os
import json
import re
import httpx
from models import AnalysisResponse, Vulnerability, SecurityMetrics
from language_detector import detect_language, count_lines

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")

SYSTEM_PROMPT = """You are SecureGen, an expert static code analysis engine specializing in security vulnerabilities in AI-generated code. Your role is to perform thorough security analysis modeled after CodeQL, Semgrep, and OWASP guidelines.

Analyze code for ALL of the following vulnerability categories:
- Injection: SQL injection, command injection, LDAP injection, XPath injection, template injection
- Cryptography: weak algorithms (MD5, SHA1, DES, RC4), hardcoded secrets/keys/passwords, insecure random, missing encryption
- Authentication & Authorization: broken auth, missing auth checks, insecure session management, privilege escalation
- Input Validation: missing sanitization, XSS, path traversal, buffer overflow, integer overflow
- Information Disclosure: sensitive data exposure, debug info leakage, verbose error messages, logging of secrets
- Dependency & Configuration: use of deprecated/unsafe APIs, insecure defaults, missing security headers
- Memory Safety: use-after-free, null pointer dereference, memory leaks (for C/C++/Rust)
- Concurrency: race conditions, deadlocks, TOCTOU issues
- Insecure Deserialization: unsafe pickle/yaml/XML parsing, object injection
- SSRF / Open Redirect: unvalidated URLs and redirects
- File Operations: arbitrary file read/write, zip slip, symlink attacks
- API Security: missing rate limiting, exposed sensitive endpoints, verbose API errors

Map each finding to the appropriate CWE ID.
Assign CVSS v3 scores: CRITICAL (9.0-10.0), HIGH (7.0-8.9), MEDIUM (4.0-6.9), LOW (0.1-3.9), INFO (0.0).

Respond ONLY with a valid JSON object (no markdown, no explanation) with this exact schema:
{
  "language": "string",
  "vulnerabilities": [
    {
      "id": "VULN-001",
      "cwe_id": "CWE-89",
      "title": "string",
      "severity": "HIGH",
      "cvss_score": 7.5,
      "line_number": 12,
      "line_snippet": "string (the actual code line)",
      "description": "string",
      "recommendation": "string",
      "category": "Injection"
    }
  ],
  "summary": "string (2-3 sentence overall security summary)",
  "recommendations": ["string", "string"],
  "ai_insights": "string (paragraph about security posture and patterns observed)"
}

If no vulnerabilities found, return empty vulnerabilities array. Be precise — only report real findings, not theoretical ones. Include line numbers whenever possible.
"""


async def analyze_code(code: str, filename: str, ext: str) -> AnalysisResponse:
    language = detect_language(ext)
    total_lines, code_lines = count_lines(code)

    if not ANTHROPIC_API_KEY:
        return _fallback_analysis(code, filename, language, total_lines, code_lines)

    prompt = f"""Analyze this {language} file for security vulnerabilities.

Filename: {filename}
Language: {language}
Total Lines: {total_lines}

CODE:
```{language.lower()}
{code[:15000]}
```

Return ONLY the JSON response as specified."""

    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": ANTHROPIC_API_KEY,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": "claude-sonnet-4-6",
                    "max_tokens": 4096,
                    "system": SYSTEM_PROMPT,
                    "messages": [{"role": "user", "content": prompt}],
                },
            )

        if response.status_code != 200:
            return _fallback_analysis(code, filename, language, total_lines, code_lines)

        data = response.json()
        text = data["content"][0]["text"].strip()

        # Strip markdown fences if present
        text = re.sub(r"^```json\s*", "", text)
        text = re.sub(r"\s*```$", "", text)

        parsed = json.loads(text)
        return _build_response(parsed, filename, language, total_lines, code_lines)

    except Exception as e:
        print(f"Analysis error: {e}")
        return _fallback_analysis(code, filename, language, total_lines, code_lines)


def _build_response(parsed: dict, filename: str, language: str, total_lines: int, code_lines: int) -> AnalysisResponse:
    vulns = []
    for i, v in enumerate(parsed.get("vulnerabilities", [])):
        vulns.append(Vulnerability(
            id=v.get("id", f"VULN-{i+1:03d}"),
            cwe_id=v.get("cwe_id"),
            title=v.get("title", "Unknown Vulnerability"),
            severity=v.get("severity", "MEDIUM").upper(),
            cvss_score=v.get("cvss_score"),
            line_number=v.get("line_number"),
            line_snippet=v.get("line_snippet"),
            description=v.get("description", ""),
            recommendation=v.get("recommendation", ""),
            category=v.get("category", "General"),
        ))

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for v in vulns:
        counts[v.severity] = counts.get(v.severity, 0) + 1

    score = _calculate_score(counts)
    risk = _risk_level(counts)

    metrics = SecurityMetrics(
        total_lines=total_lines,
        code_lines=code_lines,
        vulnerability_count=len(vulns),
        critical_count=counts["CRITICAL"],
        high_count=counts["HIGH"],
        medium_count=counts["MEDIUM"],
        low_count=counts["LOW"],
        info_count=counts["INFO"],
        security_score=score,
        risk_level=risk,
    )

    return AnalysisResponse(
        filename=filename,
        language=language,
        metrics=metrics,
        vulnerabilities=vulns,
        summary=parsed.get("summary", "Analysis complete."),
        recommendations=parsed.get("recommendations", []),
        ai_insights=parsed.get("ai_insights", ""),
    )


def _calculate_score(counts: dict) -> int:
    penalty = (
        counts.get("CRITICAL", 0) * 25 +
        counts.get("HIGH", 0) * 15 +
        counts.get("MEDIUM", 0) * 7 +
        counts.get("LOW", 0) * 3 +
        counts.get("INFO", 0) * 1
    )
    return max(0, 100 - penalty)


def _risk_level(counts: dict) -> str:
    if counts.get("CRITICAL", 0) > 0:
        return "CRITICAL"
    if counts.get("HIGH", 0) > 0:
        return "HIGH"
    if counts.get("MEDIUM", 0) > 0:
        return "MEDIUM"
    if counts.get("LOW", 0) > 0:
        return "LOW"
    return "SECURE"


def _fallback_analysis(code: str, filename: str, language: str, total_lines: int, code_lines: int) -> AnalysisResponse:
    """Rule-based fallback when API key is missing or API fails."""
    vulns = []
    lines = code.split("\n")

    patterns = [
        (r"eval\s*\(", "CRITICAL", "CWE-95", "Dangerous eval() Usage", "Code Execution",
         "eval() executes arbitrary code and is extremely dangerous with user input.",
         "Replace eval() with safer alternatives like ast.literal_eval() for data parsing."),
        (r"(password|secret|api_key|token|passwd)\s*=\s*['\"][^'\"]{4,}", "HIGH", "CWE-798",
         "Hardcoded Credential", "Authentication",
         "Hardcoded credentials found in source code. If committed to version control, these are exposed.",
         "Use environment variables or a secrets manager instead of hardcoded credentials."),
        (r"md5|sha1\b", "MEDIUM", "CWE-327", "Weak Cryptographic Algorithm", "Cryptography",
         "MD5/SHA1 are cryptographically broken and should not be used for security purposes.",
         "Use SHA-256 or SHA-3 for hashing. Use bcrypt/argon2 for passwords."),
        (r"subprocess\.call|os\.system|exec\(", "HIGH", "CWE-78", "Potential Command Injection", "Injection",
         "Shell commands executed with user-controlled input can lead to command injection.",
         "Use subprocess with a list of arguments and shell=False. Validate all inputs."),
        (r"pickle\.loads|pickle\.load", "HIGH", "CWE-502", "Insecure Deserialization", "Deserialization",
         "Deserializing untrusted data with pickle can execute arbitrary code.",
         "Use JSON or other safe serialization formats. Never deserialize untrusted data with pickle."),
        (r"random\.(random|randint|choice)\(\)", "LOW", "CWE-330", "Weak Pseudo-Random Number", "Cryptography",
         "random module is not cryptographically secure.",
         "Use secrets module or os.urandom() for cryptographic operations."),
        (r"SELECT.+WHERE.+['\"].*\+", "CRITICAL", "CWE-89", "SQL Injection Risk", "Injection",
         "String concatenation in SQL queries can lead to SQL injection attacks.",
         "Use parameterized queries or an ORM to prevent SQL injection."),
        (r"innerHTML\s*=|document\.write\(", "HIGH", "CWE-79", "Cross-Site Scripting (XSS)", "Injection",
         "Directly inserting user data into innerHTML or document.write can enable XSS attacks.",
         "Sanitize input and use textContent instead of innerHTML, or use a library like DOMPurify."),
        (r"verify\s*=\s*False", "MEDIUM", "CWE-295", "SSL Certificate Verification Disabled", "Configuration",
         "Disabling SSL certificate verification makes the app vulnerable to man-in-the-middle attacks.",
         "Always enable SSL verification in production. Use verify=True (default)."),
        (r"DEBUG\s*=\s*True", "LOW", "CWE-489", "Debug Mode Enabled", "Configuration",
         "Debug mode exposes sensitive information and should never be enabled in production.",
         "Set DEBUG=False in production environments."),
    ]

    for line_num, line in enumerate(lines, start=1):
        for pattern, severity, cwe, title, category, desc, rec in patterns:
            if re.search(pattern, line, re.IGNORECASE):
                vuln_id = f"VULN-{len(vulns)+1:03d}"
                vulns.append(Vulnerability(
                    id=vuln_id,
                    cwe_id=cwe,
                    title=title,
                    severity=severity,
                    cvss_score={"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.5, "LOW": 2.5}.get(severity, 5.0),
                    line_number=line_num,
                    line_snippet=line.strip()[:120],
                    description=desc,
                    recommendation=rec,
                    category=category,
                ))

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for v in vulns:
        counts[v.severity] = counts.get(v.severity, 0) + 1

    score = _calculate_score(counts)
    risk = _risk_level(counts)

    summary = (
        f"Rule-based scan of {filename} ({language}) completed. "
        f"Found {len(vulns)} potential issue(s). "
        f"Set ANTHROPIC_API_KEY for deep AI-powered analysis."
    ) if vulns else (
        f"No common vulnerability patterns detected in {filename} by rule-based scan. "
        f"Set ANTHROPIC_API_KEY for comprehensive AI-powered analysis."
    )

    return AnalysisResponse(
        filename=filename,
        language=language,
        metrics=SecurityMetrics(
            total_lines=total_lines,
            code_lines=code_lines,
            vulnerability_count=len(vulns),
            critical_count=counts["CRITICAL"],
            high_count=counts["HIGH"],
            medium_count=counts["MEDIUM"],
            low_count=counts["LOW"],
            info_count=counts["INFO"],
            security_score=score,
            risk_level=risk,
        ),
        vulnerabilities=vulns,
        summary=summary,
        recommendations=[
            "Set the ANTHROPIC_API_KEY environment variable for full AI-powered analysis.",
            "Review all flagged lines manually.",
            "Run additional tools like bandit (Python) or eslint-security (JS) for deeper coverage.",
        ],
        ai_insights="AI-powered insights are unavailable without an Anthropic API key. The rule-based scan above covers the most common vulnerability patterns.",
    )