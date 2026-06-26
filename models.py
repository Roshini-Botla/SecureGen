from pydantic import BaseModel
from typing import List, Optional


class Vulnerability(BaseModel):
    id: str
    cwe_id: Optional[str] = None
    title: str
    severity: str           # CRITICAL / HIGH / MEDIUM / LOW / INFO
    cvss_score: Optional[float] = None
    line_number: Optional[int] = None
    line_snippet: Optional[str] = None
    description: str
    recommendation: str
    category: str           # e.g. Injection, Cryptography, Auth, etc.


class SecurityMetrics(BaseModel):
    total_lines: int
    code_lines: int
    vulnerability_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    security_score: int     # 0-100
    risk_level: str         # CRITICAL / HIGH / MEDIUM / LOW / SECURE


class AnalysisResponse(BaseModel):
    filename: str
    language: str
    metrics: SecurityMetrics
    vulnerabilities: List[Vulnerability]
    summary: str
    recommendations: List[str]
    ai_insights: str