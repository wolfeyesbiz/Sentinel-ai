from enum import Enum
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field
from datetime import datetime

class ThreatType(str, Enum):
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    BRUTE_FORCE = "brute_force"
    DDOS = "ddos"
    MALWARE_UPLOAD = "malware_upload"
    SESSION_HIJACKING = "session_hijacking"
    API_ABUSE = "api_abuse"
    BOT_ATTACK = "bot_attack"
    PAYMENT_FRAUD = "payment_fraud"
    DATA_EXFILTRATION = "data_exfiltration"
    ANOMALY = "behavioral_anomaly"
    NORMAL = "normal"

class SeverityLevel(str, Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"
    EMERGENCY = "emergency"

class ThreatStatus(str, Enum):
    BLOCKED = "blocked"
    FLAGGED = "flagged"
    MONITORED = "monitored"
    RESOLVED = "resolved"
    ALLOWED = "allowed"

class RequestInspectionPayload(BaseModel):
    method: str = "GET"
    path: str
    headers: Dict[str, str] = Field(default_factory=dict)
    query_params: Dict[str, str] = Field(default_factory=dict)
    body: Optional[str] = None
    client_ip: str
    user_agent: Optional[str] = "Mozilla/5.0"
    session_id: Optional[str] = None
    user_id: Optional[str] = None
    file_name: Optional[str] = None
    file_content_base64: Optional[str] = None
    timestamp: Optional[datetime] = None

class PreventionMeasure(BaseModel):
    title: str
    description: str
    code_example: Optional[str] = None
    configuration: Optional[str] = None
    priority: str = "high"

class RemediationGuide(BaseModel):
    threat_type: str
    severity: str
    explanation: str
    impact_assessment: Dict[str, str]
    immediate_actions_taken: List[str]
    how_to_fix_now: List[str]
    prevention_measures: List[PreventionMeasure]

class ThreatDetectionResult(BaseModel):
    detected: bool
    threat_type: ThreatType
    severity: SeverityLevel
    risk_score: float = Field(ge=0.0, le=1.0)
    confidence: float = 1.0
    action_taken: ThreatStatus
    matched_patterns: List[str] = Field(default_factory=list)
    malicious_payload: Optional[str] = None
    attack_vector: Optional[str] = None
    target_endpoint: str
    source_ip: str
    country: Optional[str] = "Unknown"
    remediation: Optional[RemediationGuide] = None

class AlertItem(BaseModel):
    id: str
    timestamp: str
    severity: SeverityLevel
    threat_type: ThreatType
    source_ip: str
    country: str = "United States"
    target: str
    status: ThreatStatus
    risk_score: float
    description: str
    payload: Optional[str] = None
    attack_vector: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)
    remediation: Optional[RemediationGuide] = None

class SystemMetrics(BaseModel):
    cpu_usage: float
    ram_usage: float
    network_io: float
    active_processes: int
    system_status: str = "protected"
    threat_level: str = "low"
    active_threats: int = 0
    blocked_today: int = 0
    risk_score: float = 0.12
    timestamp: str

class BlockIPRequest(BaseModel):
    ip_address: str
    duration_hours: int = 24
    reason: str = "Manual admin block"

class BlockIPResponse(BaseModel):
    success: bool
    ip_address: str
    blocked_until: Optional[str] = None
    permanent: bool = False
    message: str

class BlockedIPItem(BaseModel):
    ip_address: str
    reason: str
    blocked_at: str
    blocked_until: Optional[str]
    permanent: bool
    attack_count: int = 1

class SimulateAttackRequest(BaseModel):
    threat_type: ThreatType
    source_ip: Optional[str] = None
    target: Optional[str] = None
    payload: Optional[str] = None

class WafRule(BaseModel):
    id: str
    name: str
    threat_type: ThreatType
    pattern: str
    action: ThreatStatus
    enabled: bool = True
    description: str
