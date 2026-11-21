from fastapi import APIRouter
from typing import Dict, Any, List
from app.models.schemas import SimulateAttackRequest, ThreatType
from app.simulation.attack_simulator import attack_simulator, SCENARIOS

router = APIRouter(prefix="/simulate-attack", tags=["Attack Simulator"])

@router.post("")
async def simulate_attack(req: SimulateAttackRequest):
    return await attack_simulator.simulate(
        threat_type=req.threat_type,
        source_ip=req.source_ip,
        target=req.target,
        payload_override=req.payload
    )

@router.get("/scenarios")
async def get_attack_scenarios() -> List[Dict[str, Any]]:
    scenarios = []
    descriptions = {
        ThreatType.SQL_INJECTION: "Bypasses authentication and attempts to dump or drop database tables via SQL syntax injection.",
        ThreatType.XSS: "Injects malicious script tag to hijack customer session cookies via reflected/stored input.",
        ThreatType.BRUTE_FORCE: "High-frequency credential stuffing against customer & admin authentication endpoints.",
        ThreatType.DDOS: "Volumetric burst flooding requests to deplete web server worker pools.",
        ThreatType.MALWARE_UPLOAD: "Uploads an executable web shell with polyglot PHP headers disguised as an image avatar.",
        ThreatType.SESSION_HIJACKING: "Replays stolen session token from a disparate IP and altered browser fingerprint.",
        ThreatType.API_ABUSE: "Manipulates JSON price field to 0.00 and attempts role escalation to administrator.",
        ThreatType.BOT_ATTACK: "Automated scraper inventory hoarding targeted at high-demand products.",
        ThreatType.PAYMENT_FRAUD: "High-velocity carding authorization attack testing stolen credit cards.",
        ThreatType.DATA_EXFILTRATION: "Attempts bulk database export with unbounded limit parameter."
    }

    for tt, sc in SCENARIOS.items():
        scenarios.append({
            "threat_type": tt.value,
            "title": tt.value.replace("_", " ").title(),
            "target": sc.get("path"),
            "source_ip": sc.get("source_ip"),
            "description": descriptions.get(tt, "Simulated security vector")
        })
    return scenarios
