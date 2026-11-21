from typing import Dict, Any, Optional
from app.models.schemas import RemediationGuide
from app.remediation.knowledge_base import get_remediation_guide

class RemediationAdvisor:
    """Dynamically contextualizes remediation advice with specific incident parameters."""
    
    def generate_contextual_remediation(
        self,
        threat_type: str,
        source_ip: str,
        target_endpoint: str,
        payload: Optional[str] = None
    ) -> RemediationGuide:
        base_guide = get_remediation_guide(threat_type)
        
        # Contextualize how_to_fix_now with live IP and endpoint
        customized_fixes = []
        for fix in base_guide.how_to_fix_now:
            customized = fix.replace(":source_ip", source_ip).replace(":target", target_endpoint)
            customized_fixes.append(customized)
            
        base_guide.how_to_fix_now = customized_fixes
        return base_guide

remediation_advisor = RemediationAdvisor()
