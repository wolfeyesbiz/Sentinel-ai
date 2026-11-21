import re
from typing import Dict, Any, Optional

class BotDetector:
    def __init__(self):
        # Known automated bot & scraper user-agent signatures
        self.bot_signatures = [
            r'python-requests', r'scrapy', r'curl\/', r'wget\/', r'postmanruntime',
            r'headlesschrome', r'puppeteer', r'playwright', r'selenium',
            r'phantomjs', r'go-http-client', r'aiohttp', r'httpx', r'libwww-perl',
            r'zgrab', r'nikto', r'sqlmap', r'nmap', r'masscan'
        ]
        self.bot_regexes = [re.compile(b, re.IGNORECASE) for b in self.bot_signatures]

    def inspect(self, user_agent: Optional[str], headers: Dict[str, str], path: str) -> Dict[str, Any]:
        ua = user_agent or ""
        matched = []
        risk_score = 0.0

        # 1. User Agent signature matching
        for b_rgx in self.bot_regexes:
            if b_rgx.search(ua):
                matched.append(f"Automated tool/scraper signature in User-Agent: {ua[:35]}")
                risk_score = max(risk_score, 0.85)
                break

        # 2. Check for missing User-Agent header entirely on protected endpoints
        if not ua and any(p in path.lower() for p in ["/cart", "/checkout", "/auth"]):
            matched.append("Missing mandatory User-Agent header on transaction endpoint")
            risk_score = max(risk_score, 0.75)

        # 3. Inventory hoarding probe (e.g. rapid cart reserve endpoint hits)
        if "/api/cart/reserve" in path.lower() or "/api/cart/batch-add" in path.lower():
            if risk_score > 0.4:
                matched.append("Bot inventory hoarding pattern targeted at high-demand stock")
                risk_score = max(risk_score, 0.90)

        detected = risk_score >= 0.70
        return {
            "detected": detected,
            "risk_score": min(1.0, risk_score),
            "matched": matched,
            "user_agent": ua
        }

bot_detector = BotDetector()
