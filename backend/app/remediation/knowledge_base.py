"""
Sentinel AI - Automated Remediation Knowledge Base
Provides deep, actionable remediation guidance for all 10 attack classes:
1. SQL Injection (SQLi)
2. Cross-Site Scripting (XSS)
3. Brute Force Attacks
4. DDoS / DoS Attacks
5. Malware Upload Attempts
6. Session Hijacking
7. API Abuse / Parameter Tampering
8. Bot Attacks & Scraping
9. Payment Fraud / Velocity Attacks
10. Data Exfiltration
"""

from typing import Dict, Any
from app.models.schemas import RemediationGuide, PreventionMeasure

REMEDIATION_KB: Dict[str, Dict[str, Any]] = {
    "sql_injection": {
        "threat_type": "sql_injection",
        "severity": "critical",
        "explanation": "SQL injection occurs when untrusted user input is directly concatenated into database query strings, allowing attackers to bypass authentication, read or destroy database contents, or execute administrative commands.",
        "impact_assessment": {
            "potential_damage": "CRITICAL - Unauthorized database takeover, table drops, and data loss",
            "data_at_risk": "Customer credentials, credit card records, hashed passwords, PII, inventory tables",
            "business_impact": "Catastrophic data breach, PCI-DSS compliance failure, regulatory fines (GDPR/CCPA), brand destruction"
        },
        "immediate_actions_taken": [
            "Attack blocked at Sentinel AI WAF layer (HTTP 403 Forbidden issued)",
            "Attacker IP dynamically quarantined in temporary firewall blacklist (24 hours)",
            "Automated alert dispatched via WebSocket, Webhook, and Admin SMS/Email",
            "Tampered query captured in immutable audit trail for forensic investigation"
        ],
        "how_to_fix_now": [
            "1. Verify no queries executed: Check database query audit logs for recent statements from the offending IP: SELECT * FROM pg_stat_activity WHERE client_addr = :source_ip;",
            "2. Audit database consistency and integrity: Run DBCC CHECKDB('store_database') or check Postgres table integrity.",
            "3. Revoke any active sessions opened from this IP address across all customer and admin accounts.",
            "4. Rotate database administrative credentials immediately if any privileged connection leaks occurred."
        ],
        "prevention_measures": [
            {
                "title": "Use Parameterized Queries & Prepared Statements",
                "description": "Never concatenate user-supplied input into SQL strings. Always pass variables via parameterized drivers.",
                "code_example": (
                    "# Python (psycopg2 / asyncpg / sqlite3)\n"
                    "# BAD (vulnerable):\n"
                    "# cursor.execute(f\"SELECT * FROM products WHERE category = '{category}'\")\n\n"
                    "# GOOD (safe parameterized query):\n"
                    "cursor.execute(\"SELECT * FROM products WHERE category = %s AND status = 'active'\", (category,))\n\n"
                    "// Node.js (pg / mysql2)\n"
                    "const result = await pool.query(\n"
                    "  'SELECT * FROM products WHERE category = $1 AND in_stock = true',\n"
                    "  [category]\n"
                    ");"
                ),
                "configuration": (
                    "# ORM Configuration (SQLAlchemy / Prisma)\n"
                    "# Use strict ORM query builders that enforce parameter binding:\n"
                    "db.query(Product).filter(Product.category == category).all()"
                ),
                "priority": "critical"
            },
            {
                "title": "Strict Whitelist Input Validation",
                "description": "Validate all incoming category, filter, and sorting parameters against known-safe regular expressions or enums.",
                "code_example": (
                    "import re\n"
                    "def validate_category_slug(slug: str) -> str:\n"
                    "    if not re.match(r'^[a-zA-Z0-9_-]{2,50}$', slug):\n"
                    "        raise ValueError('Invalid category identifier format')\n"
                    "    return slug.lower()"
                ),
                "configuration": None,
                "priority": "high"
            },
            {
                "title": "Principle of Least Privilege Database Role",
                "description": "Ensure the e-commerce application user has minimal database privileges. Deny DROP, ALTER, and administrative privileges.",
                "code_example": None,
                "configuration": (
                    "-- PostgreSQL Principle of Least Privilege\n"
                    "REVOKE ALL ON DATABASE store_prod FROM ecommerce_app;\n"
                    "GRANT CONNECT ON DATABASE store_prod TO ecommerce_app;\n"
                    "GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO ecommerce_app;\n"
                    "REVOKE DROP, TRUNCATE, ALTER ON ALL TABLES IN SCHEMA public FROM ecommerce_app;"
                ),
                "priority": "high"
            },
            {
                "title": "Deploy ModSecurity / WAF Filter Rules",
                "description": "Filter common SQL injection vectors at the ingress reverse proxy.",
                "code_example": None,
                "configuration": (
                    "# Nginx / ModSecurity Core Rule Set (CRS)\n"
                    "SecRule REQUEST_URI|ARGS|HEADERS \"(?i)(union.*select|drop.*table|insert.*into|exec.*xp_)\" \\\n"
                    "    \"id:10001,phase:2,deny,status:403,log,msg:'SQL Injection detected by Sentinel AI'\""
                ),
                "priority": "medium"
            }
        ]
    },
    "xss": {
        "threat_type": "xss",
        "severity": "critical",
        "explanation": "Cross-Site Scripting (XSS) occurs when malicious JavaScript or executable HTML markup is injected into web pages, allowing attackers to steal session cookies, hijack customer accounts, or deface the store UI.",
        "impact_assessment": {
            "potential_damage": "HIGH - Session cookie theft, DOM hijacking, malicious redirects at checkout",
            "data_at_risk": "Session tokens, admin credentials, payment forms via DOM keystroke loggers",
            "business_impact": "Account takeovers, fraudulent customer redirection, loss of consumer trust"
        },
        "immediate_actions_taken": [
            "Malicious script payload stripped and request rejected with HTTP 400/403",
            "Offending IP address placed on active monitoring watch",
            "Admin alerted to audit stored reviews and comments for persisted script tags"
        ],
        "how_to_fix_now": [
            "1. Scan database for persisted XSS tags in recent product reviews, comments, and profile names.",
            "2. Ensure all session cookies have the 'HttpOnly', 'Secure', and 'SameSite=Lax/Strict' flags set.",
            "3. Invalidate active sessions for any user whose profile input matched the attack signature."
        ],
        "prevention_measures": [
            {
                "title": "Context-Aware HTML Entity Escaping & Sanitization",
                "description": "Always encode untrusted output before rendering in HTML templates, and use DOMPurify on the frontend.",
                "code_example": (
                    "# Python (html.escape / bleach)\n"
                    "import html\n"
                    "safe_customer_comment = html.escape(untrusted_comment)\n\n"
                    "// JavaScript / React\n"
                    "// BAD: <div dangerouslySetInnerHTML={{ __html: userBio }} />\n"
                    "// GOOD: Use default JSX escaping or DOMPurify:\n"
                    "import DOMPurify from 'dompurify';\n"
                    "const cleanHTML = DOMPurify.sanitize(userBio);"
                ),
                "configuration": None,
                "priority": "critical"
            },
            {
                "title": "Enforce Robust Content-Security-Policy (CSP)",
                "description": "Disallow unsafe inline scripts, eval(), and unauthorized external script domains.",
                "code_example": None,
                "configuration": (
                    "# HTTP Response Headers in Nginx / FastAPI\n"
                    "Content-Security-Policy: default-src 'self'; script-src 'self' https://js.stripe.com; object-src 'none'; base-uri 'self';\n"
                    "X-Content-Type-Options: nosniff\n"
                    "X-XSS-Protection: 1; mode=block"
                ),
                "priority": "high"
            }
        ]
    },
    "brute_force": {
        "threat_type": "brute_force",
        "severity": "warning",
        "explanation": "Brute force and credential stuffing attacks systematically attempt thousands of username and password combinations to penetrate customer accounts or admin portals.",
        "impact_assessment": {
            "potential_damage": "HIGH - Unauthorized account takeover, fraudulent checkout using stored cards",
            "data_at_risk": "Customer profiles, stored loyalty credits, admin privileges",
            "business_impact": "Customer churn, chargebacks, customer support overload"
        },
        "immediate_actions_taken": [
            "Login endpoint throttled for source IP (HTTP 429 Too Many Requests)",
            "Targeted username temporarily placed in step-up verification mode",
            "Source IP address added to dynamic firewall jail"
        ],
        "how_to_fix_now": [
            "1. Check if any attempts succeeded: SELECT * FROM login_audit WHERE ip = :source_ip AND status = 'success';",
            "2. If an account was compromised, force immediate password reset and invalidate active tokens.",
            "3. Enforce CAPTCHA requirement on /api/auth/login after 3 failed attempts."
        ],
        "prevention_measures": [
            {
                "title": "Implement Exponential Backoff & Rate Limiting",
                "description": "Rate limit login endpoints using Redis sliding window counters per IP and per username.",
                "code_example": (
                    "# Python FastAPI Rate Limiting with Redis\n"
                    "async def verify_login_velocity(ip: str, email: str, redis_client):\n"
                    "    key = f'login_fail:{ip}:{email}'\n"
                    "    attempts = await redis_client.incr(key)\n"
                    "    if attempts == 1:\n"
                    "        await redis_client.expire(key, 300) # 5 min window\n"
                    "    if attempts > 5:\n"
                    "        raise HTTPException(status_code=429, detail='Too many attempts. Account locked temporarily.')"
                ),
                "configuration": (
                    "# Nginx Rate Limiting Directive\n"
                    "limit_req_zone $binary_remote_addr zone=login_limit:10m rate=5r/m;\n"
                    "location /api/auth/login {\n"
                    "    limit_req zone=login_limit burst=3 nodelay;\n"
                    "}"
                ),
                "priority": "critical"
            },
            {
                "title": "Mandate Multi-Factor Authentication (MFA/2FA)",
                "description": "Require TOTP (Google Authenticator) or WebAuthn for all administrative and merchant accounts.",
                "code_example": None,
                "configuration": "Settings -> Security -> Enforce 2FA for Staff Roles = Enabled",
                "priority": "high"
            }
        ]
    },
    "ddos": {
        "threat_type": "ddos",
        "severity": "critical",
        "explanation": "Distributed Denial of Service (DDoS) floods the e-commerce store with anomalous volumetric request bursts or slow HTTP connections, starving legitimate shoppers of resources.",
        "impact_assessment": {
            "potential_damage": "CRITICAL - Complete storefront downtime during peak shopping hours",
            "data_at_risk": "Operational availability, live transaction completions",
            "business_impact": "Direct revenue loss ($10k-$100k+/hr), abandoned shopping carts, SEO penalties"
        },
        "immediate_actions_taken": [
            "Aggressive rate-limit throttling engaged at Sentinel AI gateway",
            "Offending CIDR subnet blocked at edge firewall filter",
            "Slowloris connection timeouts shortened to 5 seconds"
        ],
        "how_to_fix_now": [
            "1. Activate edge DDoS shield (Cloudflare / AWS Shield Under Attack mode).",
            "2. Drop connections from the anomalous source ASN / IP range at the OS iptables level: iptables -I INPUT -s :source_ip -j DROP",
            "3. Scale up backend replica pods to absorb remaining legitimate traffic."
        ],
        "prevention_measures": [
            {
                "title": "Configure Reverse Proxy Buffering & Timeouts",
                "description": "Mitigate slow HTTP body attacks and slowloris by enforcing aggressive client read timeouts.",
                "code_example": None,
                "configuration": (
                    "# Nginx Anti-DDoS & Slowloris Mitigation\n"
                    "client_body_timeout 5s;\n"
                    "client_header_timeout 5s;\n"
                    "keepalive_timeout 15s;\n"
                    "send_timeout 5s;\n"
                    "limit_conn_zone $binary_remote_addr zone=addr:10m;\n"
                    "limit_conn addr 20;"
                ),
                "priority": "high"
            }
        ]
    },
    "malware_upload": {
        "threat_type": "malware_upload",
        "severity": "emergency",
        "explanation": "Malicious file upload attempt detected. An attacker attempted to upload an executable, web shell (.php, .phtml, .sh, .exe), or polyglot file disguised as an image into product reviews or profile avatars.",
        "impact_assessment": {
            "potential_damage": "EMERGENCY - Remote Code Execution (RCE), full server compromise",
            "data_at_risk": "All server files, environment variables, database credentials, underlying host OS",
            "business_impact": "Total operational compromise, ransomware infection, host hijacking"
        },
        "immediate_actions_taken": [
            "Uploaded file payload intercepted and quarantined in isolated sandbox",
            "Permanent execution permissions stripped; file deleted from staging buffer",
            "Uploader IP permanently banned; security incident escalated to EMERGENCY level"
        ],
        "how_to_fix_now": [
            "1. Confirm no malicious files exist in the media directory: find /var/www/uploads/ -type f -name '*.php*' -delete",
            "2. Ensure the upload directory has no execution permissions (noexec mount).",
            "3. Verify file storage is isolated on Amazon S3 / Google Cloud Storage rather than local disk."
        ],
        "prevention_measures": [
            {
                "title": "Validate Magic Bytes & Re-encode Images",
                "description": "Never trust client-supplied Content-Type or file extensions. Inspect byte headers and re-encode with Pillow.",
                "code_example": (
                    "from PIL import Image\n"
                    "import io\n\n"
                    "def sanitize_and_save_image(file_bytes: bytes, dest_path: str):\n"
                    "    # Verify and re-encode to strip EXIF / embedded shells\n"
                    "    image = Image.open(io.BytesIO(file_bytes))\n"
                    "    if image.format not in ['JPEG', 'PNG', 'WEBP']:\n"
                    "        raise ValueError('Unsupported or malicious image format')\n"
                    "    image.save(dest_path, format=image.format)"
                ),
                "configuration": (
                    "# Nginx - Disable script execution in uploads directory\n"
                    "location /media/uploads/ {\n"
                    "    types { }\n"
                    "    default_type application/octet-stream;\n"
                    "    location ~ \\.(php|phtml|sh|py|pl|cgi)$ {\n"
                    "        deny all;\n"
                    "    }\n"
                    "}"
                ),
                "priority": "critical"
            }
        ]
    },
    "session_hijacking": {
        "threat_type": "session_hijacking",
        "severity": "critical",
        "explanation": "Session hijacking or anomalous token replay detected. A customer session token was suddenly presented from a disparate IP address, different country, or altered browser fingerprint.",
        "impact_assessment": {
            "potential_damage": "CRITICAL - Attacker browsing as authenticated user, unauthorized purchases",
            "data_at_risk": "Customer order history, shipping addresses, saved payment methods",
            "business_impact": "Fraudulent purchases, consumer identity theft, chargeback disputes"
        },
        "immediate_actions_taken": [
            "Compromised session token instantly invalidated in Redis store",
            "User forced to re-authenticate with step-up MFA challenge",
            "Security advisory sent to customer email on record"
        ],
        "how_to_fix_now": [
            "1. Invalidate all active JWTs/sessions for the affected user: redis-cli DEL session:{session_id}",
            "2. Prompt user to reset password and review recent orders.",
            "3. Verify TLS 1.3 configuration to prevent Man-in-the-Middle (MitM) session snooping."
        ],
        "prevention_measures": [
            {
                "title": "Bind Sessions to IP Subnet & Device Fingerprint",
                "description": "Store hashed user-agent and IP prefix in the session payload; reject requests when fingerprint drifts.",
                "code_example": (
                    "import hashlib\n\n"
                    "def generate_session_fingerprint(req) -> str:\n"
                    "    ua = req.headers.get('user-agent', '')\n"
                    "    client_ip = req.client.host.split('.')[0] # Class A/B subnet\n"
                    "    return hashlib.sha256(f'{ua}:{client_ip}'.encode()).hexdigest()\n\n"
                    "def validate_session(session_data, current_req):\n"
                    "    if session_data['fingerprint'] != generate_session_fingerprint(current_req):\n"
                    "        raise HTTPException(status_code=401, detail='Session fingerprint anomaly detected.')"
                ),
                "configuration": None,
                "priority": "high"
            }
        ]
    },
    "api_abuse": {
        "threat_type": "api_abuse",
        "severity": "warning",
        "explanation": "API abuse or unauthorized parameter tampering detected. Requests attempted to access restricted administrative routes, modify unmodifiable payload fields (e.g. price/role tampering), or exceed rate limits.",
        "impact_assessment": {
            "potential_damage": "HIGH - Negative price orders, privilege escalation to admin, API denial",
            "data_at_risk": "Store pricing rules, administrative endpoints, sensitive user records",
            "business_impact": "Financial loss through manipulated order totals, inventory discrepancies"
        },
        "immediate_actions_taken": [
            "Manipulated order rejected before payment gateway authorization",
            "Endpoint rate limit triggered; API key quarantined",
            "Incident logged for merchant inspection"
        ],
        "how_to_fix_now": [
            "1. Audit order records for zero-dollar or negative-value line items: SELECT * FROM orders WHERE total <= 0;",
            "2. Ensure server-side price validation recalculates totals from database product records, never trusting client payload.",
            "3. Restrict administrative API paths (/api/v1/admin/*) to internal VPN IPs."
        ],
        "prevention_measures": [
            {
                "title": "Strict Server-Side Price & Quantity Validation",
                "description": "Always retrieve canonical prices from the database; never accept client-provided unit prices.",
                "code_example": (
                    "# Python FastAPI server-side checkout validation\n"
                    "@app.post('/api/checkout')\n"
                    "async def checkout(cart_items: List[CartItem], db: Session):\n"
                    "    real_total = 0\n"
                    "    for item in cart_items:\n"
                    "        product = db.query(Product).filter(Product.id == item.product_id).first()\n"
                    "        if not product or item.quantity <= 0:\n"
                    "            raise HTTPException(status_code=400, detail='Invalid cart item')\n"
                    "        real_total += product.price * item.quantity\n"
                    "    # Charge real_total, ignoring any client-sent price\n"
                    "    return await charge_payment(real_total)"
                ),
                "configuration": None,
                "priority": "critical"
            }
        ]
    },
    "bot_attack": {
        "threat_type": "bot_attack",
        "severity": "warning",
        "explanation": "Automated bot scraping, inventory hoarding, or fake account creation detected. Unnatural browsing speed, missing browser headers, or headless browser automation signatures identified.",
        "impact_assessment": {
            "potential_damage": "MEDIUM-HIGH - Stolen product pricing/inventory data, cart checkout hoarding",
            "data_at_risk": "Competitive pricing data, real inventory availability for legitimate shoppers",
            "business_impact": "Lost sales due to fake 'out-of-stock' states caused by hoarders, high cloud compute bills"
        },
        "immediate_actions_taken": [
            "Bot session challenged with silent Proof-of-Work / CAPTCHA",
            "Temporary reservation carts held by bot automatically flushed",
            "Scraping IP rate-limited to 1 request per 10 seconds"
        ],
        "how_to_fix_now": [
            "1. Release abandoned shopping carts created in the last 15 minutes by bot IP.",
            "2. Enforce bot management rules via Cloudflare Turnstile or reCAPTCHA v3 on /checkout and /cart.",
            "3. Add honey-pot fields to checkout and registration forms that only bots fill."
        ],
        "prevention_measures": [
            {
                "title": "Implement Honeypot Form Fields & Header Inspection",
                "description": "Reject submissions where hidden honeypot fields are filled or standard browser headers are missing.",
                "code_example": (
                    "def verify_request_authenticity(headers, form_data):\n"
                    "    # Check for hidden honeypot field\n"
                    "    if form_data.get('website_url_hp'):\n"
                    "        raise HTTPException(status_code=400, detail='Bot activity detected')\n"
                    "    # Check standard browser headers\n"
                    "    if not headers.get('accept-language') or not headers.get('user-agent'):\n"
                    "        raise HTTPException(status_code=403, detail='Automated client rejected')"
                ),
                "configuration": None,
                "priority": "high"
            }
        ]
    },
    "payment_fraud": {
        "threat_type": "payment_fraud",
        "severity": "critical",
        "explanation": "Payment fraud or card testing attack detected. High-velocity card authorization attempts with rapid expiration/CVV alterations or stolen card testing patterns identified.",
        "impact_assessment": {
            "potential_damage": "CRITICAL - Merchant account termination, excessive chargeback fees ($15-$50 per occurrence)",
            "data_at_risk": "Merchant processing gateway standing, customer dispute ratio",
            "business_impact": "Card processor fines, termination of Stripe/Adyen merchant accounts, fraud losses"
        },
        "immediate_actions_taken": [
            "Checkout authorization halted before calling card processor API",
            "Offending IP quarantined across payment checkout gateways",
            "High-risk alert pushed to Store Security Team for merchant review"
        ],
        "how_to_fix_now": [
            "1. Inspect recent orders for card testing patterns (e.g., $1.00 or micro-orders with distinct names).",
            "2. Void any uncaptured authorizations originating from the flagged IP/BIN.",
            "3. Enforce 3D Secure (3DS) mandatory challenge for international and high-risk orders."
        ],
        "prevention_measures": [
            {
                "title": "Enforce Stripe Radar / 3D Secure 2.0 & Velocity Guards",
                "description": "Limit card checkout attempts to 3 per IP/hour and require 3DS authentication for risk scores > 0.6.",
                "code_example": (
                    "# Python Stripe 3DS & Radar Integration\n"
                    "import stripe\n\n"
                    "async def create_secure_payment(amount: int, currency: str, customer_ip: str):\n"
                    "    intent = stripe.PaymentIntent.create(\n"
                    "        amount=amount,\n"
                    "        currency=currency,\n"
                    "        payment_method_options={\n"
                    "            'card': {'request_three_d_secure': 'automatic'}\n"
                    "        },\n"
                    "        metadata={'customer_ip': customer_ip}\n"
                    "    )\n"
                    "    return intent.client_secret"
                ),
                "configuration": None,
                "priority": "critical"
            }
        ]
    },
    "data_exfiltration": {
        "threat_type": "data_exfiltration",
        "severity": "emergency",
        "explanation": "Data exfiltration or bulk database harvesting attempt detected. An anomalous spike in outbound bytes, sequential customer record pagination, or unauthorized export endpoints was intercepted.",
        "impact_assessment": {
            "potential_damage": "EMERGENCY - Mass customer PII leak, store customer list theft",
            "data_at_risk": "Entire customer database, email addresses, order histories, physical addresses",
            "business_impact": "Massive GDPR / CCPA regulatory fines (up to 4% of global turnover), class action lawsuits"
        },
        "immediate_actions_taken": [
            "Outgoing connection terminated; bulk query stream severed",
            "API key and user token permanently revoked",
            "Incident logged to permanent forensic archive; Security Officer notified"
        ],
        "how_to_fix_now": [
            "1. Check egress network logs: verify total bytes transferred during the anomalous session.",
            "2. Immediately cap API pagination limit to maximum 100 records per request.",
            "3. Disable public export endpoints until full code audit is completed."
        ],
        "prevention_measures": [
            {
                "title": "Strict Query Pagination & Egress Rate Limiting",
                "description": "Hard-cap all API list endpoints to prevent unbounded database dumps.",
                "code_example": (
                    "# FastAPI safe pagination enforcement\n"
                    "@app.get('/api/orders')\n"
                    "def list_orders(limit: int = 50, offset: int = 0):\n"
                    "    # Enforce safe ceiling\n"
                    "    safe_limit = min(max(1, limit), 100)\n"
                    "    return db.query(Order).offset(offset).limit(safe_limit).all()"
                ),
                "configuration": (
                    "# Outbound Data Transfer Monitoring\n"
                    "# Alert when a single API session exceeds 5MB of response payload in 1 minute\n"
                    "MAX_EGRESS_MB_PER_MINUTE = 5"
                ),
                "priority": "critical"
            }
        ]
    },
    "behavioral_anomaly": {
        "threat_type": "behavioral_anomaly",
        "severity": "warning",
        "explanation": "Behavioral Anomaly detected by Machine Learning Isolation Forest model. The request profile deviates significantly from learned e-commerce baselines (unusual time of day, anomalous header structure, or request parameter entropy).",
        "impact_assessment": {
            "potential_damage": "ELEVATED - Potential 0-day probe, unusual automated reconnaissance",
            "data_at_risk": "Application structure, hidden endpoints, unindexed assets",
            "business_impact": "Early warning indicator of a targeted breach attempt before signature-based attacks launch"
        },
        "immediate_actions_taken": [
            "Session flagged for high-resolution logging and continuous risk evaluation",
            "Client presented with low-overhead challenge",
            "Risk score added to cumulative session profile"
        ],
        "how_to_fix_now": [
            "1. Review recent request traces from the anomalous session in Sentinel AI activity inspector.",
            "2. Verify whether client is an unannounced partner or external crawler.",
            "3. Tune baseline model threshold if anomaly is determined to be benign store maintenance."
        ],
        "prevention_measures": [
            {
                "title": "Continuous Model Baseline Retraining",
                "description": "Periodically retrain the Isolation Forest on verified clean store traffic to adapt to seasonality.",
                "code_example": (
                    "# Sentinel AI Baseline Retrainer\n"
                    "from app.ml.isolation_forest import isolation_forest_model\n"
                    "isolation_forest_model.retrain_baseline(clean_traffic_dataframe)"
                ),
                "configuration": "Settings -> Anomaly Threshold = 0.70",
                "priority": "medium"
            }
        ]
    }
}

def get_remediation_guide(threat_type: str) -> RemediationGuide:
    """Retrieve detailed remediation guide for a threat class, with fallback."""
    raw = REMEDIATION_KB.get(threat_type.lower()) or REMEDIATION_KB.get("behavioral_anomaly")
    
    prevention = [
        PreventionMeasure(
            title=p["title"],
            description=p["description"],
            code_example=p.get("code_example"),
            configuration=p.get("configuration"),
            priority=p.get("priority", "high")
        )
        for p in raw["prevention_measures"]
    ]
    
    return RemediationGuide(
        threat_type=raw["threat_type"],
        severity=raw["severity"],
        explanation=raw["explanation"],
        impact_assessment=raw["impact_assessment"],
        immediate_actions_taken=raw["immediate_actions_taken"],
        how_to_fix_now=raw["how_to_fix_now"],
        prevention_measures=prevention
    )
