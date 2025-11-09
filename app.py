from flask import Flask, request, jsonify
import re
from urllib.parse import urlparse

app = Flask(__name__)

# Database Python mein hi define
PHISHING_DB = {
    "immediate_blacklist": {
        "known_phishing_domains": [
            "paypal-security-center.com", "facebook-login-secure.net", 
            "apple-id-verification.org", "microsoft-account-update.com",
            "amazon-payment-verification.co", "netflix-billing-update.xyz",
            "whatsapp-web-login.com", "instagram-verify-account.net",
            "bankofamerica-securelogin.com", "wellsfargo-online-banking.org",
            "secure-paypal-login.xyz", "fb-account-recovery.com",
            "apple-support-center.net", "msn-security-update.com",
            "amazon-prime-renewal.org", "netflix-payment-failed.com"
        ]
    },
    "suspicious_patterns": {
        "typosquatting_keywords": [
            "paypall", "facebok", "micorsoft", "amazoon", "netfliks",
            "whatsappp", "instagarm", "gooogle", "twittter", "linkdedin",
            "appple", "bankofamerrica", "wellsfargo", "chasee"
        ],
        "phishing_keywords": [
            "verify", "secure", "login", "account", "update", "security",
            "confirm", "validation", "authentication", "billing",
            "payment", "urgent", "immediate", "action-required",
            "suspended", "limited", "verification", "reactivate"
        ],
        "suspicious_tlds": [".tk", ".ml", ".ga", ".cf", ".xyz", ".top", ".club"]
    },
    "brand_protection": {
        "legitimate_domains": [
            "paypal.com", "facebook.com", "apple.com", "microsoft.com",
            "amazon.com", "netflix.com", "whatsapp.com", "instagram.com",
            "google.com", "twitter.com", "linkedin.com", "chase.com",
            "bankofamerica.com", "wellsfargo.com"
        ]
    },
    "whitelist": {
        "trusted_domains": [
            "paypal.com", "www.paypal.com", "facebook.com", "www.facebook.com",
            "apple.com", "www.apple.com", "microsoft.com", "www.microsoft.com",
            "amazon.com", "www.amazon.com", "netflix.com", "www.netflix.com",
            "whatsapp.com", "web.whatsapp.com", "instagram.com", "www.instagram.com",
            "google.com", "www.google.com", "twitter.com", "www.twitter.com"
        ]
    },
    "scoring_system": {
        "high_risk_threshold": 7,
        "medium_risk_threshold": 4,
        "risk_scores": {
            "known_phishing_domain": 10,
            "suspicious_tld": 3,
            "typosquatting": 4,
            "phishing_keyword": 2,
            "brand_impersonation": 5
        }
    }
}

def calculate_risk_score(url):
    """
    URL ka comprehensive risk score calculate karta hai
    """
    risk_score = 0
    detected_threats = []
    
    # 1. Whitelist check - agar safe hai toh immediately return karo
    for safe_domain in PHISHING_DB["whitelist"]["trusted_domains"]:
        if safe_domain in url:
            return 0, ["Trusted domain"]
    
    # 2. Immediate blacklist check
    for domain in PHISHING_DB["immediate_blacklist"]["known_phishing_domains"]:
        if domain in url:
            risk_score += PHISHING_DB["scoring_system"]["risk_scores"]["known_phishing_domain"]
            detected_threats.append(f"Known phishing domain: {domain}")
    
    # 3. Typosquatting detection
    for typo in PHISHING_DB["suspicious_patterns"]["typosquatting_keywords"]:
        if typo in url.lower():
            risk_score += PHISHING_DB["scoring_system"]["risk_scores"]["typosquatting"]
            detected_threats.append(f"Typosquatting detected: {typo}")
    
    # 4. Phishing keywords
    for keyword in PHISHING_DB["suspicious_patterns"]["phishing_keywords"]:
        if re.search(r'\b' + re.escape(keyword) + r'\b', url.lower()):
            risk_score += PHISHING_DB["scoring_system"]["risk_scores"]["phishing_keyword"]
            detected_threats.append(f"Suspicious keyword: {keyword}")
    
    # 5. Suspicious TLDs
    parsed_url = urlparse(url)
    domain = parsed_url.netloc or parsed_url.path
    for tld in PHISHING_DB["suspicious_patterns"]["suspicious_tlds"]:
        if domain.endswith(tld):
            risk_score += PHISHING_DB["scoring_system"]["risk_scores"]["suspicious_tld"]
            detected_threats.append(f"Suspicious TLD: {tld}")
    
    # 6. Brand impersonation
    for legit_domain in PHISHING_DB["brand_protection"]["legitimate_domains"]:
        brand_name = legit_domain.split('.')[0]
        if brand_name in url and legit_domain not in url:
            risk_score += PHISHING_DB["scoring_system"]["risk_scores"]["brand_impersonation"]
            detected_threats.append(f"Brand impersonation: {brand_name}")
    
    return risk_score, detected_threats

def get_risk_level(score):
    """Risk score ko category mein convert karo"""
    if score >= PHISHING_DB["scoring_system"]["high_risk_threshold"]:
        return "HIGH_RISK"
    elif score >= PHISHING_DB["scoring_system"]["medium_risk_threshold"]:
        return "MEDIUM_RISK"
    else:
        return "LOW_RISK"

@app.route('/analyze-url', methods=['POST'])
def analyze_url():
    """
    Smart URL analysis endpoint
    """
    data = request.get_json()
    url = data.get('url', '').lower()
    
    if not url:
        return jsonify({"error": "URL parameter required"}), 400
    
    # Risk score calculate karo
    risk_score, threats = calculate_risk_score(url)
    risk_level = get_risk_level(risk_score)
    
    # Detailed analysis provide karo
    analysis_result = {
        "url_analyzed": url,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "threats_detected": threats,
        "total_threats": len(threats),
        "recommendation": "BLOCK" if risk_level == "HIGH_RISK" else "CAUTION" if risk_level == "MEDIUM_RISK" else "SAFE"
    }
    
    return jsonify(analysis_result)

@app.route('/checkurl', methods=['GET'])
def check_url_get():
    """
    Direct browser URL se check karne ka endpoint
    Example: https://yoursite.com/checkurl?url=paypal-security-center.com
    """
    url = request.args.get('url', '').lower()
    
    if not url:
        return jsonify({"error": "URL parameter missing. Use: /checkurl?url=your-url-here"}), 400
    
    # Risk score calculate karo
    risk_score, threats = calculate_risk_score(url)
    risk_level = get_risk_level(risk_score)
    
    # Analysis result
    analysis_result = {
        "url_analyzed": url,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "threats_detected": threats,
        "total_threats": len(threats),
        "recommendation": "BLOCK" if risk_level == "HIGH_RISK" else "CAUTION" if risk_level == "MEDIUM_RISK" else "SAFE"
    }
    
    return jsonify(analysis_result)

@app.route('/bulk-analyze', methods=['POST'])
def bulk_analyze():
    """
    Multiple URLs ko ek saath analyze karo
    """
    data = request.get_json()
    urls = data.get('urls', [])
    
    if not urls:
        return jsonify({"error": "URLs array required"}), 400
    
    results = []
    for url in urls:
        risk_score, threats = calculate_risk_score(url.lower())
        risk_level = get_risk_level(risk_score)
        
        results.append({
            "url": url,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "threats_detected": threats,
            "total_threats": len(threats)
        })
    
    return jsonify({"analysis_results": results})

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({"status": "healthy", "service": "Smart Phishing Detection API"})

@app.route('/')
def home():
    """Home endpoint with usage instructions"""
    return jsonify({
        "message": "Phishing Detection API is running!",
        "endpoints": {
            "POST /analyze-url": "Analyze single URL (JSON body)",
            "GET /checkurl?url=YOUR_URL": "Analyze URL via browser",
            "POST /bulk-analyze": "Analyze multiple URLs",
            "GET /health": "Health check"
        },
        "example": "https://your-domain.com/checkurl?url=paypal-security-center.com"
    })

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)
