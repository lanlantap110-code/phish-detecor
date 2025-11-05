from flask import Flask, request, jsonify
import json
import re
import urllib.parse
from urllib.parse import urlparse

app = Flask(__name__)

# Database load karo
with open('smart_phishing_db.json', 'r') as f:
    db = json.load(f)

def calculate_risk_score(url):
    """
    URL ka comprehensive risk score calculate karta hai
    """
    risk_score = 0
    detected_threats = []
    
    # 1. Immediate blacklist check
    for domain in db['immediate_blacklist']['known_phishing_domains']:
        if domain in url:
            risk_score += db['scoring_system']['risk_scores']['known_phishing_domain']
            detected_threats.append(f"Known phishing domain: {domain}")
    
    for domain in db['immediate_blacklist']['recent_malicious_domains']:
        if domain in url:
            risk_score += db['scoring_system']['risk_scores']['known_phishing_domain']
            detected_threats.append(f"Recent malicious domain: {domain}")
    
    # 2. Whitelist check - agar safe hai toh immediately return karo
    for safe_domain in db['whitelist']['trusted_domains']:
        if safe_domain in url:
            return {
                "risk_score": 0,
                "risk_level": "safe",
                "detected_threats": [],
                "message": "Trusted domain - Safe to proceed"
            }
    
    # 3. Typosquatting detection
    for typo in db['suspicious_patterns']['typosquatting_keywords']:
        if typo in url.lower():
            risk_score += db['scoring_system']['risk_scores']['typosquatting']
            detected_threats.append(f"Typosquatting detected: {typo}")
    
    # 4. Phishing keywords
    for keyword in db['suspicious_patterns']['phishing_keywords']:
        if re.search(r'\b' + re.escape(keyword) + r'\b', url.lower()):
            risk_score += db['scoring_system']['risk_scores']['phishing_keyword']
            detected_threats.append(f"Suspicious keyword: {keyword}")
    
    # 5. Suspicious TLDs
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    for tld in db['suspicious_patterns']['suspicious_tlds']:
        if domain.endswith(tld):
            risk_score += db['scoring_system']['risk_scores']['suspicious_tld']
            detected_threats.append(f"Suspicious TLD: {tld}")
    
    # 6. Brand impersonation
    for brand_pattern in db['brand_protection']['brand_impersonation_patterns']:
        if brand_pattern in url.lower():
            risk_score += db['scoring_system']['risk_scores']['brand_impersonation']
            detected_threats.append(f"Brand impersonation: {brand_pattern}")
    
    # 7. Hex encoding detection
    for hex_pattern in db['technical_indicators']['hex_encoded_urls']:
        if hex_pattern in url:
            risk_score += db['scoring_system']['risk_scores']['hex_encoding']
            detected_threats.append("Hex encoding detected")
    
    # 8. Social engineering phrases (URL parameters mein)
    query_params = parsed_url.query.lower()
    for phrase in db['behavioral_patterns']['social_engineering_phrases']:
        if phrase in query_params:
            risk_score += db['scoring_system']['risk_scores']['social_engineering_phrase']
            detected_threats.append(f"Social engineering: {phrase}")
    
    # 9. Urgency indicators
    for urgent_word in db['behavioral_patterns']['urgency_indicators']:
        if urgent_word in query_params:
            risk_score += db['scoring_system']['risk_scores']['urgency_indicator']
            detected_threats.append(f"Urgency indicator: {urgent_word}")
    
    return risk_score, detected_threats

def get_risk_level(score):
    """Risk score ko category mein convert karo"""
    if score >= db['scoring_system']['high_risk_threshold']:
        return "HIGH_RISK"
    elif score >= db['scoring_system']['medium_risk_threshold']:
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

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)
