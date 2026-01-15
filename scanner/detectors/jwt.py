import jwt
from typing import List, Dict
import httpx
import re

async def scan(target: str, client: httpx.AsyncClient) -> List[Dict]:
    """Scan for JWT misconfigurations"""
    vulns = []
    
    # Extract JWTs from common locations
    resp = await client.get(target)
    
    # Look for JWTs in response
    jwt_patterns = r'eyJ[A-Za-z0-9-_]+?\.[A-Za-z0-9-_]*?\.[A-Za-z0-9-_]*'
    jwt_matches = re.findall(jwt_patterns, resp.text)
    
    for jwt_token in jwt_matches:
        issues = await _analyze_jwt(jwt_token)
        vulns.extend(issues)
    
    # Test common JWT attacks
    vulns.extend(await _test_jwt_attacks(target, client))
    
    return vulns

async def _analyze_jwt(token: str) -> List[Dict]:
    """Analyze JWT token for weaknesses"""
    issues = []
    
    try:
        # Test none algorithm
        test_token = token.rsplit('.', 2)
        none_token = '.'.join(test_token[:2] + ['.'])
        
        # Decode without verification (for analysis only)
        header = jwt.get_unverified_header(none_token)
        
        if header.get('alg') == 'none':
            issues.append({
                "type": "JWT_NONE_ALG",
                "severity": "CRITICAL",
                "description": "JWT uses 'none' algorithm - completely insecure",
                "fix": "Never allow 'none' algorithm. Validate JWT signature"
            })
        
        if header.get('alg') in ['HS256', 'HS384', 'HS512']:
            issues.append({
                "type": "JWT_WEAK_ALG",
                "severity": "HIGH",
                "description": f"JWT uses symmetric algorithm ({header['alg']}) - vulnerable to secret extraction",
                "fix": "Use asymmetric algorithms (RS256, ES256) with proper key management"
            })
            
    except:
        pass
    
    return issues

async def _test_jwt_attacks(target: str, client: httpx.AsyncClient) -> List[Dict]:
    """Test common JWT attacks"""
    vulns = []
    
    attack_vectors = [
        {"alg": "none", "severity": "CRITICAL", "name": "None Algorithm"},
        {"kid": "../etc/passwd", "severity": "HIGH", "name": "Path Traversal KID"},
        {"kid": "' OR 1=1--", "severity": "MEDIUM", "name": "SQL Injection KID"}
    ]
    
    for attack in attack_vectors:
        # This would test JWT header manipulation
        # Implementation depends on discovering actual JWT endpoints
        pass
    
    return vulns