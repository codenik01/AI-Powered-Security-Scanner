import httpx
import re
from typing import Dict, List, Any
from urllib.parse import urlparse, parse_qs, urlencode

async def scan_endpoint(endpoint: str, client: httpx.AsyncClient) -> List[Dict]:
    """Scan single endpoint for IDOR"""
    vulnerabilities = []
    
    # Common IDOR patterns
    id_patterns = [
        r'id=(\d+)',
        r'user_id=(\d+)',
        r'account_id=(\d+)',
        r'order_id=(\d+)',
        r'profile/(\d+)'
    ]
    
    try:
        # Test GET request first
        resp = await client.get(endpoint)
        vulns = await _test_idor_patterns(endpoint, resp.text, client)
        vulnerabilities.extend(vulns)
    except:
        pass
    
    return vulnerabilities

async def test_raw_request(raw_req: Dict) -> List[Dict]:
    """Test IDOR on raw request"""
    vulnerabilities = []
    
    # Check if request contains numeric IDs
    url = raw_req.get("url", "")
    if re.search(r'id=\d+|user_id=\d+', url):
        # Test ID manipulation
        original_resp = await _send_raw_request(raw_req)
        modified_req = _modify_id(raw_req)
        modified_resp = await _send_raw_request(modified_req)
        
        if original_resp.status_code == 200 and modified_resp.status_code == 200:
            vulnerabilities.append({
                "type": "IDOR",
                "severity": "HIGH",
                "description": "IDOR detected - changing ID parameter returns different user data",
                "endpoint": url,
                "evidence": {
                    "original_status": original_resp.status_code,
                    "modified_status": modified_resp.status_code
                },
                "fix": "Implement proper authorization checks for object access"
            })
    
    return vulnerabilities

async def _send_raw_request(req: Dict):
    """Send raw HTTP request"""
    async with httpx.AsyncClient() as client:
        method = req.get("method", "GET")
        if method.upper() == "GET":
            resp = await client.get(req["url"], headers=req.get("headers", {}))
        else:
            resp = await client.post(
                req["url"], 
                headers=req.get("headers", {}),
                content=req.get("body", "")
            )
        return resp

def _modify_id(req: Dict) -> Dict:
    """Modify ID parameter in request (+1)"""
    url = req["url"]
    
    # Replace first numeric ID with ID+1
    def replacer(match):
        num = int(match.group(1))
        return f"{match.group(0)[:-len(str(num))]:<{len(match.group(0))-len(str(num))}}{num+1}"
    
    patterns = [r'id=(\d+)', r'user_id=(\d+)', r'account_id=(\d+)']
    for pattern in patterns:
        url = re.sub(pattern, replacer, url, count=1)
    
    req["url"] = url
    return req

async def _test_idor_patterns(endpoint: str, response_text: str, client: httpx.AsyncClient) -> List[Dict]:
    """Test specific IDOR patterns in response"""
    vulns = []
    
    # Look for IDs in response that might be manipulable
    id_matches = re.findall(r'href="([^"]*id=\d+[^"]*)"', response_text)
    
    for link in id_matches[:3]:  # Test first 3
        full_url = urljoin(endpoint, link)
        vuln = await _test_single_idor(full_url, client)
        if vuln:
            vulns.append(vuln)
    
    return vulns

async def _test_single_idor(url: str, client: httpx.AsyncClient) -> Optional[Dict]:
    """Test single potential IDOR"""
    try:
        # Original request
        resp1 = await client.get(url, allow_redirects=False)
        
        if resp1.status_code != 200:
            return None
        
        # Modify ID (+1)
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        
        id_found = False
        for param in query:
            if param in ['id', 'user_id', 'account_id']:
                ids = query[param]
                if ids and ids[0].isdigit():
                    new_id = str(int(ids[0]) + 1)
                    query[param] = [new_id]
                    id_found = True
                    break
        
        if not id_found:
            return None
        
        new_query = urlencode(query, doseq=True)
        new_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
        
        resp2 = await client.get(new_url, allow_redirects=False)
        
        # IDOR if both requests succeed with different content
        if (resp2.status_code == 200 and 
            resp1.text != resp2.text and 
            len(resp1.text) > 100 and len(resp2.text) > 100):
            
            return {
                "type": "IDOR",
                "severity": "HIGH",
                "description": "Insecure Direct Object Reference - user can access other users' data by modifying ID parameter",
                "endpoint": url,
                "proof_of_concept": {
                    "original": url,
                    "modified": new_url,
                    "original_status": resp1.status_code,
                    "modified_status": resp2.status_code
                },
                "fix_recommendations": [
                    "Implement proper object-level authorization checks",
                    "Use indirect references (UUIDs, hashes) instead of sequential IDs",
                    "Validate user ownership before serving object data"
                ]
            }
    except:
        pass
    
    return None