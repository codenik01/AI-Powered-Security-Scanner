import httpx
from playwright.async_api import async_playwright
from typing import Dict, List, Any, Optional
import asyncio
from urllib.parse import urljoin, urlparse
import re
from datetime import datetime
from scanner.detectors import idor_detector, auth_detector, headers_detector, jwt_detector

class SecurityScanner:
    def __init__(self, target: str):
        self.target = target
        self.base_domain = urlparse(target).netloc
        self.results: Dict[str, Any] = {
            "scan_date": datetime.utcnow().isoformat(),
            "target": target,
            "vulnerabilities": [],
            "summary": {},
            "security_headers": {},
            "endpoints": []
        }
        self.client = httpx.AsyncClient(
            timeout=30.0,
            follow_redirects=True,
            limits=httpx.Limits(max_keepalive_connections=10, max_connections=50)
        )
    
    async def scan_full(self, scan_type: str = "full", max_depth: int = 3, auth_token: Optional[str] = None) -> Dict:
        """Full security scan"""
        tasks = [
            self._scan_security_headers(),
            self._scan_auth_bypass(auth_token),
            self._crawl_and_scan(max_depth),
            self._scan_jwt_tokens()
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process IDOR detection on discovered endpoints
        await self._scan_idor_on_endpoints()
        
        self._calculate_summary()
        return self.results
    
    async def _scan_security_headers(self):
        """Check security headers"""
        try:
            resp = await self.client.get(self.target)
            headers_result = headers_detector.analyze(resp.headers)
            self.results["security_headers"] = headers_result
            self.results["vulnerabilities"].extend(headers_result["issues"])
        except Exception as e:
            self.results["vulnerabilities"].append({
                "type": "NETWORK_ERROR",
                "severity": "INFO",
                "description": f"Could not reach target: {str(e)}"
            })
    
    async def _scan_auth_bypass(self, auth_token: Optional[str] = None):
        """Test authentication bypass"""
        auth_results = await auth_detector.scan(self.target, self.client, auth_token)
        self.results["vulnerabilities"].extend(auth_results)
    
    async def _crawl_and_scan(self, max_depth: int):
        """Crawl and discover endpoints"""
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            )
            page = await context.new_page()
            
            await page.goto(self.target, wait_until="networkidle")
            
            # Extract endpoints from page
            endpoints = await self._extract_endpoints(page)
            self.results["endpoints"] = endpoints
            
            await browser.close()
    
    async def _extract_endpoints(self, page) -> List[str]:
        """Extract API endpoints from JavaScript/network requests"""
        endpoints = set()
        
        # Listen for network requests
        async def handle_request(route, request):
            url = request.url
            if self.base_domain in url:
                endpoints.add(url)
        
        page.on("request", handle_request)
        await page.wait_for_timeout(5000)  # Let requests complete
        
        return list(endpoints)
    
    async def _scan_idor_on_endpoints(self):
        """Scan discovered endpoints for IDOR"""
        for endpoint in self.results["endpoints"]:
            idor_results = await idor_detector.scan_endpoint(endpoint, self.client)
            self.results["vulnerabilities"].extend(idor_results)
    
    async def _scan_jwt_tokens(self):
        """Detect JWT misconfigurations"""
        jwt_results = await jwt_detector.scan(self.target, self.client)
        self.results["vulnerabilities"].extend(jwt_results)
    
    async def analyze_raw_request(self, raw_req: Dict) -> Dict:
        """Analyze raw HTTP request"""
        results = []
        
        # Test for IDOR patterns in raw request
        if "id=" in raw_req.get("url", "").lower():
            idor_test = await idor_detector.test_raw_request(raw_req)
            results.extend(idor_test)
        
        return {"vulnerabilities": results}
    
    def _calculate_summary(self):
        """Calculate severity scores and summary"""
        vulns = self.results["vulnerabilities"]
        severity_map = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        
        total_score = sum(severity_map.get(v.get("severity", "INFO"), 0) for v in vulns)
        severity_count = {
            "CRITICAL": sum(1 for v in vulns if v.get("severity") == "CRITICAL"),
            "HIGH": sum(1 for v in vulns if v.get("severity") == "HIGH"),
            "MEDIUM": sum(1 for v in vulns if v.get("severity") == "MEDIUM"),
            "LOW": sum(1 for v in vulns if v.get("severity") == "LOW")
        }
        
        self.results["summary"] = {
            "total_vulnerabilities": len(vulns),
            "severity_score": total_score,
            "risk_level": self._get_risk_level(total_score),
            "by_severity": severity_count
        }
    
    def _get_risk_level(self, score: int) -> str:
        if score >= 10: return "CRITICAL"
        elif score >= 6: return "HIGH"
        elif score >= 3: return "MEDIUM"
        else: return "LOW"
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.client.aclose()