from openai import AsyncOpenAI
from typing import Dict, Any, List
import json
import os

class AIAnalyzer:
    def __init__(self):
        self.client = AsyncOpenAI(api_key=os.getenv("OPENAI_API_KEY"))
        self.model = "gpt-4o-mini"
    
    async def analyze(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """AI-powered vulnerability analysis and explanation"""
        
        prompt = self._build_analysis_prompt(scan_results)
        
        try:
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.1
            )
            
            analysis = json.loads(response.choices[0].message.content)
            
            # Enhance results with AI analysis
            enhanced_results = scan_results.copy()
            enhanced_results["ai_analysis"] = analysis
            enhanced_results["severity_score"] = self._calculate_ai_severity(analysis)
            enhanced_results["human_readable_explanation"] = analysis.get("explanation", "")
            
            return enhanced_results
            
        except Exception as e:
            # Fallback to rule-based analysis
            return self._rule_based_analysis(scan_results)
    
    def _build_analysis_prompt(self, results: Dict[str, Any]) -> str:
        """Build comprehensive prompt for AI analysis"""
        vulns_summary = "\n".join([
            f"- {v['type']}: {v['description'][:100]}..." 
            for v in results["vulnerabilities"][:10]
        ])
        
        return f"""
You are a senior security engineer analyzing automated scan results.

Scan Results:
Target: {results['target']}
Vulnerabilities found: {len(results['vulnerabilities'])}
Summary: {json.dumps(results['summary'], indent=2)}

Top vulnerabilities:
{vulns_summary}

Security Headers Score: {results['security_headers'].get('overall_score', 0):.2f}

Provide JSON analysis with:
{{
  "risk_assessment": "CRITICAL|HIGH|MEDIUM|LOW",
  "explanation": "2-3 sentences explaining overall risk",
  "prioritized_fixes": ["Fix 1", "Fix 2", "Fix 3"],
  "attack_scenario": "Real-world attack path description",
  "business_impact": "What could happen if exploited"
}}

Focus on:
1. Real exploitability (not just theoretical)
2. Business impact 
3. Prioritized remediation steps
4. Attack narrative for non-technical stakeholders
"""

    def _calculate_ai_severity(self, analysis: Dict) -> Dict:
        """Calculate severity using AI insights"""
        severity_weights = {
            "CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 2
        }
        return severity_weights.get(analysis.get("risk_assessment", "LOW"), 1)
    
    def _rule_based_analysis(self, results: Dict) -> Dict:
        """Fallback analysis without AI"""
        return {
            **results,
            "ai_analysis": {
                "risk_assessment": results["summary"]["risk_level"],
                "explanation": "Automated scan completed. Review findings for security issues.",
                "prioritized_fixes": ["Review all HIGH/CRITICAL findings", "Implement fixes", "Rescan"]
            }
        }