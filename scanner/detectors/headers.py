SECURITY_HEADERS = {
    "Strict-Transport-Security": {"required": True, "min_age": 31536000},
    "X-Frame-Options": {"required": True},
    "X-Content-Type-Options": {"required": True, "value": "nosniff"},
    "Referrer-Policy": {"required": True},
    "Content-Security-Policy": {"required": False},  # Recommended but not always present
    "Permissions-Policy": {"required": False},
    "X-XSS-Protection": {"required": False}  # Legacy
}

def analyze(headers: dict) -> dict:
    """Analyze security headers"""
    issues = []
    header_status = {}
    
    for header_name, config in SECURITY_HEADERS.items():
        present = header_name.lower() in {k.lower(): k for k in headers.keys()}
        header_status[header_name] = {"present": present}
        
        if not present and config["required"]:
            issues.append({
                "type": "MISSING_SECURITY_HEADER",
                "severity": "MEDIUM",
                "description": f"Missing required security header: {header_name}",
                "header": header_name,
                "fix": f"Add {header_name} header with appropriate value"
            })
        elif present:
            actual_header = next(k for k in headers.keys() if k.lower() == header_name.lower())
            value = headers[actual_header]
            header_status[header_name]["value"] = value
            
            # Check specific value requirements
            if "value" in config and config["value"] not in value:
                issues.append({
                    "type": "INCORRECT_HEADER_VALUE",
                    "severity": "LOW",
                    "description": f"Security header {header_name} has incorrect value",
                    "expected": config["value"],
                    "actual": value,
                    "fix": f"Set {header_name}: {config['value']}"
                })
    
    return {
        "overall_score": len([h for h in header_status.values() if h["present"]]) / len(SECURITY_HEADERS),
        "issues": issues,
        "headers_present": sum(1 for h in header_status.values() if h["present"])
    }