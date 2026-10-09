"""Explainable Zero Trust access-policy demonstration."""
def authorize(request: dict) -> dict:
    reasons = []
    if not request.get("authenticated", False): reasons.append("identity is not authenticated")
    if not request.get("mfa", False): reasons.append("MFA is missing")
    if not request.get("device_compliant", False): reasons.append("device posture is not compliant")
    allowed_roles = request.get("allowed_roles", [])
    if request.get("role") not in allowed_roles: reasons.append("role is not authorized for this resource")
    if request.get("resource_sensitivity") == "high" and not request.get("managed_device", False):
        reasons.append("high-sensitivity resource requires a managed device")
    return {"decision": "deny" if reasons else "allow", "reasons": reasons}

if __name__ == "__main__":
    demo = {"authenticated":True, "mfa":True, "device_compliant":True, "managed_device":True,
            "role":"analyst", "allowed_roles":["analyst"], "resource_sensitivity":"high"}
    print(authorize(demo))