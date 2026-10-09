"""Explainable Zero Trust access-policy evaluator (demo, not a production IdP)."""
from __future__ import annotations

def authorize(request: dict) -> dict:
    if not isinstance(request,dict): raise ValueError("Request must be an object")
    reasons=[]
    for key,label in [("authenticated","Identity is not authenticated"),("mfa","MFA is missing"),("device_compliant","Device posture is not compliant")]:
        if request.get(key) is not True: reasons.append(label)
    roles=request.get("allowed_roles",[])
    if not isinstance(roles,list): raise ValueError("allowed_roles must be a list")
    if not request.get("role") or request["role"] not in roles: reasons.append("Role is not authorized")
    if request.get("resource_sensitivity") not in {"low","medium","high"}: reasons.append("Resource sensitivity must be low, medium, or high")
    if request.get("resource_sensitivity")=="high" and request.get("managed_device") is not True:
        reasons.append("High-sensitivity resource requires a managed device")
    return {"decision":"deny" if reasons else "allow","reasons":reasons}

if __name__=="__main__":
    sample={"authenticated":True,"mfa":True,"device_compliant":True,"managed_device":True,"role":"analyst","allowed_roles":["analyst"],"resource_sensitivity":"high"}
    print(authorize(sample))
