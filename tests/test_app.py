import unittest
from app import authorize
BASE={"authenticated":True,"mfa":True,"device_compliant":True,"managed_device":True,"role":"analyst","allowed_roles":["analyst"],"resource_sensitivity":"high"}
class ZeroTrustTests(unittest.TestCase):
 def test_valid_request_allowed(self): self.assertEqual(authorize(BASE)["decision"],"allow")
 def test_missing_mfa_denied(self):
  q={**BASE,"mfa":False}; self.assertEqual(authorize(q)["decision"],"deny")
 def test_wrong_role_denied(self):
  q={**BASE,"role":"guest"}; self.assertIn("Role is not authorized",authorize(q)["reasons"])
 def test_unmanaged_high_sensitivity_denied(self):
  q={**BASE,"managed_device":False}; self.assertEqual(authorize(q)["decision"],"deny")
 def test_invalid_role_list_rejected(self):
  with self.assertRaises(ValueError): authorize({**BASE,"allowed_roles":"analyst"})
if __name__=="__main__": unittest.main()
