"""Portable fixed-action contract checks for host lifecycle adapters."""
import unittest

from Deployment.system_operations import (
    RECEIPT_SCHEMA, operation_request, validate_receipt, validate_request,
)


class SystemOperationContractTests(unittest.TestCase):
    def request(self, operation="activate"):
        return operation_request(
            backend="launchd", operation=operation, service="home/nas",
            plan_path="/private/shadow6/launch.json",
            lock_digest="sha256:" + "a" * 64, now=1000, ttl=60,
        )

    def test_fixed_operation_request_is_short_lived_and_has_no_command(self):
        request = self.request("restart")
        self.assertEqual(validate_request(request, now=1030), request)
        self.assertNotIn("argv", request)
        self.assertNotIn("command", request)
        with self.assertRaisesRegex(ValueError, "unsupported system operation"):
            self.request("run-arbitrary-command")
        with self.assertRaisesRegex(ValueError, "lifetime"):
            validate_request({**request, "expiresAt": request["issuedAt"] + 301}, now=1001)

    def test_receipt_cannot_claim_platform_readiness(self):
        request = self.request("activate")
        receipt = {
            "schema": RECEIPT_SCHEMA, "requestId": request["requestId"],
            "operation": request["operation"], "lockDigest": request["lockDigest"],
            "result": "completed", "observedAt": 1010, "readiness": "unknown",
        }
        self.assertEqual(validate_receipt(receipt, request, now=1010), receipt)
        with self.assertRaisesRegex(ValueError, "separately verified"):
            validate_receipt({**receipt, "readiness": "ready"}, request, now=1010)
        with self.assertRaisesRegex(ValueError, "binding mismatch"):
            validate_receipt({**receipt, "lockDigest": "sha256:" + "b" * 64}, request, now=1010)

    def test_aix_src_uses_the_same_fixed_operator_contract(self):
        request = operation_request(backend='aix-src', operation='status',
            service='home/nas', plan_path='/var/lib/shadow6/launch.json',
            lock_digest='sha256:' + 'a' * 64, now=1000)
        self.assertEqual(validate_request(request, now=1001), request)
        self.assertNotIn('command', request)


if __name__ == "__main__":
    unittest.main()
