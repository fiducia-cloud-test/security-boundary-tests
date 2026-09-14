import unittest

from deep_tests.security_model import BoundaryViolation, normalize_relative_path, validate_outbound_url


class SecurityEncodingFollowupTests(unittest.TestCase):
    def test_nested_and_mixed_case_encoded_parent_segments_fail_closed(self):
        for value in (
            "safe/%2e%2e/secret",
            "%2E%2e/%2e%2E/secret",
            "safe/%252e%252e/secret",
            "%2e%2e%2fsecret",
        ):
            with self.assertRaises(BoundaryViolation):
                normalize_relative_path(value)

    def test_url_authority_confusion_matrix_is_rejected(self):
        allowed = {"api.example.test"}
        for value in (
            "https://api.example.test.attacker.invalid/v1",
            "https://api.example.test%40attacker.invalid/v1",
            "https://attacker.invalid/?next=https://api.example.test",
            "//attacker.invalid/api.example.test",
        ):
            with self.assertRaises(BoundaryViolation):
                validate_outbound_url(value, allowed)


if __name__ == "__main__":
    unittest.main()
