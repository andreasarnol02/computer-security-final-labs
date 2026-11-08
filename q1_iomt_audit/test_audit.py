"""Uji unit untuk audit_iomt: pagar lingkup dan klasifikasi risiko (fungsi murni)."""
import contextlib
import io
import unittest
from unittest import mock

import audit_iomt as a


class TestScopeGuard(unittest.TestCase):
    def test_denied_without_authorized(self):
        self.assertIn("--authorized", a.check_scope("127.0.10.0/28", False))

    def test_loopback_and_rfc1918_accepted(self):
        for cidr in ("127.0.10.0/28", "127.0.0.0/24", "10.1.2.0/24",
                     "172.16.5.0/24", "172.31.255.0/24", "192.168.1.0/25"):
            with self.subTest(cidr=cidr):
                self.assertIsNone(a.check_scope(cidr, True))

    def test_public_networks_denied(self):
        # 172.32.0.0 tepat di luar 172.16.0.0/12; 100.64.0.0/10 (RFC 6598) bukan RFC 1918.
        for cidr in ("8.8.8.0/24", "172.32.0.0/24", "192.0.2.0/24",
                     "169.254.1.0/24", "100.64.0.0/24"):
            with self.subTest(cidr=cidr):
                self.assertIn("not loopback", a.check_scope(cidr, True))

    def test_prefix_shorter_than_24_denied(self):
        for cidr in ("10.0.0.0/8", "127.0.0.0/8", "192.168.0.0/16",
                     "172.16.0.0/12", "127.0.10.0/23"):
            with self.subTest(cidr=cidr):
                self.assertIn("/24", a.check_scope(cidr, True))

    def test_invalid_input_denied(self):
        for cidr in ("not-a-cidr", "", "::1/128", "0.0.0.0/0"):
            with self.subTest(cidr=cidr):
                self.assertIsNotNone(a.check_scope(cidr, True))

    def test_main_denies_with_code_2_without_opening_socket(self):
        cases = [["--cidr", "127.0.10.0/28"],
                 ["--cidr", "8.8.8.0/24", "--authorized"],
                 ["--cidr", "10.0.0.0/8", "--authorized"]]
        for argv in cases:
            with self.subTest(argv=argv), \
                 mock.patch("socket.create_connection",
                            side_effect=AssertionError("socket should not be opened")) as sk, \
                 contextlib.redirect_stderr(io.StringIO()) as err:
                self.assertEqual(a.main(argv), 2)
                sk.assert_not_called()
                self.assertIn("DENIED", err.getvalue())


class TestRiskClassification(unittest.TestCase):
    def test_default_credentials_accepted_is_critical(self):
        for service in ("Telnet", "HTTP", "HTTP-alt"):
            with self.subTest(service=service):
                level, _ = a.classify_risk(service, ("admin", "admin"), False)
                self.assertEqual(level, "CRITICAL")

    def test_http_without_authentication_is_critical(self):
        level, finding = a.classify_risk("HTTP", None, True)
        self.assertEqual(level, "CRITICAL")
        self.assertIn("without authentication", finding)

    def test_open_telnet_default_rejected_is_high(self):
        level, _ = a.classify_risk("Telnet", None, False)
        self.assertEqual(level, "HIGH")

    def test_http_without_tls_default_rejected_is_medium(self):
        for service in ("HTTP", "HTTP-alt"):
            with self.subTest(service=service):
                level, _ = a.classify_risk(service, None, False)
                self.assertEqual(level, "MEDIUM")

    def test_https_only_is_info(self):
        level, _ = a.classify_risk("HTTPS", None, False)
        self.assertEqual(level, "INFO")

    def test_credentials_never_shown_verbatim(self):
        _, finding = a.classify_risk("Telnet", ("admin", "1234"), False)
        self.assertIn("admin/***", finding)
        self.assertNotIn("1234", finding)


class TestConstants(unittest.TestCase):
    def test_synthetic_credential_list_has_exactly_three(self):
        self.assertEqual(len(a.CREDS), 3)
        self.assertIn(("admin", "admin"), a.CREDS)
        self.assertIn(("root", "root"), a.CREDS)
        self.assertIn(("admin", "1234"), a.CREDS)

    def test_attempt_limit_per_service(self):
        self.assertEqual(a.MAX_ATTEMPTS_PER_SERVICE, 3)


if __name__ == "__main__":
    unittest.main()
