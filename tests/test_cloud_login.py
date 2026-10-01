import unittest

from omada_wg.errors import AuthenticationError
from omada_wg.session import CloudCredentialSessionProvider


class CloudLoginTests(unittest.TestCase):
    def test_extracts_session_code_from_identity_fragment(self):
        url = "https://id.tplinkcloud.com/#/login?session_code=ABC123"
        self.assertEqual(CloudCredentialSessionProvider._session_code(url), "ABC123")

    def test_missing_session_code_is_rejected(self):
        with self.assertRaises(AuthenticationError):
            CloudCredentialSessionProvider._session_code("https://id.tplinkcloud.com/#/login")

    def test_unwraps_success_envelope(self):
        self.assertEqual(CloudCredentialSessionProvider._result(
            {"errorCode": 0, "result": {"serviceUrl": "https://example"}})["serviceUrl"],
            "https://example")

    def test_extracts_cloud_portal_oauth_exchange(self):
        url = (
            "https://omada.tplinkcloud.com/redirect/index.html"
            "#/loginRedirect?code=ONE-TIME&state=STATE123"
            "&serviceUrl=https%3A%2F%2Fh2api-id.tplinkcloud.com&canary=false"
        )
        self.assertEqual(CloudCredentialSessionProvider._oauth_code(url), {
            "code": "ONE-TIME",
            "state": "STATE123",
            "uidServiceUrl": "https://h2api-id.tplinkcloud.com",
            "canary": False,
        })

    def test_incomplete_oauth_exchange_is_rejected(self):
        with self.assertRaises(AuthenticationError):
            CloudCredentialSessionProvider._oauth_code(
                "https://omada.tplinkcloud.com/redirect/index.html#/loginRedirect?code=only"
            )


if __name__ == "__main__":
    unittest.main()
