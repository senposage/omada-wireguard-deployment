import unittest

from omada_wg.capture_contract import ContractCapture, _cookie_objects


class Request:
    method = "PATCH"
    url = "https://example/omadac/d/openapi/v2/o/sites/s/vpn/client-to-site-vpn-servers/server"
    post_data = '{"clients":[{"name":"codexcontractprobe"}]}'


class CaptureContractTests(unittest.TestCase):
    def test_captures_path_and_json_without_headers(self):
        capture = ContractCapture()
        capture.request(Request())
        self.assertEqual(capture.record["method"], "PATCH")
        self.assertEqual(capture.record["request_body"]["clients"][0]["name"], "codexcontractprobe")
        self.assertNotIn("headers", capture.record)

    def test_ignores_vpn_default_value_background_request(self):
        capture = ContractCapture()
        request = Request()
        request.url = "https://example/openapi/v1/o/sites/s/vpn/defaultValue"
        capture.request(request)
        self.assertIsNone(capture.record)

    def test_cookie_header_becomes_parent_domain_cookies(self):
        cookies = _cookie_objects("A=1; B=two=parts")
        self.assertEqual(cookies[1]["value"], "two=parts")
        self.assertTrue(all(x["domain"] == ".tplinkcloud.com" for x in cookies))


if __name__ == "__main__":
    unittest.main()
