import unittest

from omada_wg.capture_login import LoginCapture


class Request:
    method = "POST"
    url = "https://account.tplinkcloud.com/api/login"
    post_data = '{"username":"admin","password":"secret"}'
    headers = {"content-type": "application/json"}


class LoginCaptureTests(unittest.TestCase):
    def test_detects_login_without_recording_headers(self):
        capture = LoginCapture()
        capture.request(Request())
        record = capture.candidates[Request.url]
        self.assertEqual(record["host"], "account.tplinkcloud.com")
        self.assertEqual(record["request_body"]["username"], "admin")
        self.assertNotIn("headers", record)


if __name__ == "__main__":
    unittest.main()
