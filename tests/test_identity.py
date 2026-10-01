import unittest
from unittest.mock import patch

from omada_wg.identity import client_name, normalize_client_name


class IdentityTests(unittest.TestCase):
    def test_windows_computer_and_user_become_omada_name(self):
        with patch("omada_wg.identity.socket.gethostname", return_value="DESKTOP-REALLFUCKINGAY354"), \
             patch("omada_wg.identity.getpass.getuser", return_value="ben"), \
             patch.dict("omada_wg.identity.os.environ", {"USERDOMAIN": "DESKTOP-REALLFUCKINGAY354"}, clear=True):
            self.assertEqual(client_name("computer_user"), "DESKTOP_REALLFUCKINGAY354_ben")

    def test_domain_is_inserted_between_computer_and_user(self):
        with patch("omada_wg.identity.socket.gethostname", return_value="DESKTOP-ONE"), \
             patch("omada_wg.identity.getpass.getuser", return_value="ben"), \
             patch.dict("omada_wg.identity.os.environ", {"USERDOMAIN": "CONTOSO"}, clear=True):
            self.assertEqual(client_name("computer_user"), "DESKTOP_ONE_CONTOSO_ben")

    def test_backslash_and_repeated_invalid_characters_are_normalized(self):
        self.assertEqual(normalize_client_name(r"DESKTOP-ONE\\ben"), "DESKTOP_ONE_ben")


if __name__ == "__main__":
    unittest.main()
