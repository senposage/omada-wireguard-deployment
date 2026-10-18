import unittest

from omada_wg.tray import mapping_settle_delay, set_tunnel_running, stop_tunnel_on_tray_exit


class FakeServiceBackend:
    def __init__(self, status="stopped"):
        self.current = status
        self.actions = []

    def status(self, tunnel_name):
        return self.current

    def start(self, tunnel_name):
        self.actions.append(("start", tunnel_name))
        self.current = "running"

    def stop(self, tunnel_name):
        self.actions.append(("stop", tunnel_name))
        self.current = "stopped"


class TrayControlTests(unittest.TestCase):
    def test_mapping_waits_for_the_initial_sign_in_settle_window(self):
        self.assertEqual(mapping_settle_delay(0), 30)
        self.assertEqual(mapping_settle_delay(17), 13)
        self.assertEqual(mapping_settle_delay(45), 5)

    def test_connect_starts_a_stopped_service(self):
        backend = FakeServiceBackend("stopped")
        set_tunnel_running(backend, "omada", True)
        self.assertEqual(backend.actions, [("start", "omada")])
        self.assertEqual(backend.current, "running")

    def test_reconnect_stops_then_starts_a_running_service(self):
        backend = FakeServiceBackend("running")
        set_tunnel_running(backend, "omada", True)
        self.assertEqual(backend.actions, [("stop", "omada"), ("start", "omada")])
        self.assertEqual(backend.current, "running")

    def test_disconnect_stops_a_running_service(self):
        backend = FakeServiceBackend("running")
        set_tunnel_running(backend, "omada", False)
        self.assertEqual(backend.actions, [("stop", "omada")])
        self.assertEqual(backend.current, "stopped")

    def test_exit_stops_a_running_service_before_tray_closes(self):
        backend = FakeServiceBackend("running")
        stop_tunnel_on_tray_exit(backend, "omada")
        self.assertEqual(backend.actions, [("stop", "omada")])
        self.assertEqual(backend.current, "stopped")


if __name__ == "__main__":
    unittest.main()
