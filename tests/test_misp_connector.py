import unittest
from types import SimpleNamespace
from unittest.mock import ANY, patch

from connectors.misp.connector import main


class MISPConnectorTests(unittest.TestCase):
    def test_main_runs_once_when_configured(self):
        calls = []
        processor = SimpleNamespace(run_once=lambda: calls.append("run_once"))
        settings = SimpleNamespace(run_once=True)

        with patch("connectors.misp.connector.load_settings", return_value=settings), patch(
            "connectors.misp.connector.build_processor", return_value=processor
        ), patch("connectors.misp.connector.run_processor_loop") as run_loop:
            main()

        self.assertEqual(["run_once"], calls)
        run_loop.assert_not_called()

    def test_main_enters_loop_by_default(self):
        processor = SimpleNamespace(run_once=lambda: self.fail("run_once should not be called"))
        settings = SimpleNamespace(run_once=False)

        with patch("connectors.misp.connector.load_settings", return_value=settings), patch(
            "connectors.misp.connector.build_processor", return_value=processor
        ), patch("connectors.misp.connector.run_processor_loop") as run_loop:
            main()

        run_loop.assert_called_once_with(processor, settings, ANY)


if __name__ == "__main__":
    unittest.main()