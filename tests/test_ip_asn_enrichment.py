import tempfile
import unittest
from pathlib import Path

from core.ip_asn_enrichment import OfflineIPASNEnricher, load_ip_asn_enricher


class IPASNEnrichmentTests(unittest.TestCase):
    def test_loads_csv_and_uses_longest_prefix_match(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ip-asn.csv"
            path.write_text(
                "cidr,asn,as_name,rir,source\n"
                "203.0.113.0/24,64512,Example ASN,TEST,lab\n"
                "203.0.113.128/25,64513,Specific ASN,TEST,lab\n",
                encoding="utf-8",
            )

            enricher = load_ip_asn_enricher(str(path))

            match = enricher.lookup("203.0.113.200")
            self.assertEqual(64513, match.asn)
            self.assertEqual("Specific ASN", match.as_name)
            self.assertEqual("AS64513 Specific ASN", match.value)

    def test_loads_jsonl_and_matches_network_values(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ip-asn.jsonl"
            path.write_text(
                '{"prefix":"2001:db8::/32","as_number":"AS64514","name":"IPv6 ASN"}\n',
                encoding="utf-8",
            )

            enricher = load_ip_asn_enricher(str(path))

            match = enricher.lookup("2001:db8:1::/48")
            self.assertEqual(64514, match.asn)
            self.assertEqual("AS64514 IPv6 ASN", match.value)

    def test_returns_none_for_missing_or_invalid_file(self):
        self.assertIsNone(load_ip_asn_enricher(""))
        self.assertIsNone(load_ip_asn_enricher("missing.csv"))
        self.assertIsNone(OfflineIPASNEnricher().lookup("203.0.113.1"))


if __name__ == "__main__":
    unittest.main()
