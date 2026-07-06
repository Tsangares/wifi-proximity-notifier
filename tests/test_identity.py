"""Offline tests for the pure-logic device identity-resolution engine.

All tests are fully offline: no network, no subprocess, no randomness, no
datetime-dependent output. identity.py is stdlib-only.
"""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import identity
from identity import (
    CANONICAL_TYPES, OS_VALUES, ENGINE_VERSION,
    is_private_mac, resolve, build_evidence,
)


class TestIsPrivateMac(unittest.TestCase):
    def test_randomized_mac_true(self):
        self.assertTrue(is_private_mac("e2:4a:71:b3:f8:01"))

    def test_real_oui_prefix_false(self):
        self.assertFalse(is_private_mac("a4:83:e7"))

    def test_garbage_input_false(self):
        self.assertFalse(is_private_mac("garbage"))
        self.assertFalse(is_private_mac(""))
        self.assertFalse(is_private_mac(None))

    def test_second_mock_randomized_mac(self):
        # From mock_data.py — Jen's iPad
        self.assertTrue(is_private_mac("e6:9c:22:d1:ab:03"))

    def test_real_vendor_macs_not_private(self):
        for mac in ("a0:36:9f:e4:c7:55", "8c:f5:a3:91:de:47", "3c:2a:f4:5d:01:bb"):
            self.assertFalse(is_private_mac(mac), mac)


class TestMdnsServices(unittest.TestCase):
    def test_iphone_via_companion_link(self):
        evidence = {
            "mac": "e2:4a:71:b3:f8:01",
            "hostname": "Wils-iPhone",
            "mdns_services": [
                {"type": "_companion-link._tcp", "name": "Wil’s iPhone",
                 "hostname": "Wils-iPhone.local", "txt": ""},
                {"type": "_airplay._tcp", "name": "Wil’s iPhone",
                 "hostname": "Wils-iPhone.local", "txt": ""},
            ],
        }
        r = resolve(evidence)
        self.assertEqual(r["device_type"], {"value": "phone", "confidence": 0.9, "source": "mdns_services"})
        self.assertEqual(r["os_guess"]["value"], "iOS")
        self.assertEqual(r["manufacturer"]["value"], "Apple")
        self.assertEqual(r["manufacturer"]["source"], "mdns_services")
        self.assertEqual(r["display_name"]["value"], "Wil’s iPhone")

    def test_ipad_disambiguation_via_name(self):
        evidence = {
            "mac": "e6:9c:22:d1:ab:03",
            "mdns_services": [
                {"type": "_companion-link._tcp", "name": "Jen’s iPad",
                 "hostname": "Jens-iPad.local", "txt": ""},
            ],
        }
        r = resolve(evidence)
        self.assertEqual(r["device_type"]["value"], "tablet")
        self.assertEqual(r["device_type"]["source"], "mdns_services")
        self.assertEqual(r["os_guess"]["value"], "iOS")

    def test_googlecast_is_tv(self):
        evidence = {
            "mac": "00:11:22:33:44:77",
            "mdns_services": [
                {"type": "_googlecast._tcp", "name": "Living Room TV",
                 "hostname": "chromecast.local", "txt": ""},
            ],
        }
        r = resolve(evidence)
        self.assertEqual(r["device_type"]["value"], "tv")
        self.assertEqual(r["device_type"]["source"], "mdns_services")

    def test_googlecast_speaker_variant(self):
        evidence = {
            "mac": "00:11:22:33:44:78",
            "mdns_services": [
                {"type": "_googlecast._tcp", "name": "Nest Audio Kitchen",
                 "hostname": "nest-audio.local", "txt": ""},
            ],
        }
        r = resolve(evidence)
        self.assertEqual(r["device_type"]["value"], "speaker")

    def test_mdns_beats_hostname(self):
        evidence = {
            "mac": "e2:4a:71:b3:f8:01",
            "hostname": "esp32-sensor",  # would say iot on its own
            "mdns_services": [
                {"type": "_companion-link._tcp", "name": "Wil’s iPhone",
                 "hostname": "Wils-iPhone.local", "txt": ""},
            ],
        }
        r = resolve(evidence)
        self.assertEqual(r["device_type"]["value"], "phone")
        self.assertEqual(r["device_type"]["source"], "mdns_services")


class TestPrivateMacFallback(unittest.TestCase):
    def test_no_evidence_at_all(self):
        evidence = {"mac": "e2:4a:71:b3:f8:01"}
        r = resolve(evidence)
        self.assertTrue(r["is_private_mac"])
        self.assertEqual(r["display_name"]["value"], "Private device f8:01")
        self.assertEqual(r["device_type"], {"value": "phone", "confidence": 0.3, "source": "private_mac"})
        self.assertEqual(r["manufacturer"]["value"], "Private (randomized MAC)")
        self.assertEqual(r["os_guess"], {"value": "", "confidence": 0.0, "source": "none"})

    def test_missing_optional_keys_do_not_crash(self):
        r = resolve({"mac": "e2:4a:71:b3:f8:01"})
        self.assertIn(r["device_type"]["value"], CANONICAL_TYPES)


class TestUserOverrides(unittest.TestCase):
    def test_custom_overrides_everything(self):
        evidence = {
            "mac": "e2:4a:71:b3:f8:01",
            "custom_name": "My Special Printer",
            "custom_type": "printer",
            "vendor": "Apple, Inc.",
            "hostname": "Wils-iPhone",
            "mdns_services": [
                {"type": "_companion-link._tcp", "name": "Wil’s iPhone",
                 "hostname": "Wils-iPhone.local", "txt": ""},
            ],
        }
        r = resolve(evidence)
        self.assertEqual(r["device_type"], {"value": "printer", "confidence": 1.0, "source": "user"})
        self.assertEqual(r["display_name"], {"value": "My Special Printer", "confidence": 1.0, "source": "user"})
        # rest still computed normally, unaffected by the override
        self.assertEqual(r["os_guess"]["value"], "iOS")
        self.assertEqual(r["manufacturer"]["value"], "Apple")

    def test_custom_type_invalid_falls_through(self):
        evidence = {
            "mac": "a0:36:9f:e4:c7:55",
            "custom_type": "smartphone",  # not a canonical type
            "hostname": "DESKTOP-GAMING",
            "vendor": "Intel Corporate",
        }
        r = resolve(evidence)
        self.assertEqual(r["device_type"]["value"], "desktop")
        self.assertEqual(r["device_type"]["source"], "hostname")
        self.assertNotEqual(r["device_type"]["source"], "user")


class TestHostnamePatterns(unittest.TestCase):
    def test_desktop_gaming(self):
        r = resolve({"mac": "a0:36:9f:e4:c7:55", "hostname": "DESKTOP-GAMING", "vendor": "Intel Corporate"})
        self.assertEqual(r["device_type"]["value"], "desktop")
        self.assertEqual(r["os_guess"]["value"], "Windows")
        self.assertEqual(r["device_type"]["source"], "hostname")

    def test_macbook_pro_cleaned_name(self):
        r = resolve({"mac": "a4:83:e7:2d:c1:09", "hostname": "Wils-MacBook-Pro.local", "vendor": "Apple, Inc."})
        self.assertEqual(r["device_type"]["value"], "laptop")
        self.assertEqual(r["os_guess"]["value"], "macOS")
        self.assertEqual(r["display_name"]["value"], "Wils-MacBook-Pro")
        self.assertEqual(r["display_name"]["source"], "hostname")

    def test_brw_printer(self):
        r = resolve({"mac": "3c:2a:f4:5d:01:bb", "hostname": "BRWF45D01BB.local", "vendor": "Hewlett Packard"})
        self.assertEqual(r["device_type"]["value"], "printer")
        self.assertEqual(r["device_type"]["source"], "hostname")

    def test_esp32_sensor(self):
        r = resolve({"mac": "24:0a:c4:88:f3:2e", "hostname": "esp32-sensor", "vendor": "Espressif Inc."})
        self.assertEqual(r["device_type"]["value"], "iot")
        self.assertEqual(r["os_guess"]["value"], "embedded")

    def test_raspberrypi(self):
        r = resolve({"mac": "11:22:33:44:55:66", "hostname": "raspberrypi"})
        self.assertEqual(r["device_type"]["value"], "iot")
        self.assertEqual(r["os_guess"]["value"], "Linux")

    def test_priority_hostname_beats_vendor(self):
        r = resolve({"mac": "a0:36:9f:e4:c7:55", "vendor": "Intel Corporate", "hostname": "raspberrypi"})
        self.assertEqual(r["device_type"]["value"], "iot")
        self.assertEqual(r["device_type"]["source"], "hostname")


class TestVendorMap(unittest.TestCase):
    def test_espressif_iot(self):
        r = resolve({"mac": "24:0a:c4:88:f3:2e", "vendor": "Espressif Inc."})
        self.assertEqual(r["device_type"], {"value": "iot", "confidence": 0.5, "source": "vendor"})
        self.assertEqual(r["os_guess"]["value"], "embedded")

    def test_sonos_speaker(self):
        r = resolve({"mac": "48:a6:b8:c2:44:19", "vendor": "Sonos, Inc."})
        self.assertEqual(r["device_type"]["value"], "speaker")

    def test_tplink_network(self):
        r = resolve({"mac": "00:11:22:33:44:55", "vendor": "TP-Link"})
        self.assertEqual(r["device_type"]["value"], "network")

    def test_samsung_phone_android(self):
        r = resolve({"mac": "8c:f5:a3:91:de:47", "vendor": "Samsung Electronics Co.,Ltd"})
        self.assertEqual(r["device_type"]["value"], "phone")
        self.assertEqual(r["os_guess"]["value"], "Android")

    def test_intel_laptop_low_confidence(self):
        r = resolve({"mac": "a0:36:9f:e4:c7:55", "vendor": "Intel Corporate"})
        self.assertEqual(r["device_type"]["value"], "laptop")
        self.assertEqual(r["os_guess"]["value"], "Windows")
        self.assertLess(r["device_type"]["confidence"], 0.5)


class TestTlsAndHttp(unittest.TestCase):
    def test_tls_cert_roku(self):
        r = resolve({"mac": "00:11:22:33:44:66", "tls_cert_text": "subject=CN=Roku, O=Roku Inc"})
        self.assertEqual(r["device_type"], {"value": "tv", "confidence": 0.9, "source": "tls_cert"})

    def test_http_legacy_roku_string(self):
        r = resolve({"mac": "00:11:22:33:44:99", "http_type": "Roku (Roku Ultra)"})
        self.assertEqual(r["device_type"]["value"], "tv")
        self.assertEqual(r["device_type"]["source"], "http")

    def test_http_iot_tasmota(self):
        r = resolve({"mac": "00:11:22:33:44:9a", "http_type": "IoT (Tasmota)"})
        self.assertEqual(r["device_type"]["value"], "iot")

    def test_apple_tv_tvos(self):
        r = resolve({"mac": "00:11:22:33:44:9b", "tls_cert_text": "subject=CN=Apple TV"})
        self.assertEqual(r["device_type"]["value"], "tv")
        self.assertEqual(r["os_guess"]["value"], "tvOS")


class TestLegacyParse(unittest.TestCase):
    def test_smart_speaker_sonos(self):
        r = resolve({"mac": "00:11:22:33:44:88", "legacy_device_type": "Smart Speaker (Sonos)"})
        self.assertEqual(r["device_type"], {"value": "speaker", "confidence": 0.3, "source": "legacy"})

    def test_iphone_ipad_legacy(self):
        r = resolve({"mac": "00:11:22:33:44:89", "legacy_device_type": "iPhone/iPad"})
        self.assertEqual(r["device_type"]["value"], "phone")
        self.assertEqual(r["os_guess"]["value"], "iOS")


class TestDeterminism(unittest.TestCase):
    def _rich_evidence(self):
        return {
            "mac": "a4:83:e7:2d:c1:09",
            "vendor": "Apple, Inc.",
            "hostname": "Wils-MacBook-Pro.local",
            "mdns_hostname": "Wils-MacBook-Pro.local",
            "mdns_services": [
                {"type": "_afpovertcp._tcp", "name": "Wil’s MacBook Pro",
                 "hostname": "Wils-MacBook-Pro.local", "txt": ""},
                {"type": "_smb._tcp", "name": "Wil’s MacBook Pro",
                 "hostname": "Wils-MacBook-Pro.local", "txt": ""},
            ],
            "netbios_name": "",
            "tls_cert_text": "",
            "http_type": "",
            "legacy_device_type": "Apple (Mac/TV/HomePod)",
            "custom_name": "",
            "custom_type": "",
        }

    def test_idempotent(self):
        e = self._rich_evidence()
        self.assertEqual(resolve(e), resolve(e))

    def test_stable_across_key_insertion_order(self):
        e1 = self._rich_evidence()
        e2 = {}
        for k in reversed(list(e1.keys())):
            e2[k] = e1[k]
        self.assertEqual(resolve(e1), resolve(e2))

    def test_batch_types_and_os_are_canonical(self):
        batch = [
            {"mac": "e2:4a:71:b3:f8:01", "mdns_services": [
                {"type": "_companion-link._tcp", "name": "Phone", "hostname": "a.local", "txt": ""}]},
            {"mac": "e6:9c:22:d1:ab:03", "mdns_services": [
                {"type": "_companion-link._tcp", "name": "iPad", "hostname": "b.local", "txt": ""}]},
            {"mac": "a4:83:e7:2d:c1:09", "hostname": "Wils-MacBook-Pro.local", "vendor": "Apple, Inc."},
            {"mac": "d4:ae:05:7f:22:b4", "vendor": "Vizio, Inc"},
            {"mac": "8c:f5:a3:91:de:47", "hostname": "Galaxy-S24", "vendor": "Samsung Electronics Co.,Ltd"},
            {"mac": "fc:a1:83:0a:ee:5c", "vendor": "Amazon Technologies Inc."},
            {"mac": "f4:f5:d8:3b:77:a0", "vendor": "Google LLC"},
            {"mac": "48:a6:b8:c2:44:19", "hostname": "Sonos-Living-Room.local", "vendor": "Sonos, Inc."},
            {"mac": "24:0a:c4:88:f3:2e", "hostname": "esp32-sensor", "vendor": "Espressif Inc."},
            {"mac": "3c:2a:f4:5d:01:bb", "hostname": "BRWF45D01BB.local", "vendor": "Hewlett Packard"},
            {"mac": "a0:36:9f:e4:c7:55", "hostname": "DESKTOP-GAMING", "vendor": "Intel Corporate"},
            {"mac": "da:77:01:f8:6e:c2", "mdns_services": [
                {"type": "_googlecast._tcp", "name": "Guest’s Pixel", "hostname": "android-pixel.local", "txt": ""}]},
            {"mac": "00:00:00:00:00:01", "legacy_device_type": "Gaming Console"},
            {"mac": "00:00:00:00:00:02", "vendor": "Nintendo Co., Ltd"},
            {"mac": "00:00:00:00:00:03"},
        ]
        for evidence in batch:
            r = resolve(evidence)
            self.assertIn(r["device_type"]["value"], CANONICAL_TYPES, evidence)
            self.assertIn(r["os_guess"]["value"], OS_VALUES, evidence)
            self.assertEqual(r["engine_version"], ENGINE_VERSION)


class TestDisplayNameFallbackChain(unittest.TestCase):
    def test_mdns_hostname_beats_netbios_and_hostname(self):
        r = resolve({
            "mac": "00:11:22:33:00:01",
            "mdns_hostname": "From-Mdns.local",
            "netbios_name": "FROM-NETBIOS",
            "hostname": "from-hostname",
        })
        self.assertEqual(r["display_name"], {"value": "From-Mdns", "confidence": 0.7, "source": "mdns_hostname"})

    def test_netbios_beats_hostname(self):
        r = resolve({
            "mac": "00:11:22:33:00:02",
            "netbios_name": "FROM-NETBIOS",
            "hostname": "from-hostname",
        })
        self.assertEqual(r["display_name"], {"value": "FROM-NETBIOS", "confidence": 0.7, "source": "netbios"})

    def test_hostname_beats_vendor_composite(self):
        r = resolve({
            "mac": "00:11:22:33:00:03",
            "hostname": "from-hostname.lan",
            "vendor": "Espressif Inc.",
        })
        self.assertEqual(r["display_name"], {"value": "from-hostname", "confidence": 0.7, "source": "hostname"})

    def test_vendor_type_composite(self):
        r = resolve({"mac": "24:0a:c4:88:f3:2e", "vendor": "Espressif Inc."})
        self.assertEqual(r["display_name"], {"value": "Espressif IoT device", "confidence": 0.4, "source": "vendor"})

    def test_vendor_type_composite_phone(self):
        r = resolve({"mac": "8c:f5:a3:91:de:47", "vendor": "Samsung Electronics Co.,Ltd"})
        self.assertEqual(r["display_name"]["value"], "Samsung phone")

    def test_private_fallback_when_nothing_else(self):
        r = resolve({"mac": "e2:4a:71:b3:f8:01"})
        self.assertEqual(r["display_name"], {"value": "Private device f8:01", "confidence": 0.3, "source": "private_mac"})

    def test_generic_fallback_non_private(self):
        r = resolve({"mac": "00:11:22:33:00:04"})
        self.assertEqual(r["display_name"], {"value": "Device 00:04", "confidence": 0.1, "source": "fallback"})


class TestBuildEvidence(unittest.TestCase):
    def test_realistic_db_row(self):
        fingerprint_data = json.dumps({
            "mdns_services": [
                {"type": "_companion-link._tcp", "name": "Wil’s iPhone",
                 "hostname": "Wils-iPhone.local", "txt": ""},
            ],
            "port_scan": None,
            "tls_cert": None,
            "http_banner": {"ports_checked": [], "identified_as": None, "detail": ""},
            "mdns": {"hostname": "", "identified_as": None},
            "netbios": {"name": "", "identified_as": None},
            "identified_by": "mdns_services",
            "final_type": "iPhone/iPad",
        })
        row = {
            "mac": "e2:4a:71:b3:f8:01",
            "hostname": "Wils-iPhone",
            "custom_name": "Wil's iPhone",
            "manufacturer": "Randomized MAC",
            "device_type": "iPhone/iPad",
            "fingerprint_data": fingerprint_data,
        }
        evidence = build_evidence(row)
        self.assertEqual(evidence["vendor"], "")
        self.assertEqual(evidence["mac"], "e2:4a:71:b3:f8:01")
        self.assertEqual(len(evidence["mdns_services"]), 1)
        self.assertEqual(evidence["mdns_services"][0]["type"], "_companion-link._tcp")
        self.assertEqual(evidence["legacy_device_type"], "iPhone/iPad")
        self.assertEqual(evidence["custom_name"], "Wil's iPhone")
        self.assertEqual(evidence["custom_type"], "")

        r = resolve(evidence)
        self.assertEqual(r["device_type"]["value"], "phone")
        self.assertEqual(r["device_type"]["source"], "mdns_services")

    def test_tls_and_http_fields_extracted(self):
        fingerprint_data = json.dumps({
            "mdns_services": [],
            "tls_cert": {"port": 443, "cert_text": "subject=CN=Roku", "identified_as": "Roku Streaming Device"},
            "http_banner": {"ports_checked": [8060], "identified_as": "Roku (Roku Ultra)", "detail": ""},
            "mdns": {"hostname": "living-room-roku.local", "identified_as": None},
            "netbios": {"name": "", "identified_as": None},
        })
        row = {
            "mac": "00:11:22:33:44:aa",
            "manufacturer": "Roku, Inc.",
            "device_type": "Streaming (Roku)",
            "fingerprint_data": fingerprint_data,
        }
        evidence = build_evidence(row)
        self.assertEqual(evidence["tls_cert_text"], "subject=CN=Roku")
        self.assertEqual(evidence["http_type"], "Roku (Roku Ultra)")
        self.assertEqual(evidence["mdns_hostname"], "living-room-roku.local")
        self.assertEqual(evidence["vendor"], "Roku, Inc.")
        self.assertEqual(evidence["legacy_device_type"], "Streaming (Roku)")

    def test_invalid_json_does_not_crash(self):
        row = {
            "mac": "00:11:22:33:44:bb",
            "manufacturer": "Unknown",
            "device_type": "Unknown",
            "fingerprint_data": "{not valid json!!",
        }
        evidence = build_evidence(row)
        self.assertEqual(evidence["mdns_services"], [])
        self.assertEqual(evidence["mdns_hostname"], "")
        self.assertEqual(evidence["tls_cert_text"], "")
        self.assertEqual(evidence["http_type"], "")
        # should resolve without raising
        r = resolve(evidence)
        self.assertIn(r["device_type"]["value"], CANONICAL_TYPES)

    def test_empty_fingerprint_data(self):
        row = {"mac": "00:11:22:33:44:cc", "manufacturer": "Unknown", "device_type": "Unknown", "fingerprint_data": ""}
        evidence = build_evidence(row)
        self.assertEqual(evidence["mdns_services"], [])
        self.assertEqual(evidence["vendor"], "")
        self.assertEqual(evidence["legacy_device_type"], "")

    def test_randomized_mac_manufacturer_maps_to_empty_vendor(self):
        for mfr in ("Randomized MAC", "Private (randomized MAC)", "Unknown"):
            row = {"mac": "e2:4a:71:b3:f8:01", "manufacturer": mfr, "device_type": "Unknown", "fingerprint_data": ""}
            evidence = build_evidence(row)
            self.assertEqual(evidence["vendor"], "", mfr)

    def test_missing_custom_type_key(self):
        row = {"mac": "00:11:22:33:44:dd", "manufacturer": "Unknown", "device_type": "Unknown"}
        evidence = build_evidence(row)
        self.assertEqual(evidence["custom_type"], "")
        self.assertEqual(evidence["custom_name"], "")


if __name__ == "__main__":
    unittest.main()
