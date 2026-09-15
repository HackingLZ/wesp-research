import tempfile
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parents[1]))
import wesplab
import wesplab_ext


class OfflineTests(unittest.TestCase):
    def test_protocol_table_has_recovered_surface(self):
        table = Path(__file__).parents[1] / 'data' / 'protocol-0.1.0.156346177.tsv'
        rows = wesplab.protocol_rows(table)
        self.assertEqual(36, len(rows))
        self.assertEqual(7, sum(row['kind'] == 'connect' for row in rows))
        self.assertEqual(29, sum(row['kind'] == 'request' for row in rows))

    def test_non_pe_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'not-pe.bin'
            path.write_bytes(b'no')
            with self.assertRaises(wesplab.PeError):
                wesplab.PeImage(path)

    def test_definition_has_all_exports(self):
        definition = Path(__file__).parents[1] / 'data' / 'espclient-0.1.0.156346177.def'
        self.assertEqual(120, len(wesplab.expected_exports(definition)))

    def test_notification_decoder_preserves_unknown_payload(self):
        event = bytearray(0x80)
        event[0:8] = (42).to_bytes(8, 'little')
        event[0x78:0x7c] = (1000).to_bytes(4, 'little')
        decoded = wesplab_ext.decode_notification({
            'event_data_hex': event.hex(), 'external_payload_hex': '4100420043004400'
        })
        self.assertEqual('ProcessCreate', decoded['event_family'])
        self.assertEqual(42, decoded['prefix']['instance_id'])
        self.assertEqual('ABCD', decoded['external_payload']['strings']['utf16le'][0])

    def test_rule_compiler_marks_only_confirmed_adapter_live(self):
        source = {
            'schema': 'wesplab.rule.v1',
            'event': {'type': 'ProcessCreate', 'properties': [6]},
            'filter': None,
            'action': {'type': 'notify', 'queue': 'auto'},
        }
        result = wesplab_ext.compile_rule_document(source)
        self.assertTrue(result['adapter']['live_supported'])
        source['filter'] = {
            'op': 'property', 'family': 'process', 'property': 6,
            'comparison': 'eq', 'value': 4,
        }
        self.assertFalse(wesplab_ext.compile_rule_document(source)['adapter']['live_supported'])

    def test_wire_validator_rejects_out_of_range_request(self):
        envelope = bytearray(0x40)
        envelope[0:4] = (0x1d).to_bytes(4, 'little')
        result = wesplab_ext.validate_wire_record({
            'envelope_hex': envelope.hex(), 'regions': [], 'relocations': []
        })
        self.assertFalse(result['valid'])

    def test_timeline_generation(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / 'events.jsonl'
            output = Path(folder) / 'timeline.html'
            source.write_text('{"timestamp_utc":"2026-01-01T00:00:00Z","event_family":"ProcessCreate"}\n')
            args = type('Args', (), {'input': [source], 'output': output, 'json': None})()
            self.assertEqual(0, wesplab_ext.cmd_timeline(args))
            self.assertIn('ProcessCreate', output.read_text())

    def test_build_diff_detects_export_and_etw_changes(self):
        with tempfile.TemporaryDirectory() as folder:
            before = Path(folder) / 'before.json'
            after = Path(folder) / 'after.json'
            output = Path(folder) / 'diff.json'
            before.write_text('{"windows_build":"1","etw_schema_sha256":"a","artifacts":[{"logical_name":"espclient.dll","sha256":"a","exports":["EspA"]}]}')
            after.write_text('{"windows_build":"2","etw_schema_sha256":"b","artifacts":[{"logical_name":"espclient.dll","sha256":"b","exports":["EspA","EspB"]}]}')
            args = type('Args', (), {'before': before, 'after': after,
                                      'output': output, 'fail_on_change': False})()
            self.assertEqual(0, wesplab_ext.cmd_build_diff(args))
            result = __import__('json').loads(output.read_text())
            self.assertTrue(result['changed'])
            self.assertEqual(['EspB'], result['artifacts'][0]['exports_added'])

    def test_health_flags_integrity_failure(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / 'health.jsonl'
            output = Path(folder) / 'report.json'
            source.write_text('{"timestamp_utc":"2026-01-01T00:00:00Z","driver_integrity_ok":false}\n')
            args = type('Args', (), {'input': [source], 'output': output,
                                      'max_gap': 60.0, 'fail_on_alert': False})()
            self.assertEqual(0, wesplab_ext.cmd_health(args))
            result = __import__('json').loads(output.read_text())
            self.assertFalse(result['healthy'])

    def test_health_correlates_canary_markers(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / 'canary.jsonl'
            output = Path(folder) / 'report.json'
            marker = 'wesplab-test-process'
            encoded = marker.encode('utf-16le').hex()
            source.write_text(
                '{"schema":"wesplab.canary-stimulus.v1","marker":"' + marker + '"}\n' +
                '{"schema":"wesplab.notification-capture.v1","external_payload_hex":"' + encoded + '"}\n'
            )
            args = type('Args', (), {'input': [source], 'output': output,
                                      'max_gap': 60.0, 'fail_on_alert': False})()
            self.assertEqual(0, wesplab_ext.cmd_health(args))
            result = __import__('json').loads(output.read_text())
            self.assertEqual([], result['canaries']['missing'])

    def test_authz_report_finds_principal_differential(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / 'authz.jsonl'
            output = Path(folder) / 'report.json'
            source.write_text(
                '{"target":"t","principal_label":"user","result":{"connect_hresult":-1}}\n'
                '{"target":"t","principal_label":"system","result":{"connect_hresult":0}}\n'
            )
            args = type('Args', (), {'input': [source], 'output': output,
                                      'fail_on_differential': False})()
            self.assertEqual(0, wesplab_ext.cmd_authz_report(args))
            result = __import__('json').loads(output.read_text())
            self.assertEqual(1, len(result['differentials']))


if __name__ == '__main__':
    unittest.main()
