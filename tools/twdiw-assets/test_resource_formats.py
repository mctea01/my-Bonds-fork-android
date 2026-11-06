import struct
import unittest
import zlib

from resource_formats import art_metadata, art_profile, runtime_stages, spirv_summary


def wrap(magic, body, count_size):
    compressed = zlib.compress(body)
    return magic + (1).to_bytes(count_size, "little") + struct.pack("<II", len(body), len(compressed)) + compressed


class ResourceFormatsTest(unittest.TestCase):
    def profile(self):
        key = b"classes.dex"
        header = struct.pack("<HHIII", len(key), 2, 8, 0x1234, 8) + key
        hot = struct.pack("<4H", 1, 0, 2, 0)
        classes = struct.pack("<2H", 2, 3)
        bitmap = bytes([2, 8])
        return wrap(b"pro\x00010\x00", header + hot + classes + bitmap, 1)

    def test_profile_deltas_and_separate_bitmap_planes(self):
        result = art_profile(self.profile())
        dex = result["dexes"][0]
        self.assertEqual([2, 5], dex["class_indices"])
        self.assertEqual([(1, 3), (3, 5)], [(m["method_index"], m["flags"]) for m in dex["methods"]])
        self.assertEqual({"hot": 2, "startup": 1, "post_startup": 1}, dex["method_flag_counts"])
        self.assertEqual(result["decompressed_bytes"], result["consumed_bytes"])

    def test_metadata_has_its_own_class_indices(self):
        key = b"classes.dex"
        body = struct.pack("<HH", 0, len(key)) + key + struct.pack("<IH2H", 8, 2, 1, 2)
        result = art_metadata(wrap(b"prm\x00002\x00", body, 2))
        self.assertEqual([1, 3], result["dexes"][0]["class_indices"])
        self.assertEqual(8, result["dexes"][0]["type_id_count"])

    def test_profiles_reject_truncated_or_extra_compressed_data(self):
        with self.assertRaises(ValueError):
            art_profile(self.profile()[:-1])
        with self.assertRaises(ValueError):
            art_profile(self.profile() + b"extra")

    def test_flatbuffer_optional_backends_and_version(self):
        data = struct.pack("<I4sHH6HiI", 24, b"IPLR", 16, 8, 0, 0, 0, 0, 0, 4, 16, 1)
        result, programs = runtime_stages(data)
        self.assertEqual({}, programs)
        self.assertEqual(5, len(result["absent_backends"]))
        with self.assertRaisesRegex(ValueError, "version 1"):
            runtime_stages(data[:-4] + struct.pack("<I", 2))
        with self.assertRaises(ValueError):
            runtime_stages(data[:10])

    def test_spirv_instruction_boundaries(self):
        header = struct.pack("<5I", 0x07230203, 0x00010300, 0, 2, 0)
        result = spirv_summary(header + struct.pack("<I", (1 << 16) | 253))
        self.assertEqual("1.3", result["version"])
        self.assertEqual(1, result["instruction_count"])
        with self.assertRaisesRegex(ValueError, "instruction length"):
            spirv_summary(header + struct.pack("<I", 253))
        with self.assertRaises(ValueError):
            spirv_summary(header + b"x")


if __name__ == "__main__":
    unittest.main()
