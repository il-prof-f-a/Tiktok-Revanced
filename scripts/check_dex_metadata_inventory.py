"""Synthetic checks: no proprietary APK content is used in these fixtures."""
import json
from pathlib import Path
import struct
import tempfile
import unittest
import zipfile

from dex_metadata_inventory import DexError, DexReader, apk_inventory


def uleb(value):
    encoded = bytearray()
    while value >= 128:
        encoded.append((value & 127) | 128)
        value >>= 7
    encoded.append(value)
    return bytes(encoded)


def micro_dex():
    # Two field/method IDs name this class, but only the first is declared in
    # class_data. This catches the reference-versus-declaration confusion.
    strings = ["Lsample/Example;", "Ljava/lang/Object;", "I", "V",
               "declaredField", "referencedField", "declaredMethod", "referencedMethod"]
    data = bytearray(112)
    offsets = {}
    for name, count, size in [("strings", 8, 4), ("types", 4, 4), ("protos", 1, 12),
                              ("fields", 2, 8), ("methods", 2, 8), ("classes", 1, 32)]:
        offsets[name] = len(data)
        data.extend(b"\0" * (count * size))
    data_start = len(data)
    for index, text in enumerate(strings):
        struct.pack_into("<I", data, offsets["strings"] + 4 * index, len(data))
        data.extend(uleb(len(text)) + text.encode("ascii") + b"\0")
    class_data_offset = len(data)
    # sizes static=1 instance=0 direct=1 virtual=0; first field+method only.
    data.extend(b"\x01\x00\x01\x00\x00\x01\x00\x01\x00")
    for index in range(4):
        struct.pack_into("<I", data, offsets["types"] + 4 * index, index)
    struct.pack_into("<III", data, offsets["protos"], 3, 3, 0)
    for index in range(2):
        struct.pack_into("<HHI", data, offsets["fields"] + 8 * index, 0, 2, 4 + index)
        struct.pack_into("<HHI", data, offsets["methods"] + 8 * index, 0, 0, 6 + index)
    struct.pack_into("<IIIIIIII", data, offsets["classes"], 0, 1, 1, 0, 0xFFFFFFFF, 0, class_data_offset, 0)
    data[:8] = b"dex\n035\0"
    struct.pack_into("<III", data, 32, len(data), 112, 0x12345678)
    for name, header, count in [("strings", 56, 8), ("types", 64, 4), ("protos", 72, 1),
                                ("fields", 80, 2), ("methods", 88, 2), ("classes", 96, 1)]:
        struct.pack_into("<II", data, header, count, offsets[name])
    struct.pack_into("<II", data, 104, len(data) - data_start, data_start)
    return bytes(data)


class InventoryChecks(unittest.TestCase):
    def test_declared_members_exclude_references(self):
        selected = DexReader(micro_dex()).selected_classes({"Lsample/Example;"})
        self.assertEqual(len(selected), 1)
        self.assertEqual([f["name"] for f in selected[0]["declared_fields"]], ["declaredField"])
        self.assertEqual([m["name"] for m in selected[0]["declared_methods"]], ["declaredMethod"])
        self.assertEqual(selected[0]["declared_methods"][0]["prototype"]["descriptor"], "()V")
        self.assertEqual(selected[0]["superclass"], "Ljava/lang/Object;")

    def test_exact_selection(self):
        self.assertEqual(DexReader(micro_dex()).selected_classes({"Lsample/Exam;"}), [])

    def test_invalid_magic_and_container_version(self):
        for magic in (b"invalid!", b"dex\n036\0", b"dex\n041\0", b"cdex001\0"):
            data = bytearray(micro_dex())
            data[:8] = magic
            with self.assertRaises(DexError):
                DexReader(data)

    def test_invalid_size_endian_and_table_bounds(self):
        for offset, value in [(32, 112), (36, 116), (40, 0x78563412), (60, 0xFFFFFFFC), (56, 2_000_001)]:
            data = bytearray(micro_dex())
            struct.pack_into("<I", data, offset, value)
            with self.assertRaises(DexError):
                DexReader(data)

    def test_bad_string_pointer(self):
        data = bytearray(micro_dex())
        struct.pack_into("<I", data, 112, len(data) + 20)
        with self.assertRaises(DexError):
            DexReader(data).selected_classes({"Lsample/Example;"})

    def test_member_group_bounds(self):
        data = bytearray(micro_dex())
        classes_offset = struct.unpack_from("<I", data, 100)[0]
        struct.pack_into("<I", data, classes_offset + 24, len(data) - 1)
        with self.assertRaises(DexError):
            DexReader(data).selected_classes({"Lsample/Example;"})

    def test_apk_missing_duplicates_and_partial_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            apk_path = Path(directory) / "synthetic.apk"
            with zipfile.ZipFile(apk_path, "w") as apk:
                apk.writestr("classes.dex", micro_dex())
                apk.writestr("classes2.dex", micro_dex())
            result = apk_inventory(apk_path, ["sample.Example", "sample.Missing"])
            self.assertTrue(result["coverage"].startswith("complete"))
            self.assertEqual(result["duplicates"], [{"descriptor": "Lsample/Example;", "occurrences": 2}])
            self.assertEqual(result["missing"], [{"descriptor": "Lsample/Missing;", "status": "not_found"}])
            self.assertEqual(len(result["artifact"]["sha256"]), 64)
            json.dumps(result, ensure_ascii=True)
            with zipfile.ZipFile(apk_path, "a") as apk:
                apk.writestr("classes3.dex", b"invalid")
            partial = apk_inventory(apk_path, ["sample.Missing"])
            self.assertEqual(partial["coverage"], "partial")
            self.assertEqual(partial["missing"][0]["status"], "unresolved_due_to_partial_inventory")


if __name__ == "__main__":
    unittest.main()
