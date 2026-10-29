"""Bounded, static declaration inventory for explicitly selected classes in APK DEX.

Original metadata-only parser based on the Android DEX format specification:
https://source.android.com/docs/core/runtime/dex-format
No method bodies, field values, APK execution, extraction, or decompilation.
Supports normal little-endian DEX 035, 037--040; rejects 041 containers and compact DEX.
This is a focused research utility, not a complete DEX verifier.
"""

import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys
import zipfile


MAX_DEX_BYTES = 128 * 1024 * 1024
MAX_TOTAL_DEX_BYTES = 1024 * 1024 * 1024
MAX_TABLE_ITEMS = 2_000_000
MAX_MEMBERS = 100_000
MAX_STRING_BYTES = 1024 * 1024
MAX_METADATA_CACHE_ENTRIES = 200_000
MAX_METADATA_TEXT_UNITS = 16 * 1024 * 1024
MAX_ZIP_ENTRIES = 100_000
MAX_DEX_ENTRIES = 256


class DexError(ValueError):
    pass


class DexReader:
    def __init__(self, data):
        self.data = data
        if len(data) < 112 or len(data) > MAX_DEX_BYTES:
            raise DexError("DEX length outside supported bounds")
        magic = data[:8]
        if magic not in [b"dex\n" + f"{v:03}".encode("ascii") + b"\0" for v in (35, 37, 38, 39, 40)]:
            raise DexError("Only standard DEX versions 035, 037--040 are supported")
        if self.u32(32) != len(data) or self.u32(36) != 112:
            raise DexError("Invalid DEX file_size/header_size")
        if self.u32(40) != 0x12345678:
            raise DexError("Only little-endian DEX is supported")
        self.tables = {}
        for name, header_offset, item_size in [
            ("strings", 56, 4), ("types", 64, 4), ("protos", 72, 12),
            ("fields", 80, 8), ("methods", 88, 8), ("classes", 96, 32),
        ]:
            count, offset = self.u32(header_offset), self.u32(header_offset + 4)
            if count > MAX_TABLE_ITEMS:
                raise DexError(f"Table count limit exceeded: {name}")
            if count == 0:
                if offset != 0:
                    raise DexError(f"Nonzero offset for empty table: {name}")
            else:
                if offset < 112 or offset % 4:
                    raise DexError(f"Invalid table offset: {name}")
                self.bounds(offset, count * item_size)
            self.tables[name] = (count, offset, item_size)
        self.string_cache = {}
        self.type_cache = {}
        self.metadata_text_units = 0

    def bounds(self, offset, size):
        if offset < 0 or size < 0 or offset > len(self.data) or size > len(self.data) - offset:
            raise DexError("Out-of-bounds DEX access")

    def u16(self, offset):
        self.bounds(offset, 2)
        return struct.unpack_from("<H", self.data, offset)[0]

    def u32(self, offset):
        self.bounds(offset, 4)
        return struct.unpack_from("<I", self.data, offset)[0]

    def table_offset(self, name, index):
        count, offset, size = self.tables[name]
        if index < 0 or index >= count:
            raise DexError(f"Invalid {name} index")
        return offset + index * size

    def uleb(self, offset):
        value = 0
        for shift in range(0, 35, 7):
            self.bounds(offset, 1)
            byte = self.data[offset]
            offset += 1
            if shift == 28 and byte > 0x0F:
                raise DexError("ULEB128 exceeds 32 bits")
            value |= (byte & 0x7F) << shift
            if not byte & 0x80:
                return value, offset
        raise DexError("Malformed ULEB128")

    def string(self, index):
        if index in self.string_cache:
            return self.string_cache[index]
        offset = self.u32(self.table_offset("strings", index))
        utf16_length, start = self.uleb(offset)
        if (len(self.string_cache) >= MAX_METADATA_CACHE_ENTRIES
                or self.metadata_text_units + utf16_length > MAX_METADATA_TEXT_UNITS):
            raise DexError("Decoded metadata cache budget exceeded")
        end = self.data.find(b"\0", start, min(len(self.data), start + MAX_STRING_BYTES + 1))
        if end < 0:
            raise DexError("Unterminated or oversized metadata string")
        encoded = self.data[start:end]
        # DEX modified UTF-8 encodes NUL as C0 80 and supplementary code points
        # as surrogate pairs. surrogatepass preserves those code units safely.
        try:
            text = encoded.replace(b"\xc0\x80", b"\0").decode("utf-8", errors="surrogatepass")
            if len(text.encode("utf-16-le", errors="surrogatepass")) // 2 != utf16_length:
                raise DexError("Metadata string UTF-16 length mismatch")
        except UnicodeError as error:
            raise DexError("Invalid modified UTF-8 metadata string") from error
        self.string_cache[index] = text
        self.metadata_text_units += utf16_length
        return text

    def type(self, index):
        if index not in self.type_cache:
            self.type_cache[index] = self.string(self.u32(self.table_offset("types", index)))
        return self.type_cache[index]

    def prototype(self, index):
        offset = self.table_offset("protos", index)
        return_type = self.type(self.u32(offset + 4))
        parameters_offset = self.u32(offset + 8)
        parameters = []
        if parameters_offset:
            if parameters_offset % 4:
                raise DexError("Unaligned prototype parameter list")
            count = self.u32(parameters_offset)
            if count > MAX_MEMBERS:
                raise DexError("Prototype parameter count limit exceeded")
            self.bounds(parameters_offset + 4, count * 2)
            parameters = [self.type(self.u16(parameters_offset + 4 + i * 2)) for i in range(count)]
        return {"return_type": return_type, "parameters": parameters,
                "descriptor": "(" + "".join(parameters) + ")" + return_type}

    def declared_members(self, class_index, class_data_offset):
        fields, methods = [], []
        if class_data_offset == 0:
            return fields, methods
        cursor = class_data_offset
        sizes = []
        for _ in range(4):
            count, cursor = self.uleb(cursor)
            sizes.append(count)
        if sum(sizes) > MAX_MEMBERS:
            raise DexError("Class member count limit exceeded")
        # Membership comes from class_data, NOT the declaring-class column of
        # field_ids/method_ids, which can also contain unresolved references.
        seen_fields, seen_methods = set(), set()
        for group_index, (kind, count) in enumerate(zip(
                ("static", "instance", "direct", "virtual"), sizes)):
            member_index = 0
            for ordinal in range(count):
                delta, cursor = self.uleb(cursor)
                if ordinal > 0 and delta == 0:
                    raise DexError("Duplicate encoded class member index")
                member_index += delta
                access_flags, cursor = self.uleb(cursor)
                if group_index < 2:
                    if member_index in seen_fields:
                        raise DexError("Field declared in multiple groups")
                    seen_fields.add(member_index)
                    offset = self.table_offset("fields", member_index)
                    if self.u16(offset) != class_index:
                        raise DexError("Declared field belongs to another class")
                    fields.append({"kind": kind, "field_index": member_index,
                                   "name": self.string(self.u32(offset + 4)),
                                   "type": self.type(self.u16(offset + 2)),
                                   "access_flags": access_flags})
                else:
                    if member_index in seen_methods:
                        raise DexError("Method declared in multiple groups")
                    seen_methods.add(member_index)
                    code_offset, cursor = self.uleb(cursor)
                    if code_offset:
                        if code_offset % 4:
                            raise DexError("Unaligned method code offset")
                        self.bounds(code_offset, 16)
                    offset = self.table_offset("methods", member_index)
                    if self.u16(offset) != class_index:
                        raise DexError("Declared method belongs to another class")
                    methods.append({"kind": kind, "method_index": member_index,
                                    "name": self.string(self.u32(offset + 4)),
                                    "prototype": self.prototype(self.u16(offset + 2)),
                                    "access_flags": access_flags})
        return fields, methods

    def selected_classes(self, requested):
        selected = []
        count, start, size = self.tables["classes"]
        for index in range(count):
            offset = start + index * size
            class_index = self.u32(offset)
            descriptor = self.type(class_index)
            if descriptor not in requested:
                continue
            superclass_index = self.u32(offset + 8)
            fields, methods = self.declared_members(class_index, self.u32(offset + 24))
            selected.append({"descriptor": descriptor, "class_def_offset": offset,
                             "superclass": None if superclass_index == 0xFFFFFFFF else self.type(superclass_index),
                             "access_flags": self.u32(offset + 4),
                             "declared_fields": fields, "declared_methods": methods})
        return selected


def normalize_class(name):
    descriptor = name if name.startswith("L") and name.endswith(";") else "L" + name.replace(".", "/") + ";"
    if not descriptor.startswith("L") or not descriptor.endswith(";") or len(descriptor) > 2048:
        raise DexError("Invalid selected class")
    return descriptor


def apk_inventory(path, classes):
    requested = set(map(normalize_class, classes))
    if not requested or len(requested) > 64:
        raise DexError("Select between 1 and 64 exact classes")
    path = Path(path).resolve(strict=True)
    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    result = {"format_version": 1, "artifact": {"path": str(path), "sha256": digest},
              "scope": "selected declared metadata only; no execution, decompilation or values",
              "requested_classes": sorted(requested), "dex_entries": [], "classes": [], "errors": [],
              "limitations": [
                  "Presence of a declaration does not prove populated metadata or availability before playback.",
                  "Inherited members, reflection, runtime state, native/dynamic code and media semantics are not inspected.",
                  "Method bodies, annotations, field values and call relationships are not decoded.",
                  "This is a focused DEX metadata reader, not full DEX, APK authenticity or signature verification.",
                  "Only normal little-endian DEX 035, 037--040 is supported; containers, compact DEX and archives inside archives are excluded."
              ]}
    total_bytes = 0
    with zipfile.ZipFile(path) as apk:
        entries = apk.infolist()
        if len(entries) > MAX_ZIP_ENTRIES:
            raise DexError("APK entry count limit exceeded")
        dex_entries = [entry for entry in entries if entry.filename.lower().endswith(".dex") and not entry.is_dir()]
        if len(dex_entries) > MAX_DEX_ENTRIES:
            raise DexError("DEX entry count limit exceeded")
        for ordinal, entry in enumerate(dex_entries):
            record = {"name": entry.filename, "archive_ordinal": ordinal,
                      "size": entry.file_size, "status": "not_examined"}
            result["dex_entries"].append(record)
            try:
                if entry.file_size > MAX_DEX_BYTES or total_bytes + entry.file_size > MAX_TOTAL_DEX_BYTES:
                    raise DexError("DEX byte budget exceeded")
                with apk.open(entry) as stream:
                    data = stream.read(MAX_DEX_BYTES + 1)
                if len(data) != entry.file_size or len(data) > MAX_DEX_BYTES:
                    raise DexError("DEX entry size mismatch or byte budget exceeded")
                total_bytes += len(data)
                record["sha256"] = hashlib.sha256(data).hexdigest()
                reader = DexReader(data)
                selected = reader.selected_classes(requested)
                record.update({"status": "examined", "version": data[4:7].decode("ascii"),
                               "class_def_count": reader.tables["classes"][0], "selected_count": len(selected)})
                for item in selected:
                    item.update({"dex_entry": entry.filename, "dex_sha256": record["sha256"],
                                 "archive_ordinal": ordinal})
                    result["classes"].append(item)
                del reader, data
            except (DexError, zipfile.BadZipFile, RuntimeError, NotImplementedError) as error:
                record["status"] = "error"
                result["errors"].append({"dex_entry": entry.filename, "error": str(error)})
    result["coverage"] = "complete_within_declared_metadata_scope" if not result["errors"] and result["dex_entries"] else "partial"
    counts = {name: sum(item["descriptor"] == name for item in result["classes"]) for name in requested}
    result["missing"] = [{"descriptor": name, "status": "not_found" if result["coverage"].startswith("complete") else "unresolved_due_to_partial_inventory"}
                         for name, count in sorted(counts.items()) if count == 0]
    result["duplicates"] = [{"descriptor": name, "occurrences": count} for name, count in sorted(counts.items()) if count > 1]
    result["limits"] = {"dex_bytes": MAX_DEX_BYTES, "total_dex_bytes": MAX_TOTAL_DEX_BYTES,
                        "table_items": MAX_TABLE_ITEMS, "members_per_class": MAX_MEMBERS,
                        "metadata_string_bytes": MAX_STRING_BYTES,
                        "metadata_cache_entries_per_dex": MAX_METADATA_CACHE_ENTRIES,
                        "metadata_text_utf16_units_per_dex": MAX_METADATA_TEXT_UNITS}
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("apk", type=Path)
    parser.add_argument("--class", dest="classes", action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.apk.resolve() == args.output.resolve():
        parser.error("Output must not replace the APK")
    try:
        result = apk_inventory(args.apk, args.classes)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("x", encoding="utf-8") as stream:
            json.dump(result, stream, ensure_ascii=True, indent=2)
            stream.write("\n")
    except (OSError, DexError, zipfile.BadZipFile) as error:
        print(f"Inventory failed: {error}", file=sys.stderr)
        return 2
    print(json.dumps({"output": str(args.output), "coverage": result["coverage"],
                      "classes": len(result["classes"]), "missing": result["missing"],
                      "errors": result["errors"]}, ensure_ascii=True))
    return 0 if result["coverage"].startswith("complete") else 1


if __name__ == "__main__":
    raise SystemExit(main())
