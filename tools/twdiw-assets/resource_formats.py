"""Parse Flutter runtime-stage bundles and ART baseline-profile structures."""

import hashlib
import struct
import zlib


class Cursor:
    def __init__(self, data):
        self.data = data
        self.position = 0

    def take(self, size):
        if size < 0 or self.position + size > len(self.data):
            raise ValueError("Truncated resource data")
        result = self.data[self.position:self.position + size]
        self.position += size
        return result

    def integer(self, size):
        return int.from_bytes(self.take(size), "little")

    def end(self):
        if self.position != len(self.data):
            raise ValueError("Unconsumed resource bytes")


class FlatBuffer:
    def __init__(self, data):
        self.data = data
        if data[4:8] != b"IPLR":
            raise ValueError("Expected IPLR file identifier")
        self.root = self.number(0, "I")

    def number(self, offset, kind):
        if offset < 0 or offset + struct.calcsize("<" + kind) > len(self.data):
            raise ValueError("FlatBuffer read out of bounds")
        return struct.unpack_from("<" + kind, self.data, offset)[0]

    def field(self, table, index):
        vtable = table - self.number(table, "i")
        size = self.number(vtable, "H")
        if size < 4 or size % 2:
            raise ValueError("Invalid FlatBuffer vtable")
        if 4 + index * 2 >= size:
            return None
        offset = self.number(vtable + 4 + index * 2, "H")
        return table + offset if offset else None

    def scalar(self, table, index, kind="Q"):
        field = self.field(table, index)
        return self.number(field, kind) if field is not None else 0

    def reference(self, offset):
        value = offset + self.number(offset, "I")
        self.number(value, "I")
        return value

    def vector(self, table, index):
        field = self.field(table, index)
        if field is None:
            return 0, 0
        offset = self.reference(field)
        return offset + 4, self.number(offset, "I")

    def bytes(self, table, index):
        offset, size = self.vector(table, index)
        if offset + size > len(self.data):
            raise ValueError("FlatBuffer vector out of bounds")
        return self.data[offset:offset + size], offset

    def text(self, table, index):
        data, offset = self.bytes(table, index)
        if offset and self.number(offset + len(data), "B") != 0:
            raise ValueError("Unterminated FlatBuffer string")
        return data.decode("utf-8")

    def tables(self, table, index):
        offset, size = self.vector(table, index)
        if size > len(self.data) // 4:
            raise ValueError("Invalid FlatBuffer table vector length")
        return [self.reference(offset + i * 4) for i in range(size)]


def runtime_stages(data):
    reader = FlatBuffer(data)
    version = reader.scalar(reader.root, 5, "I")
    if version != 1:
        raise ValueError("Expected the analyzed runtime-stage format version 1")
    stages, programs = [], {}
    for index, backend in enumerate(("sksl", "metal", "opengles", "opengles3", "vulkan")):
        field = reader.field(reader.root, index)
        if field is None:
            continue
        table = reader.reference(field)
        program, offset = reader.bytes(table, 4)
        programs[backend] = program
        stage = dict(backend=backend, stage=reader.scalar(table, 0, "b"), entrypoint=reader.text(table, 1),
                     shader_offset=offset, shader_bytes=len(program), shader_sha256=hashlib.sha256(program).hexdigest(),
                     struct_byte_length=reader.scalar(table, 5), float_count=reader.scalar(table, 6), uniforms=[], inputs=[])
        for uniform in reader.tables(table, 3):
            padding, _ = reader.bytes(uniform, 8)
            stage["uniforms"].append(dict(
                name=reader.text(uniform, 0), location=reader.scalar(uniform, 1), binding=reader.scalar(uniform, 2),
                type=reader.scalar(uniform, 3, "I"), bit_width=reader.scalar(uniform, 4), rows=reader.scalar(uniform, 5),
                columns=reader.scalar(uniform, 6), array_elements=reader.scalar(uniform, 7),
                struct_layout=list(padding), struct_float_count=reader.scalar(uniform, 9),
            ))
        for item in reader.tables(table, 2):
            stage["inputs"].append(dict(
                name=reader.text(item, 0), location=reader.scalar(item, 1), set=reader.scalar(item, 2),
                binding=reader.scalar(item, 3), type=reader.scalar(item, 4, "I"), bit_width=reader.scalar(item, 5),
                vec_size=reader.scalar(item, 6), columns=reader.scalar(item, 7), offset=reader.scalar(item, 8),
            ))
        stages.append(stage)
    return dict(format_version=version, stages=stages, absent_backends=[x for x in ("sksl", "metal", "opengles", "opengles3", "vulkan") if x not in programs]), programs


def spirv_summary(data):
    if len(data) < 20 or len(data) % 4:
        raise ValueError("Invalid SPIR-V size")
    words = struct.unpack("<" + "I" * (len(data) // 4), data)
    if words[0] != 0x07230203 or words[4] != 0:
        raise ValueError("Invalid SPIR-V header")
    position, instructions, counts = 5, 0, {}
    while position < len(words):
        count, opcode = words[position] >> 16, words[position] & 65535
        if count == 0 or position + count > len(words):
            raise ValueError("Invalid SPIR-V instruction length")
        counts[opcode] = counts.get(opcode, 0) + 1
        instructions += 1
        position += count
    return dict(version=f"{(words[1] >> 16) & 255}.{(words[1] >> 8) & 255}", generator=words[2],
                id_bound=words[3], instruction_count=instructions, opcode_counts=counts, consumed_bytes=position * 4)


def profile_body(data, magic, count_size):
    reader = Cursor(data)
    if reader.take(8) != magic:
        raise ValueError("Unexpected ART profile format")
    count, size, compressed_size = reader.integer(count_size), reader.integer(4), reader.integer(4)
    compressed = reader.take(compressed_size)
    reader.end()
    decoder = zlib.decompressobj()
    body = decoder.decompress(compressed) + decoder.flush()
    if not decoder.eof or decoder.unused_data or decoder.unconsumed_tail or len(body) != size:
        raise ValueError("Invalid ART profile compressed body")
    return count, body


def class_indices(reader, count):
    result, last = [], 0
    for _ in range(count):
        last += reader.integer(2)
        result.append(last)
    return result


def art_profile(data):
    count, body = profile_body(data, b"pro\x00010\x00", 1)
    reader, dexes = Cursor(body), []
    for _ in range(count):
        key_size, classes, hot_size = reader.integer(2), reader.integer(2), reader.integer(4)
        checksum, methods = reader.integer(4), reader.integer(4)
        dexes.append(dict(dex_key=reader.take(key_size).decode("utf-8"), class_count=classes,
                          hot_region_bytes=hot_size, dex_checksum=checksum, method_id_count=methods))
    for dex in dexes:
        hot, last, caches = Cursor(reader.take(dex["hot_region_bytes"])), 0, []
        flags = {}
        while hot.position < len(hot.data):
            last += hot.integer(2)
            if last >= dex["method_id_count"]:
                raise ValueError("Hot method index out of bounds")
            flags[last] = 1
            for _ in range(hot.integer(2)):
                entry = dict(method_index=last, dex_pc=hot.integer(2), encoding=hot.integer(1))
                entry["dex_mappings"] = []
                if entry["encoding"] not in (6, 7):
                    for _ in range(entry["encoding"]):
                        profile_index, size = hot.integer(1), hot.integer(1)
                        entry["dex_mappings"].append(dict(profile_index=profile_index, class_indices=[hot.integer(2) for _ in range(size)]))
                caches.append(entry)
        hot.end()
        dex["class_indices"] = class_indices(reader, dex["class_count"])
        bitmap = reader.take((dex["method_id_count"] * 2 + 7) // 8)
        for index in range(dex["method_id_count"]):
            for offset, flag in ((0, 2), (dex["method_id_count"], 4)):
                bit = index + offset
                if bitmap[bit // 8] & (1 << (bit % 8)):
                    flags[index] = flags.get(index, 0) | flag
        dex["methods"] = [dict(method_index=index, flags=value,
                                hot=bool(value & 1), startup=bool(value & 2), post_startup=bool(value & 4)) for index, value in sorted(flags.items())]
        dex["inline_caches"] = caches
        dex["method_flag_counts"] = {name: sum(bool(value & flag) for value in flags.values()) for name, flag in (("hot", 1), ("startup", 2), ("post_startup", 4))}
    reader.end()
    return dict(format="010", dex_count=count, decompressed_bytes=len(body), consumed_bytes=reader.position, dexes=dexes)


def art_metadata(data):
    count, body = profile_body(data, b"prm\x00002\x00", 2)
    reader, dexes = Cursor(body), []
    for _ in range(count):
        index, key_size = reader.integer(2), reader.integer(2)
        key = reader.take(key_size).decode("utf-8")
        type_count, class_count = reader.integer(4), reader.integer(2)
        dexes.append(dict(profile_index=index, dex_key=key, type_id_count=type_count,
                          class_count=class_count, class_indices=class_indices(reader, class_count)))
    reader.end()
    return dict(format="002", dex_count=count, decompressed_bytes=len(body), consumed_bytes=reader.position, dexes=dexes)
