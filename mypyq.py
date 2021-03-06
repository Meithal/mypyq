import struct
import typing
import io
import pathlib
import dataclasses
import zlib
import bz2
import itertools
import logging
import functools
import collections

import explode
import subprocess

__version__ = "0.0.1"
write_errors = False
HashType = typing.NewType('HashType', int)
FilePosition = typing.NewType('FilePosition', int)


def pairwise(iterable):  # from python manual
    """s -> (s0,s1), (s1,s2), (s2, s3), ..."""
    a, b = itertools.tee(iterable)
    next(b, None)
    return zip(a, b)


WAR3MAGIC = b"HM3W"
MPQ_USER_DATA_MAGIC = b"MPQ\x1B"
MPQ_HEADER_MAGIC = b"MPQ\x1A"

_block_index_to_filename = collections.defaultdict(dict)
_filename_to_hash_data = collections.defaultdict(dict)


class FormattedTuple:
    format_string: typing.ClassVar[str]

    def __init_subclass__(cls, format_string, **kwargs):
        cls.format_string = format_string

        super().__init_subclass__(**kwargs)


@dataclasses.dataclass()
class MPQUserData(FormattedTuple, format_string="4s3I"):
    magic: bytes
    max_size: int
    offset_to_header: int
    this_size: int


@dataclasses.dataclass
class MPQHeader(FormattedTuple, format_string="4s2I2H4I"):
    magic: bytes
    header_size: int
    mpq_size: int
    format_version: int
    block_size_exp: int
    hash_table_offset: int
    block_table_offset: int
    hash_table_entries: int
    block_table_entries: int

    offset_format: typing.ClassVar = "%s_table_offset"
    entries_format: typing.ClassVar = "%s_table_entries"

    @property
    def sector_size(self):
        return 512 << self.block_size_exp


@dataclasses.dataclass
class MPQHashEntry(FormattedTuple, format_string="2IHHI"):
    name_part_a: int
    name_part_b: int
    locale: int
    platform: int
    block_index: int
    archive: dataclasses.InitVar['MPQArchive']
    positions: dataclasses.InitVar[typing.Tuple[int, ...]]
    index: dataclasses.InitVar[int] = -1

    def __post_init__(self, archive: dataclasses.InitVar['MPQArchive'], positions, index=-1):
        self.archive = archive
        self.index = index

    @property
    def was_always_empty(self):
        return self.block_index == 0xFFFFFFFF

    @property
    def was_deleted(self):
        return self.block_index == 0xFFFFFFFE


def unblast(content) -> typing.Tuple[set, bytes]:
    try:
        if pathlib.Path("WinBlast.exe").exists():
            res = subprocess.run(["WinBlast"], input=content, capture_output=True)
            if res.returncode < 0:
                raise ValueError("Weird")
            rv = res.stdout
        else:
            rv = explode.explode(content)
    except Exception as e:
        logging.error(f"Error during explode: {e}")
        with open("dump", 'wb') as file:
            file.write(content)
        return content
    else:
        return rv


@dataclasses.dataclass
class MPQBlockEntry(FormattedTuple, format_string="4I"):
    file_position: FilePosition
    compressed_size: int
    uncompressed_size: int
    flags: int
    archive: dataclasses.InitVar['MPQArchive']
    positions: dataclasses.InitVar[typing.Tuple[int, ...]]
    index: dataclasses.InitVar[int] = -1

    flags_table: typing.ClassVar = {
        0x00000100: ('pkware_imploded', "PKWARE compressed file (imploded)"),
        0x00000200: ('other_compressions', "Other compression"),
        0x00010000: ('encrypted', "File is encrypted"),
        0x00020000: ('decrypt_key', "Decryption key fixed with file offset in archive"),
        0x00100000: ('is_patch', "File is a patch"),
        0x01000000: ('single_sector', "Single block file"),
        0x02000000: ('deleted', "File is deleted by patch"),
        0x04000000: ('has_crc', "Each sector of file has CRC"),
        0x80000000: ('exists', "File exists")
    }

    ZERO_SIZE: typing.ClassVar = "ZERO_SIZE"
    FLAG_NOT_EXISTS: typing.ClassVar = "FLAG_NOT_EXISTS"
    MALFORMED_DCL_CHUNK: typing.ClassVar = "Malformed PKWARE DCL chunk"

    def __post_init__(self, archive: dataclasses.InitVar['MPQArchive'], positions=None, index=-1):

        self.archive = archive
        self.positions = positions
        self.index = index

    def __repr__(self):
        dic = dataclasses.asdict(self)
        dic.update({'flags': bin(self.flags)})
        filename = self.archive.filename_for_index(self.index) or "**No name found**"

        return f"{dic} - {filename} - {self.describe_flags()} Positions: {self.sectors_positions(self.archive)}"

    def describe_flags(self):
        return ', '.join(desc for key, (_, desc) in self.flags_table.items() if self.flags & key)

    def sectors_positions(self, archive: 'MPQArchive', decrypt_key: HashType = None):
        if self.single_sector:
            return [0, self.compressed_size]

        sector_size = archive.header.sector_size
        sectors, remainder = divmod(self.uncompressed_size, sector_size)

        sectors += bool(remainder)
        sectors += bool(self.has_crc)

        file_pos = archive.tell_file()
        archive.seek_file_to(self.file_position + 0x200)

        positions_data = archive.stream.read(struct.calcsize("<I") * (sectors + 1))
        if isinstance(decrypt_key, int):
            positions_data, rem = _decrypt(positions_data, HashType(decrypt_key))
        positions = struct.unpack('<%dI' % (sectors + 1), positions_data)
        self.positions = positions

        archive.seek_file_to(file_pos)
        return positions

    def extract_file(self, filename, archive: 'MPQArchive') -> typing.Tuple[bytes, set]:
        errors = set()
        if self.uncompressed_size == 0:
            return b'', {f"{self.ZERO_SIZE} {self!r}"}

        if not self.exists:
            return b'', {f"{self.FLAG_NOT_EXISTS} {self!r}"}

        archive.seek_file_to(self.file_position + 0x200)

        key = None
        if self.encrypted:
            key = _hash(filename, 'TABLE')
            if self.decrypt_key:
                key = (key + self.file_position) ^ self.uncompressed_size

        if self.single_sector:
            if self.other_compressions and self.uncompressed_size > self.compressed_size:
                errors_, value = self._uncompress(archive.stream.read(self.compressed_size), (filename, "whole"))
                errors.update(errors_ and {f"single: {errors_} {self!r}"})
            else:
                value = archive.stream.read(self.uncompressed_size)
            if errors:
                errors.add(repr(self))
            return value, errors

        positions = self.sectors_positions(archive, key and key - 1)

        if self.other_compressions or self.pkware_imploded:
            result = bytearray()
            raw_bytes_to_read = archive.stream.read(positions[-1])
            for i, (start, end) in enumerate(pairwise([p for p in positions[:-1]] + [positions[-1]])):
                # todo: use a single iterator ?
                to_read = raw_bytes_to_read[start:end]
                rem = "Non encypted"
                errors_ = set()

                if self.encrypted:
                    to_read, rem = _decrypt(to_read, HashType(key + i))

                if self.other_compressions:
                    needed_chunk = self.uncompressed_size - len(result)
                    if needed_chunk > archive.header.sector_size:
                        needed_chunk = archive.header.sector_size
                    if needed_chunk != (end - start):
                        # todo: we could probably detect that early and simply read it into the result
                        # but we have to be sure that we decrypt every block if it is even possible
                        errors_, uncompress = self._uncompress(to_read, (filename, i + 1, len(positions) - 1), rem)
                    else:
                        uncompress = to_read
                else:  # pkware
                    uncompress = unblast(to_read)

                result += uncompress
                errors.update(errors_ and {f"{i + 1} on {len(positions) - 1}: {errors_} {self!r}"})

            value = bytes(result)
        else:
            if self.encrypted:
                raise ValueError("Should never happen.")
            value = archive.stream.read(self.uncompressed_size)

        return value, errors

    UNSUPPORTED_COMPRESSION: typing.ClassVar = "UNSUPPORTED_COMPRESSION"
    ZLIB_ERROR: typing.ClassVar = "ZLIB_ERROR"
    DECOMPRESSION_ERROR: typing.ClassVar = "DECOMPRESSION_ERROR"
    compressions: typing.ClassVar = {
        0x40: ("monowav", lambda x: -1),  # todo: implement
        0x80: ("stereowav", lambda x: -1),  # todo: implement
        0x01: ("huffman", lambda x: -1),  # todo: implement
        0x02: ("zlib", zlib.decompress),
        0x08: ("pkware", unblast),
        0x10: ("bzip2", bz2.decompress)
    }

    def _uncompress(self, raw: bytes, debug_diag, rem=None) -> typing.Tuple[set, bytes]:
        compressions = raw[0]
        orig = raw[1:]
        errors = set()
        dec = b""
        for mask, (short, meth) in reversed([*self.compressions.items()]):
            if not compressions & mask:
                continue
            try:
                dec = meth(orig)
                if write_errors and short == "zlib":
                    filename, part, max_parts = debug_diag
                    with open(f"{filename} {part}-{max_parts} {rem} GOOD", 'wb') as f:
                        f.write(orig)

                if dec == -1:
                    errors.add(self.UNSUPPORTED_COMPRESSION + short)
                    dec = orig
                    break
            except OSError as e:
                logging.error(f"Uncompress error for method {short} - {e} for {debug_diag}")
                errors.add(self.DECOMPRESSION_ERROR + short + str(e))
            except zlib.error as e:
                logging.error(f"Zlib error {short} - {e} for {debug_diag}")
                errors.add(self.ZLIB_ERROR + str(e))
            else:
                continue

            if write_errors:
                filename, part, max_parts = debug_diag
                with open(f"{filename} {part}-{max_parts} {rem} BAD", 'wb') as f:
                    f.write(orig)

            dec = orig
            break

        return errors, dec


def _init_mpq_block_accessors():
    for k, (prop, desc) in MPQBlockEntry.flags_table.items():
        setattr(MPQBlockEntry, prop, property(lambda instance, key_=k: bool(instance.flags & key_), doc=desc))


_init_mpq_block_accessors()

logging.info("Creating the crypt table")

_crypt_table = [0] * 0x500


def _make_crypto():
    seed = 0x00100001

    for i in range(256):
        index = i
        for _ in range(5):
            seed = (seed * 125 + 0b11) % 0x2AAAAB
            temp1 = (seed & 0xFFFF) << 16

            seed = (seed * 125 + 0b11) % 0x2AAAAB
            temp2 = (seed & 0xFFFF)

            _crypt_table[index] = (temp1 | temp2)

            index += 256


_make_crypto()


class MPQArchive:
    stream: typing.BinaryIO  # actually required, but made optional so this dc can be inherited from
    hash_: typing.AnyStr
    header_offset: typing.ClassVar[int] = 0x200
    raw_pre_archive: bytes
    user_data: typing.Optional[MPQUserData]
    header: MPQHeader
    hash_table: typing.List[MPQHashEntry]
    block_table: typing.List[MPQBlockEntry]
    filenames_to_test: typing.Tuple[str]
    tested_filenames: set

    lang_id: typing.ClassVar = {
        0x00000409: 'enUS',
        0x00000809: 'enGB',
        0x0000040c: 'frFR',
        0x00000407: 'deDE',
        0x0000040a: 'esES',
        0x00000410: 'itIT',
        0x00000405: 'csCZ',
        0x00000419: 'ruRU',
        0x00000415: 'plPL',
        0x00000416: 'ptBR',
        0x00000816: 'ptPT',
        0x0000041f: 'tkTK',
        0x00000411: 'jaJA',
        0x00000412: 'koKR',
        0x00000404: 'zhTW',
        0x00000804: 'zhCN',
        0x0000041e: 'thTH',
    }

    def __init__(self, stream, hash_: typing.AnyStr, filenames_to_test: typing.Tuple[str] = tuple()):
        self.stream = stream
        if self.stream.closed:
            raise OSError("File is closed.")
        if not self.stream.readable() or not self.stream.seekable():
            raise OSError(f"Something wrong with the stream.")
        self.hash_ = hash_
        self.raw_pre_archive = self.stream.read(self.header_offset)
        self.stream.seek(self.header_offset)

        # at this point, if we don't find the user data block, we can assume this map is protected.
        self._fill_user_data()
        self.header = self._fill_header()

        self.hash_table = list(self._fill_table('hash', MPQHashEntry))
        self.block_table = list(self._fill_table('block', MPQBlockEntry))

        self.tested_filenames = set()

        for filename in filenames_to_test:
            self.test_filename(filename, "list given at init")

    def __hash__(self):
        return hash(self.hash_)  # required so successive instances of the same mpq map to the same filename persist

    def __contains__(self, item):
        return self._hash_entry(item, 0, 0) is not None

    def insight(self):
        number_of_hash_entires = self.header.hash_table_entries
        used_hash_table_entries = len([h for h in self.hash_table if not (h.was_deleted or h.was_always_empty)])
        number_of_block_entires = self.header.block_table_entries
        block_indices = [h.block_index for h in self.hash_table if not (h.was_deleted or h.was_always_empty)]
        blocks = []
        for block_index in [h.block_index for h in self.hash_table if not (h.was_deleted or h.was_always_empty)]:
            block = self.block_table[block_index]
            blocks.append(repr(block))
        hashes = []
        for h in self.hash_table:
            hashes.append(repr(h))
        return {
            'header': {k: str(v) for k, v in dataclasses.asdict(self.header).items()},
            'number_of_hash_entires': number_of_hash_entires,
            'used_hash_table_entries': used_hash_table_entries,
            'number_of_block_entires': number_of_block_entires,
            'sector_size': self.header.sector_size,
            'block_indices': block_indices,
            'blocks': blocks,
            'hashes': hashes,
            'tested_filenames': list(self.tested_filenames),
        }

    def test_filename(self, name: str, reason: str, locale=0, platform=0):
        hash_entry_ = self._hash_entry(name, locale, platform)
        self.tested_filenames.add((reason, f"{bool(hash_entry_)}: {name}"))
        if hash_entry_:
            _block_index_to_filename[hash(self)][
                hash_entry_.block_index
            ] = reason, name, hash_entry_.locale, hash_entry_.platform
            _filename_to_hash_data[hash(self)][
                name, hash_entry_.locale, hash_entry_.platform
            ] = hash_entry_
            return hash_entry_
        return None

    def _fill_user_data(self):
        contents = self.stream.read(struct.calcsize(MPQUserData.format_string))
        self.stream.seek(self.header_offset)
        if contents[:4] != MPQ_USER_DATA_MAGIC:
            return
        self.user_data = MPQUserData(
            *struct.unpack(MPQUserData.format_string, contents[:struct.calcsize(MPQUserData.format_string)])
        )

    def _fill_header(self):
        contents = self.stream.read(struct.calcsize(MPQHeader.format_string))
        self.stream.seek(self.header_offset)
        if contents[:4] != MPQ_HEADER_MAGIC:
            raise TypeError
        header = MPQHeader(
            *struct.unpack(MPQHeader.format_string, contents[:struct.calcsize(MPQHeader.format_string)])
        )
        if header.format_version != 0:
            raise NotImplementedError("Burning crusade format not supported.")
        return header

    def _fill_table(self, which: str, instance):
        self.stream.seek(getattr(self.header, self.header.offset_format % which) + 0x200, io.SEEK_SET)
        size = struct.calcsize(instance.format_string)
        contents = self.stream.read(size * getattr(self.header, self.header.entries_format % which))
        contents, rem = _decrypt(
            contents[:16 * getattr(self.header, self.header.entries_format % which)],
            _hash('(%s table)' % which, 'TABLE')
        )

        for i in range(getattr(self.header, self.header.entries_format % which)):
            try:
                yield instance(
                    *struct.unpack(instance.format_string, contents[size * i:size * i + size]), self, tuple(), i
                )
            except Exception as e:
                logging.error(e)
        self.stream.seek(getattr(self.header, self.header.offset_format % which) + 0x200, io.SEEK_SET)

    @property
    def has_listfile(self):
        return self._hash_entry("(listfile)", 0, 0) is not None

    def filename_for_index(self, index: int):
        return _block_index_to_filename[hash(self)].get(index, None)

    def _hash_entry(self, filename: str, locale=0, platform=0) -> typing.Optional[MPQHashEntry]:
        if (filename, locale, platform) in _filename_to_hash_data[hash(self)]:
            return _filename_to_hash_data[hash(self)][filename, locale, platform]
        hash_a = _hash(filename, 'HASH_A')
        hash_b = _hash(filename, 'HASH_B')
        best = None
        for value in self.hash_table:
            if value.name_part_a == hash_a and value.name_part_b == hash_b:
                if value.locale == locale and value.platform == platform:
                    return value
                best = value
        return best

    def read_file(self, filename: str, locale=0, platform=0, reason="direct read") -> typing.Tuple[bytes, set]:
        # todo: find out why 7ff1a2-DotA Allstars v603b\PASBTNBlue_Lightning.blp takes so long

        hash_ = self.test_filename(filename, reason, locale, platform)
        if not hash_:
            return b'', {"Hash not found" + filename.replace('\\', '-').replace('.', '')}

        block = self.block_table[hash_.block_index]

        return block.extract_file(pathlib.Path(filename).name, self)

    def seek_file_to(self, position: FilePosition):
        self.stream.seek(position, 0)

    def tell_file(self) -> FilePosition:
        return FilePosition(self.stream.tell())

    def all_files(self):
        for index in range(len(self.block_table)):
            yield self.filename_for_index(index)

    def has_unknown_files(self):
        return not all(file_ for file_ in self.all_files())


_hash_types = {
    'TABLE_OFFSET': 0,
    'HASH_A': 1,
    'HASH_B': 2,
    'TABLE': 3
}


@functools.lru_cache(maxsize=None)
def _hash(string: str, hash_type: str) -> HashType:
    """Hash a string using MPQ's hash function."""
    seed1 = 0x7FED7FED
    seed2 = 0xEEEEEEEE
    offset = _hash_types[hash_type] << 8

    for ch in string.upper():
        ch = ord(ch)
        value = _crypt_table[offset + ch]
        seed1 = (value ^ (seed1 + seed2)) & 0xFFFFFFFF
        seed2 = ch + seed1 + seed2 + (seed2 << 5) + 0b11 & 0xFFFFFFFF

    return seed1


@functools.lru_cache(maxsize=None)
def _decrypt(data: bytes, key: HashType) -> (bytes, int):
    """Decrypt hash or block table or a sector."""
    seed1 = key
    seed2 = 0xEEEEEEEE
    result = bytearray()

    for i in range(len(data) // 4):
        seed2 += _crypt_table[0x400 + (seed1 & 0xFF)]
        seed2 &= 0xFFFFFFFF
        dat = data[i * 4:i * 4 + 4]
        value, = struct.unpack("<I", dat)
        value = (value ^ (seed1 + seed2)) & 0xFFFFFFFF

        seed1 = ((~seed1 << 21) + 0x11111111) | (seed1 >> 11)
        seed1 &= 0xFFFFFFFF
        seed2 = value + seed2 + (seed2 << 5) + 0b11 & 0xFFFFFFFF

        result += struct.pack("<I", value)
    result += data[len(data) // 4 * 4: (len(data) // 4 * 4) + len(data) % 4]

    return result, len(data) % 4
