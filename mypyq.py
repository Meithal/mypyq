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

import explode
import subprocess

# Complete rewrite of TheSil fork of the eagloflo's mpyq library.
# to Decompress pkware dcl imploded files his explode script is also included.
# c 2020, Zlib/Png License

__version__ = "0.0.1"
write_errors = False
HashType = typing.NewType('HashType', int)


def pairwise(iterable):
    """s -> (s0,s1), (s1,s2), (s2, s3), ..."""
    a, b = itertools.tee(iterable)
    next(b, None)
    return zip(a, b)


WAR3MAGIC = b"HM3W"
MPQ_USER_DATA_MAGIC = b"MPQ\x1B"
MPQ_HEADER_MAGIC = b"MPQ\x1A"


def yield_file_stream(path: pathlib.Path, keep_open: bool) \
        -> typing.Generator[io.BufferedReader, typing.Any, None]:
    yield_file_stream.keep_open = keep_open
    while True:
        with path.open("rb", buffering=io.DEFAULT_BUFFER_SIZE) as f:
            logging.info(f"{path.name} opened")
            yield f
            logging.info(f"{path.name} closed")
        while True:
            cont = yield
            if cont == "reopen":
                break


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

    @property
    def sector_size(self):
        return 512 << self.block_size_exp


@dataclasses.dataclass
class MPQHashEntry(FormattedTuple, format_string="2IHBBI"):
    name_part_a: int
    name_part_b: int
    locale: int
    platform: int
    reserved: int
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
    file_position: int
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

        positions_data = archive.file.read(struct.calcsize("<I") * (sectors + 1))
        if isinstance(decrypt_key, int):
            positions_data, rem = _decrypt(positions_data, HashType(decrypt_key))
        positions = struct.unpack('<%dI' % (sectors + 1), positions_data)
        self.positions = positions

        archive.seek_file_to(file_pos)
        return positions

    def __repr__(self):
        dic = dataclasses.asdict(self)
        dic.update({'flags': bin(self.flags)})
        filename = self.archive.filename_for_index(self.index) or "**No name found**"

        return f"{dic} - {filename} - {self.describe_flags()} Positions: {self.sectors_positions(self.archive)}"

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
                errors_, value = self._uncompress(archive.file.read(self.compressed_size), (filename, "whole"))
                errors.update(errors_ and {f"single: {errors_} {self!r}"})
            else:
                value = archive.file.read(self.uncompressed_size)
            archive.done_with_file()
            if errors:
                errors.add(repr(self))
            return value, errors

        positions = self.sectors_positions(archive, key and key - 1)

        if self.other_compressions or self.pkware_imploded:
            result = bytearray()
            raw_bytes_to_read = archive.file.read(positions[-1])
            # for i, (start, end) in enumerate(pairwise([p - positions[0] for p in positions[:-1]] + [positions[-1]])):
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
                    # elif needed_chunk <= archive.header.sector_size:
                    #     needed_chunk += positions[0]
                    if needed_chunk != (end - start):
                        # todo: we could probably detect that early and simply read it into the result
                        # but we have to be sure that we decrypt every block if it is even possible
                        errors_, uncompress = self._uncompress(to_read, (filename, i+1, len(positions)-1), rem)
                    else:
                        uncompress = to_read
                else:  # pkware
                    errors_, uncompress = unblast(to_read)

                result += uncompress
                errors.update(errors_ and {f"{i+1} on {len(positions)-1}: {errors_} {self!r}"})

            value = bytes(result)
        else:
            if self.encrypted:
                raise ValueError("Should never happen.")
            value = archive.file.read(self.uncompressed_size)

        archive.done_with_file()
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
                errors.add(self.DECOMPRESSION_ERROR + short + e)
            except zlib.error as e:
                logging.error(f"Zlib error {short} - {e} for {debug_diag}")
                errors.add(self.ZLIB_ERROR + e)
            else:
                continue

            if write_errors:
                filename, part, max_parts = debug_diag
                with open(f"{filename} {part}-{max_parts} {rem} BAD", 'wb') as f:
                    f.write(orig)

            dec = orig
            break

        return errors, dec


def init_mpq_block_accessors():
    for k, (prop, desc) in MPQBlockEntry.flags_table.items():
        setattr(MPQBlockEntry, prop, property(lambda instance, key_=k: bool(instance.flags & key_), doc=desc))


init_mpq_block_accessors()

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

_block_index_to_filename = {}
_filename_to_hash_data = {}


@dataclasses.dataclass
class MPQArchive:
    path: pathlib.Path = None  # actually required, but made optional so this dc can be inherited from
    header_offset: typing.ClassVar[int] = 0x200
    file: typing.ClassVar[io.BufferedReader] = None
    user_data: typing.Optional[MPQUserData] = None
    header: MPQHeader = None
    hash_table: typing.List[MPQHashEntry] = dataclasses.field(default_factory=list)
    block_table: typing.List[MPQBlockEntry] = dataclasses.field(default_factory=list)
    mpq_map_name: bytes = b""
    keep_open: dataclasses.InitVar[bool] = False
    filenames_to_test: dataclasses.InitVar[tuple] = tuple()

    def __post_init__(self, keep_open: bool, filenames_to_test: typing.Tuple[str]=tuple()):

        if filenames_to_test is None:
            filenames_to_test = []
        if not self.path.exists():
            raise OSError(f"{self.path.resolve()} doesn't appear to be a file.")
        self.filesize = self.path.stat().st_size
        self.file_gen = yield_file_stream(self.path, keep_open)
        self.file = next(self.file_gen)
        self.parse_w3_header()
        self.file.seek(0x200)

        # at this point, if we don't find the user data block, we can assume this map is protected.
        self.fill_user_data()
        self.fill_header()

        self.fill_hash_and_block_table()

        self.done_with_file()

        _block_index_to_filename[self] = {}
        _filename_to_hash_data[self] = {}
        for filename in filenames_to_test:
            hash_entry_ = self.hash_entry(filename)
            if isinstance(hash_entry_, MPQHashEntry):
                _block_index_to_filename[self][hash_entry_.block_index] = filename, hash_entry_.locale, hash_entry_.platform
                _filename_to_hash_data[self][filename, hash_entry_.locale, hash_entry_.platform] = hash_entry_

    def __hash__(self):
        return hash(str(self.path))

    def insight(self):
        number_of_hash_entires = self.header.hash_table_entries
        used_hash_table_entries = len([h for h in self.hash_table if not (h.was_deleted or h.was_always_empty)])
        number_of_block_entires = self.header.block_table_entries
        block_indices = [h.block_index for h in self.hash_table if not (h.was_deleted or h.was_always_empty)]
        blocks = []
        for block_index in [h.block_index for h in self.hash_table if not (h.was_deleted or h.was_always_empty)]:
            block = self.block_table[block_index]
            blocks.append(repr(block))
        return {
            'number_of_hash_entires': number_of_hash_entires,
            'used_hash_table_entries': used_hash_table_entries,
            'number_of_block_entires': number_of_block_entires,
            'sector_size': self.header.sector_size,
            'block_indices': block_indices,
            'blocks': blocks
        }

    def parse_w3_header(self):
        self.file.seek(0, io.SEEK_SET)
        contents = self.file.peek()
        if contents[:4] == WAR3MAGIC:
            zero_index = contents.index(b'\0', 8)
            self.mpq_map_name = contents[8:zero_index]

    def fill_user_data(self):
        contents = self.file.peek()
        if contents[:4] != MPQ_USER_DATA_MAGIC:
            return
        self.user_data = MPQUserData(
            *struct.unpack(MPQUserData.format_string, contents[:struct.calcsize(MPQUserData.format_string)])
        )

    def fill_header(self):
        contents = self.file.peek()
        if contents[:4] != MPQ_HEADER_MAGIC:
            return
        self.header = MPQHeader(
            *struct.unpack(MPQHeader.format_string, contents[:struct.calcsize(MPQHeader.format_string)])
        )
        if self.header.format_version != 0:
            raise NotImplementedError("Burning crusade format not supported.")

    def _fill_table(self, which: str, instance):
        self.file.seek(getattr(self.header, "%s_table_offset" % which) + 0x200, io.SEEK_SET)
        size = struct.calcsize(instance.format_string)
        contents = self.file.read(size * getattr(self.header, "%s_table_entries" % which))
        contents, rem = _decrypt(
            contents[:16 * getattr(self.header, "%s_table_entries" % which)], _hash('(%s table)' % which, 'TABLE')
        )

        where = getattr(self, "%s_table" % which)

        for i in range(getattr(self.header, "%s_table_entries" % which)):
            try:
                where.append(instance(
                    *struct.unpack(instance.format_string, contents[size * i:size * i + size]), self, tuple(), i
                ))
            except Exception as e:
                logging.error(e)
        self.file.seek(getattr(self.header, "%s_table_offset" % which) + 0x200, io.SEEK_SET)

    def fill_hash_and_block_table(self):
        if not self.header:
            return

        self._fill_table('hash', MPQHashEntry)
        self._fill_table('block', MPQBlockEntry)

    def w3_filename(self):
        return self.mpq_map_name

    @property
    def has_listfile(self):
        return self.hash_entry("(listfile)", 0, 0) is not self.NOTFOUND

    def filename_for_index(self, index: int):
        return _block_index_to_filename[self].get(index, None)

    NOTFOUND: typing.ClassVar = "NOTFOUND"

    def hash_entry(self, filename, locale=0, platform=0):
        if (filename, locale, platform) in _filename_to_hash_data[self]:
            return _filename_to_hash_data[self][filename, locale, platform]
        hash_a = _hash(filename, 'HASH_A')
        hash_b = _hash(filename, 'HASH_B')
        best = self.NOTFOUND
        for value in self.hash_table:
            if value.name_part_a == hash_a and value.name_part_b == hash_b:
                if value.locale == locale and value.platform == platform:
                    return value
                best = value
        return best

    def read_file(self, filename: str, locale=0, platform=0) -> typing.Tuple[bytes, set]:
        # todo: find out why 7ff1a2-DotA Allstars v603b\PASBTNBlue_Lightning.blp takes so long

        hash_ = self.hash_entry(filename, locale, platform)
        if hash_ is self.NOTFOUND:
            return b'', {hash_ + filename.replace('\\', '-').replace('.', '')}

        block = self.block_table[hash_.block_index]

        return block.extract_file(pathlib.Path(filename).name, self)

    def done_with_file(self):
        if yield_file_stream.keep_open:  # this can be used to force the file open
            return
        try:
            next(self.file_gen)
        except StopIteration:
            pass

    def reopen_file(self):
        self.file = self.file_gen.send("reopen")

    def seek_file_to(self, position):
        if self.file.closed:
            self.reopen_file()
        self.file.seek(position, 0)

    def tell_file(self):
        if self.file.closed:
            self.reopen_file()
        return self.file.tell()


_hash_types = {
    'TABLE_OFFSET': 0,
    'HASH_A': 1,
    'HASH_B': 2,
    'TABLE': 3
}


@functools.lru_cache
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


@functools.lru_cache
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
