import struct
import typing
import io
import pathlib
import dataclasses
import zlib
import bz2
import itertools
import logging

import explode
import subprocess

# Complete rewrite of TheSil fork of the eagloflo's mpyq library.
# to Decompress pkware dcl imploded files his explode script is also included.
# c 2020, Zlib/Png License

__version__ = "0.0.1"
write_errors = True

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

    @property
    def was_always_empty(self):
        return self.block_index == 0xFFFFFFFF

    @property
    def was_deleted(self):
        return self.block_index == 0xFFFFFFFE


@dataclasses.dataclass
class MPQBlockEntry(FormattedTuple, format_string="4I"):
    file_position: int
    compressed_size: int
    uncompressed_size: int
    flags: int

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

    ZERO_SIZE: typing.ClassVar = "ZEROSIZE"
    FLAG_NOT_EXISTS: typing.ClassVar = "FLAG_NOT_EXISTS"
    MALFORMED_DCL_CHUNK: typing.ClassVar = "Malformed PKWARE DCL chunk"

    def describe_flags(self):
        return ', '.join(desc for key, (_, desc) in self.flags_table.items() if self.flags & key)

    def __repr__(self):
        dic = dataclasses.asdict(self)
        dic.update({'flags': bin(self.flags)})
        return f"{dic} {self.describe_flags()}"

    def extract_file(self, archive: 'MPQArchive', filename) -> typing.Tuple[bytes, set]:
        errors = set()
        if self.uncompressed_size == 0:
            return b'', {f"{self.ZERO_SIZE} {self!r}"}

        if not self.exists:
            return b'', {f"{self.FLAG_NOT_EXISTS} {self!r}"}

        offset = self.file_position + 0x200
        if archive.file.closed:
            archive.reopen_file()
        archive.file.seek(offset, 0)

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

        sectors, remainder = divmod(self.uncompressed_size, archive.header.sector_size)

        sectors += bool(remainder)
        sectors += bool(self.has_crc)

        if self.other_compressions or self.pkware_imploded:
            positions_data = archive.file.read(struct.calcsize("<I") * (sectors + 1))
            if self.encrypted:
                key = _hash(filename, 'TABLE')
                if self.decrypt_key:
                    key = (key + self.file_position) ^ self.uncompressed_size
                positions_data, rem = _decrypt(positions_data, key - 1)
            positions = struct.unpack('<%dI' % (sectors + 1), positions_data)
            result = bytearray()
            raw_bytes_to_read = archive.file.read(positions[-1])
            for i, (start, end) in enumerate(pairwise([p - positions[0] for p in positions[:-1]] + [positions[-1]])):
                # todo: use a single iterator ?
                to_read = raw_bytes_to_read[start:end]
                rem = "Non encypted"
                errors_ = set()

                if self.encrypted:
                    to_read, rem = _decrypt(to_read, key + i)

                if self.other_compressions:
                    needed_chunk = self.uncompressed_size - len(result)
                    if needed_chunk > archive.header.sector_size:
                        needed_chunk = archive.header.sector_size
                    elif needed_chunk <= archive.header.sector_size:
                        needed_chunk += positions[0]
                    if needed_chunk != (end - start):
                        # todo: we could probably detect that early and simply read it into the result
                        # but we have to be sure that we decrypt every block if it is even possible
                        errors_, uncompress = self._uncompress(to_read, (filename, i, len(positions)), rem)
                    else:
                        uncompress = to_read
                else:  # pkware
                    errors_, uncompress = unblast(to_read)

                result += uncompress
                errors.update(errors_ and {f"{i}: {errors_} {self!r}"})

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
        0x02: ("zlib", lambda x: zlibb(x)),
        # todo: all files in 9496bb-SVP Zombie Survivor Second Map V7 fail to deflate
        0x08: ("pkware", lambda x: unblast(x)),
        0x10: ("bzip2", lambda x: bz2.decompress(x))
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
                logging.error(f"Uncompress error for method {short} - {e}")
                errors.add(self.DECOMPRESSION_ERROR + short)
            except zlib.error as e:
                logging.error(f"Zlib error {short} - {e}")
                errors.add(self.ZLIB_ERROR)
            else:
                continue

            if write_errors:
                filename, part, max_parts = debug_diag
                with open(f"{filename} {part}-{max_parts} {rem} BAD", 'wb') as f:
                    f.write(orig)

            dec = orig
            break

        return errors, dec


def zlibb(val):
    print("zlib", val[:10])
    return zlib.decompress(val, 0)


for k, (prop, desc) in MPQBlockEntry.flags_table.items():
    setattr(MPQBlockEntry, prop, property(lambda instance, key_=k: bool(instance.flags & key_), doc=desc))
del k
del prop
del desc

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
HashType = typing.NewType('HashType', int)


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
        return {MPQBlockEntry.MALFORMED_DCL_CHUNK}, content
    else:
        return set(), rv


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

    def __post_init__(self, keep_open: bool):

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
        hash_size = struct.calcsize(instance.format_string)
        contents = self.file.read(hash_size * getattr(self.header, "%s_table_entries" % which))
        contents, rem = _decrypt(
            contents[:16 * getattr(self.header, "%s_table_entries" % which)], _hash('(%s table)' % which, 'TABLE')
        )
        hash_size = struct.calcsize(instance.format_string)

        where = getattr(self, "%s_table" % which)

        for i in range(getattr(self.header, "%s_table_entries" % which)):
            try:
                where.append(instance(
                    *struct.unpack(instance.format_string, contents[hash_size * i:hash_size * i + hash_size])
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

    NOTFOUND: typing.ClassVar = "NOTFOUND"

    def hash_entry(self, filename, locale=0, platform=0):
        hash_a = _hash(filename, 'HASH_A')
        hash_b = _hash(filename, 'HASH_B')
        best = self.NOTFOUND
        for value in self.hash_table:  # todo: this can be done in O(1)
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

        return block.extract_file(self, pathlib.Path(filename).name)

    def done_with_file(self):
        if yield_file_stream.keep_open:  # this can be used to force the file open
            return
        try:
            next(self.file_gen)
        except StopIteration:
            pass

    def reopen_file(self):
        self.file = self.file_gen.send("reopen")


def _hash(string: str, hash_type: str) -> HashType:
    """Hash a string using MPQ's hash function."""
    hash_types = {
        'TABLE_OFFSET': 0,
        'HASH_A': 1,
        'HASH_B': 2,
        'TABLE': 3
    }
    seed1 = 0x7FED7FED
    seed2 = 0xEEEEEEEE

    for ch in string.upper():
        ch = ord(ch)
        value = _crypt_table[(hash_types[hash_type] << 8) + ch]
        seed1 = (value ^ (seed1 + seed2)) & 0xFFFFFFFF
        seed2 = ch + seed1 + seed2 + (seed2 << 5) + 0b11 & 0xFFFFFFFF

    return seed1


def _decrypt(data: bytes, key: HashType) -> (bytes, int):
    """Decrypt hash or block table or a sector."""
    seed1 = key
    seed2 = 0xEEEEEEEE
    result = bytearray()

    for i in range(len(data) // 4):
        seed2 += _crypt_table[0x400 + (seed1 & 0xFF)]
        seed2 &= 0xFFFFFFFF
        store = bytearray(4)
        dat = data[i * 4:i * 4 + 4]
        value, = struct.unpack("<I", dat)
        value = (value ^ (seed1 + seed2)) & 0xFFFFFFFF

        seed1 = ((~seed1 << 21) + 0x11111111) | (seed1 >> 11)
        seed1 &= 0xFFFFFFFF
        seed2 = value + seed2 + (seed2 << 5) + 0b11 & 0xFFFFFFFF

        result += struct.pack("<I", value)
    result += data[len(data) // 4 * 4 : (len(data) // 4 * 4) + len(data) % 4]

    return result, len(data) % 4
