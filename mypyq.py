import struct
import typing
import io
import pathlib
import enum
import dataclasses
import zlib
import bz2
import itertools


def pairwise(iterable):
    "s -> (s0,s1), (s1,s2), (s2, s3), ..."
    a, b = itertools.tee(iterable)
    next(b, None)
    return zip(a, b)


war3magic = b"HM3W"
mpqUserDataMagic = b"MPQ\x1B"
mpqHeaderMagic = b"MPQ\x1A"

common_files = [
    '(attributes)',
    '(listfile)',
    'war3map.doo',
    'war3map.j',
    'war3map.mmp',
    'war3map.shd',
    'war3map.w3c',
    'war3map.w3e',
    'war3map.w3i',
    'war3map.w3r',
    'war3map.w3u',
    'war3map.wct',
    'war3map.wpm',
    'war3map.wtg',
    'war3map.wts',
    'war3mapMap.blp',
    'war3mapUnits.doo'
]


class ArchiveTypes(enum.Enum):
    w3map = enum.auto()


def yield_file_stream(path: pathlib.Path) -> typing.Generator[io.BufferedReader, typing.Any, None]:
    while True:
        with path.open("rb", buffering=io.DEFAULT_BUFFER_SIZE) as f:
            print(path.name, "opened")
            yield f
            print(path.name, "closed")
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


class ArchiveFormatVersion(enum.Enum):
    Original = 0
    BurningCrusade = 1


@dataclasses.dataclass
class MPQHeader(FormattedTuple, format_string="4s2I2H4I"):
    magic: bytes
    header_size: int
    mpq_size: int
    format_version: ArchiveFormatVersion
    block_size_exp: int
    hash_table_offset: int
    block_table_offset: int
    hash_table_entries: int
    block_table_entries: int

    @property
    def sector_size(self):
        return 512 * 2 ** self.block_size_exp


@dataclasses.dataclass()
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


@dataclasses.dataclass(repr=False)
class MPQBlockEntry(FormattedTuple, format_string="4I"):
    file_position: int
    compressed_size: int
    uncompressed_size: int
    flags: int

    flags_table: typing.ClassVar = {
        0x00000100: {'key': 'pkware_imploded', 'long': "PKWARE compressed file (imploded)"},
        0x00000200: {'key': 'other_compressions', 'long': "Other compression"},
        0x00010000: {'key': 'encrypted', 'long': "File is encrypted"},
        0x00020000: {'key': 'decrypt_key', 'long': "Decryption key fixed with file offset in archive"},
        0x00100000: {'key': 'is_patch', 'long': "File is a patch"},
        0x01000000: {'key': 'single_sector', 'long': "Single block file"},
        0x02000000: {'key': 'deleted', 'long': "File is deleted by patch"},
        0x04000000: {'key': 'has_crc', 'long': "Each sector of file has CRC"},
        0x80000000: {'key': 'exists', 'long': "File exists"}
    }

    def describe_flags(self):
        return ', '.join(value_["long"] for key_, value_ in self.flags_table.items() if self.flags & key_)

    def __repr__(self):
        dic = dataclasses.asdict(self)
        dic.update({'flags': bin(self.flags)})
        return f"{dic} {self.describe_flags()}"


for k, v in MPQBlockEntry.flags_table.items():
    setattr(MPQBlockEntry, v['key'], property(lambda instance, key_=k: bool(instance.flags & key_), doc=v["long"]))
    MPQBlockEntry.__annotations__.update({v['key']: bool})
del k
del v


class PrepareCryptTable:

    def __init_subclass__(cls: typing.ForwardRef('MPQArchive'), **kwargs):
        print("Creating the crypt table")

        cls.crypt_table = [0] * 0x500
        seed = 0x00100001

        for i in range(256):
            index = i
            for _ in range(5):
                seed = (seed * 125 + 0b11) % 0x2AAAAB
                temp1 = (seed & 0xFFFF) << 16

                seed = (seed * 125 + 0b11) % 0x2AAAAB
                temp2 = (seed & 0xFFFF)

                cls.crypt_table[index] = (temp1 | temp2)

                index += 256

        super(**kwargs)


HashType = typing.NewType('HashType', int)


@dataclasses.dataclass
class MPQArchive(PrepareCryptTable):
    path: pathlib.Path = None  # actually required, but made optional so this dc can be inherited from
    header_offset: typing.ClassVar[int] = 0x200
    crypt_table: typing.ClassVar[typing.Dict[int, int]]
    file: typing.ClassVar[io.BufferedReader] = None
    user_data: typing.Optional[MPQUserData] = None
    header: MPQHeader = None
    hash_table: typing.List[MPQHashEntry] = dataclasses.field(default_factory=list)
    block_table: typing.List[MPQBlockEntry] = dataclasses.field(default_factory=list)
    mpq_map_name: bytes = b""
    weird_thing_after_map_name: bytes = b""
    weird_thing_after_map_name_int: int = 0

    def __post_init__(self):

        print(self.path.exists(), self.path.resolve(), self.path.stat())
        if not self.path.exists():
            raise OSError(f"{self.path.resolve()} doesn't appear to be a file.")
        self.filesize = self.path.stat().st_size
        self.file_gen = yield_file_stream(self.path)
        self.file = next(self.file_gen)
        kind, offset = self.type_and_offset()
        self.file.seek(offset)

        # at this point, if we don't find the user data block, we can assume his map is protected
        self.fill_user_data()
        self.fill_header()

        self.fill_hash_and_block_table()

        self.done_with_file()

    def type_and_offset(self) -> typing.Tuple[ArchiveTypes, int]:
        self.file.seek(0, io.SEEK_SET)
        contents = self.file.peek()
        if contents[:4] == war3magic:
            zero_index = contents.index(b'\0', 8)
            self.mpq_map_name = contents[8:zero_index]
            self.weird_thing_after_map_name = contents[zero_index + 1: zero_index + 3]
            self.weird_thing_after_map_name_int = int.from_bytes(self.weird_thing_after_map_name, byteorder='little')
            return ArchiveTypes.w3map, 0x200

    def fill_user_data(self):
        contents = self.file.peek()
        if contents[:4] != mpqUserDataMagic:
            return
        self.user_data = MPQUserData(
            *struct.unpack(MPQUserData.format_string, contents[:struct.calcsize(MPQUserData.format_string)])
        )

    def fill_header(self):
        contents = self.file.peek()
        if contents[:4] != mpqHeaderMagic:
            return
        self.header = MPQHeader(
            *struct.unpack(MPQHeader.format_string, contents[:struct.calcsize(MPQHeader.format_string)])
        )
        if self.header.format_version != 0:
            raise NotImplementedError("Burning crusade format not supported.")

    def _fill_table(self, which: str, instance: typing.Type[typing.Union[MPQHashEntry, MPQBlockEntry]]):
        self.file.seek(getattr(self.header, "%s_table_offset" % which) + 0x200, io.SEEK_SET)
        hash_size = struct.calcsize(instance.format_string)
        contents = self.file.read(hash_size * getattr(self.header, "%s_table_entries" % which))
        contents = self._decrypt(
            contents[:16 * getattr(self.header, "%s_table_entries" % which)], self._hash('(%s table)' % which, 'TABLE')
        )
        hash_size = struct.calcsize(instance.format_string)

        where = getattr(self, "%s_table" % which)

        for i in range(getattr(self.header, "%s_table_entries" % which)):
            try:
                where.append(instance(
                    *struct.unpack(instance.format_string, contents[hash_size * i:hash_size * i + hash_size])
                ))
            except Exception as e:
                print(e)
        self.file.seek(getattr(self.header, "%s_table_offset" % which) + 0x200, io.SEEK_SET)

    def fill_hash_and_block_table(self):
        self._fill_table('hash', MPQHashEntry)
        self._fill_table('block', MPQBlockEntry)

    def w3_filename(self):
        return self.mpq_map_name

    @property
    def has_listfile(self):
        return self.hash_entry("(listfile)", 0, 0) is not self.NOTFOUND

    NOTFOUND: typing.ClassVar = "NOTFOUND"
    ZEROSIZE: typing.ClassVar = "ZEROSIZE"
    BLOCKFLAGNOTEXISTS: typing.ClassVar = "BLOCKFLAGNOTEXISTS"

    def hash_entry(self, filename, locale=0, platform=0):
        hash_a = self._hash(filename, 'HASH_A')
        hash_b = self._hash(filename, 'HASH_B')
        best = self.NOTFOUND
        for value in self.hash_table:
            if value.name_part_a == hash_a and value.name_part_b == hash_b:
                if value.locale == locale and value.platform == platform:
                    return value
                best = value
        return best

    def read_file(self, filename: str, locale=0, platform=0):
        errors = set()

        hash_ = self.hash_entry(filename, locale, platform)
        if hash_ is self.NOTFOUND:
            return b'', {hash_ + filename}

        block = self.block_table[hash_.block_index]

        if block.uncompressed_size == 0:
            return b'', {self.ZEROSIZE}

        if not block.exists:
            return b'', {self.BLOCKFLAGNOTEXISTS}

        offset = block.file_position + 0x200
        if self.file.closed:
            self.reopen_file()
        self.file.seek(offset, 0)

        if block.single_sector:
            if block.other_compressions and block.uncompressed_size > block.compressed_size:
                value = self._uncompress(self.file.read(block.compressed_size))
                if isinstance(value, set):
                    errors.update(value)
            else:
                value = self.file.read(block.uncompressed_size)
            self.done_with_file()
            return value, errors

        sectors, remainder = divmod(block.uncompressed_size, self.header.sector_size)  # why uncompressed
        if remainder:
            sectors += 1

        if block.has_crc:
            sectors += 1

        if block.other_compressions or block.pkware_imploded:
            # todo: fetch positions of each compressed bit
            positions_data = self.file.read(struct.calcsize("<I") * (sectors + 1))
            if block.encrypted:
                key = self._hash(filename, 'TABLE')
                if block.decrypt_key:
                    key = (key + block.file_position) ^ block.uncompressed_size
                positions_data = self._decrypt(positions_data, key - 1)
            positions = struct.unpack('<%dI' % (sectors + 1), positions_data)
            result = bytearray()
            raw_bytes_to_read = self.file.read(positions[-1])
            i = 0
            for start, end in pairwise([p - positions[0] for p in positions[:-1]] + [positions[-1]]):
                to_read = raw_bytes_to_read[start:end]
                if block.encrypted:
                    to_read = self._decrypt(to_read, key + i)
                uncompress = self._uncompress(to_read, force_pkware=block.pkware_imploded)
                if not isinstance(uncompress, set):
                    result += uncompress
                else:
                    result += to_read
                    errors.update(uncompress)
                i += 1
            value = bytes(result)
        else:
            value = self.file.read(block.uncompressed_size)

        self.done_with_file()
        return value, errors

    UNSUPPORTED_COMPRESSION: typing.ClassVar = "UNSUPPORTED_COMPRESSION"
    ZLIB_ERROR: typing.ClassVar = "ZLIB_ERROR"
    DECOMPRESSION_ERROR: typing.ClassVar = "DECOMPRESSION_ERROR"
    compressions: typing.ClassVar = {
        0x40: {"short": "monowav", "desc": "IMA ADPCM mono (.wav)", "meth": lambda x: -1},  # todo: implement
        0x80: {"short": "stereowav", "desc": "IMA ADPCM stereo (.wav)", "meth": lambda x: -1},  # todo: implement
        0x01: {"short": "huffman", "desc": "Huffman encoded", "meth": lambda x: -1},  # todo: implement
        0x02: {"short": "zlib", "desc": "Deflated(see ZLib)", "meth": lambda x: zlib.decompress(x)},
        0x08: {"short": "pkware", "desc": "Imploded(see PKWare Data Compression Library) (Should be impossible ?)", "meth": lambda x: -1},  # todo: implement
        0x10: {"short": "bzip2", "desc": "BZip2 compressed(see BZip2)", "meth": lambda x: bz2.decompress(x)}
    }

    def _uncompress(self, raw: bytes, force_pkware=False) -> typing.Union[set, bytes]:
        compressions = raw[0]
        if force_pkware:
            compressions |= 0x08
        data = raw[1:]
        errors = set()
        for mask, values in reversed([*self.compressions.items()]):
            if compressions & mask:
                try:
                    data = values["meth"](data)
                except OSError as e:
                    print(f"Uncompress error for method {values['desc']} - {e}")
                    errors.add(self.DECOMPRESSION_ERROR + values['short'])
                    continue
                except zlib.error as e:
                    print(f"Zlib error {values['desc']} - {e}")
                    errors.add(self.ZLIB_ERROR)
                    continue
                if data == -1:
                    return {self.UNSUPPORTED_COMPRESSION + values['short']}

        return errors or data

    def done_with_file(self):
        try:
            next(self.file_gen)
        except StopIteration:
            pass

    def reopen_file(self):
        self.file = self.file_gen.send("reopen")

    @classmethod
    def _hash(cls, string: str, hash_type: str) -> HashType:
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
            value = cls.crypt_table[(hash_types[hash_type] << 8) + ch]
            seed1 = (value ^ (seed1 + seed2)) & 0xFFFFFFFF
            seed2 = ch + seed1 + seed2 + (seed2 << 5) + 0b11 & 0xFFFFFFFF

        return seed1

    @classmethod
    def _decrypt(cls, data: bytes, key: HashType):
        """Decrypt hash or block table or a sector."""
        seed1 = key
        seed2 = 0xEEEEEEEE
        result = io.BytesIO()

        for i in range(len(data) // 4):
            seed2 += cls.crypt_table[0x400 + (seed1 & 0xFF)]
            seed2 &= 0xFFFFFFFF
            value, = struct.unpack("<I", data[i * 4:i * 4 + 4])
            value = (value ^ (seed1 + seed2)) & 0xFFFFFFFF

            seed1 = ((~seed1 << 21) + 0x11111111) | (seed1 >> 11)
            seed1 &= 0xFFFFFFFF
            seed2 = value + seed2 + (seed2 << 5) + 0b11 & 0xFFFFFFFF

            result.write(struct.pack("<I", value))

        # append any remaining data
        rem = len(data) % 4
        if rem:
            result.write(data[-rem:])

        return result.getvalue()
