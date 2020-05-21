import struct
import typing
import io
import pathlib
import enum
import dataclasses

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


def yield_file_stream(path: pathlib.Path):
    with path.open("rb", buffering=io.DEFAULT_BUFFER_SIZE) as f:
        yield f
        print(path.name, "closed")
        yield


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
    block_size: int
    hash_table_pos: int
    block_table_pos: int
    hash_table_size: int
    block_table_size: int

    @property
    def size_of_each_block_sector(self):
        return 512 * 2 ** self.block_size


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
        0x00000100: "PKWARE compressed file",
        0x00000200: "Various compression",
        0x00010000: "File is encrypted",
        0x00020000: "Decryption key fixed with file offset in archive",
        0x00100000: "File is a patch",
        0x01000000: "Single block file",
        0x02000000: "File is deleted by patch",
        0x04000000: "Each sector of file has CRC",
        0x80000000: "File exists"
    }

    def describe_flags(self):
        return ', '.join(value for key, value in self.flags_table.items() if self.flags & key)

    def __repr__(self):
        dic = dataclasses.asdict(self)
        dic.update({'flags': bin(self.flags)})
        return f"{dic} {self.describe_flags()}"


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
    file: io.BufferedReader = None
    user_data: typing.Optional[MPQUserData] = None
    header: MPQHeader = None
    hash_table: [MPQHashEntry] = dataclasses.field(default_factory=list)
    block_table: [MPQBlockEntry] = dataclasses.field(default_factory=list)

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

    def type_and_offset(self) -> typing.Tuple[ArchiveTypes, int]:
        self.file.seek(0, io.SEEK_SET)
        contents = self.file.peek()
        if contents[:4] == war3magic:
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

    def _fill_table(self, which: str, instance: typing.Type[typing.Union[MPQHashEntry, MPQBlockEntry]]):
        self.file.seek(getattr(self.header, "%s_table_pos" % which) + 0x200, io.SEEK_SET)
        contents = self.file.peek()
        contents = self._decrypt(
            contents[:16 * getattr(self.header, "%s_table_size" % which)], self._hash('(%s table)' % which, 'TABLE')
        )
        hash_size = struct.calcsize(instance.format_string)

        where = getattr(self, "%s_table" % which)

        for i in range(getattr(self.header, "%s_table_size" % which)):
            where.append(instance(
                *struct.unpack(instance.format_string, contents[hash_size*i:hash_size*i+hash_size])
            ))

    def fill_hash_and_block_table(self):
        self._fill_table('hash', MPQHashEntry)
        self._fill_table('block', MPQBlockEntry)

    def w3_filename(self):
        pass

    def done_with_file(self):
        next(self.file_gen)

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
