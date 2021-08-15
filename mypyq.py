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
import math
import time
import operator
import _huffman

import explode

__version__ = "0.0.1"
__author__ = "github.com/Meithal"

listfile_name = b'(listfile)'
attributes_name = b'(attributes)'
signature_name = b'(signature)'

_HashType = typing.NewType('_HashType', int)
"Hashed version of a string, that MPQ can work with."
_FilePosition = typing.NewType('_FilePosition', int)
"An offset in the stream."
HashTableEntries = typing.NewType('HashTableEntries', int)
"A number that is a power of 2."
FilePath = typing.NewType('FilePath', bytes)
r"""
A full qualified path that is a valid windows path, for example `Foo\\Bar\\file.txt`.
Such a path is used as an entry key to extract a file from a MPQ.
For multi-OS compatibility, only backslashes have been observed as directory separators
and every implementation capitalizes the letters of the path to
allow unpacking on case insensitive file systems.
"""


@functools.lru_cache(maxsize=None)
def _closest_power_of_two(x) -> HashTableEntries:
    return HashTableEntries(math.ceil(math.log(x, 2)) * 2)


def _pairwise(iterable):  # from python manual
    """s -> (s0,s1), (s1,s2), (s2, s3), ..."""
    a, b = itertools.tee(iterable)
    next(b, None)
    return zip(a, b)


_MPQ_USER_DATA_MAGIC = b"MPQ\x1B"
_MPQ_HEADER_MAGIC = b"MPQ\x1A"


class _ABHashes(dict):
    def __missing__(self, key_):
        return key_


a_and_b_hashes_to_path_names: typing.Dict[typing.Tuple[int, int], bytes] = _ABHashes()


class _FormattedTuple:
    format_string: typing.ClassVar[str]

    @classmethod
    def __init_subclass__(cls, format_string, **kwargs):
        cls.format_string = format_string

        super().__init_subclass__(**kwargs)


@dataclasses.dataclass()
class _MPQUserData(_FormattedTuple, format_string="4s3I"):
    magic: bytes
    max_size: int
    offset_to_header: int
    this_size: int


@dataclasses.dataclass
class MPQHeader(_FormattedTuple, format_string="4s2I2H4I"):
    magic: bytes
    header_size: int
    mpq_size: int
    format_version: int
    block_size_exp: int
    hash_table_offset: int
    block_table_offset: int
    hash_table_entries: HashTableEntries
    block_table_entries: int

    offset_format: typing.ClassVar[bytes] = b"%s_table_offset"
    entries_format: typing.ClassVar[bytes] = b"%s_table_entries"

    @property
    def sector_size(self):
        return 512 << self.block_size_exp


@dataclasses.dataclass
class MPQHashEntry(_FormattedTuple, format_string="2IHHI"):
    name_part_a: int
    name_part_b: int
    locale: int
    platform: int
    block_index: int

    @property
    def was_always_empty(self):
        return self.block_index == 0xFFFFFFFF

    @property
    def was_deleted(self):
        return self.block_index == 0xFFFFFFFE


@dataclasses.dataclass
class MPQBlockEntry(_FormattedTuple, format_string="4I"):
    """
    A packed file with a locale and a platform.
    Size and flags tell how to uncompress the file.
    """
    file_position: _FilePosition
    compressed_size: int
    uncompressed_size: int
    flags: int
    errors: dataclasses.field(default_factory=list) = None

    # dummies replaced by getter/setter properties, to shut lint warnings.
    pkware_imploded: typing.ClassVar[bool]
    other_compressions: typing.ClassVar[bool]
    encrypted: typing.ClassVar[bool]
    decrypt_key: typing.ClassVar[bool]
    is_patch: typing.ClassVar[bool]
    single_sector: typing.ClassVar[bool]
    deleted: typing.ClassVar[bool]
    has_crc: typing.ClassVar[bool]
    exists: typing.ClassVar[bool]

    flags_table: typing.ClassVar[typing.Dict] = {
        0x00000100: ('pkware_imploded', "PKWare compressed file (imploded)."),
        0x00000200: ('other_compressions', "Other compression than PKWare is used."),
        0x00010000: ('encrypted', "File is encrypted from its name (without path)."),
        0x00020000: ('decrypt_key', "Additional layer of encryption from offset in "
                                    "archive and final file size."),
        0x00100000: ('is_patch', "File is a patch."),
        0x01000000: ('single_sector', "Single block file."),
        0x02000000: ('deleted', "File is replaced by patch."),
        0x04000000: ('has_crc', "Each sector of file has CRC."),
        0x80000000: ('exists', "Block is a file and not empty space.")
    }

    def __post_init__(self):
        self.errors = []

    def __repr__(self):
        dic = dataclasses.asdict(self)
        dic.update({'flags': bin(self.flags)})

        descriptions = ', '.join(
            desc for key, (_, desc) in self.flags_table.items() if self.flags & key
        )

        return f"{dic} - {descriptions} "

    def pack_tuple(self):
        return self.file_position, self.compressed_size, self.uncompressed_size, self.flags

    def sectors_positions(
        self, stream: typing.BinaryIO, sector_size: int,
        *, decrypt_key: _HashType = None, offset=0
    ):
        if self.single_sector:
            return [0, self.compressed_size]

        if not self.pkware_imploded and not self.other_compressions:
            return [0, self.uncompressed_size]  # potentially malicious

        sectors, remainder = divmod(self.uncompressed_size, sector_size)

        sectors += bool(remainder)
        sectors += bool(self.has_crc)

        file_pos = stream.tell()
        stream.seek(self.file_position + offset)

        positions_data = stream.read(struct.calcsize("<i") * (sectors + 1))
        # an extra sector has total file size

        if decrypt_key is not None:
            positions_data = _decrypt(positions_data, decrypt_key)

        positions = struct.unpack('<%di' % (sectors + 1), positions_data)

        stream.seek(file_pos)

        if positions[-1] != self.compressed_size:
            self.errors.append(self.MALICIOUS_SECTOR_DATA)
            # attempt to recover file despite a malicious sector data
            if len(positions) > 2:
                # if self.pkware_imploded:
                #     content = stream.read(self.compressed_size)
                #     prob = 0
                #     for i in range(len(content) - 1):
                #         try:
                #             explode.explode(content)
                #             # assert content[i] == 0 and 4 <= content[i+1] < 7
                #         except Exception:
                #             continue
                #         else:
                #             prob += 1
                raise NotImplementedError("Implement this.")
            if any(map(lambda x: x > self.compressed_size, positions)):
                # single sector is set to False yet the block doesn't have any sector data
                positions = [0, self.compressed_size]
            else:
                # positions are just completely gibberish
                len_position_data = struct.calcsize("<i") * (sectors + 1)
                positions = [len_position_data, len_position_data + self.compressed_size]

        return positions

    MALICIOUS_SECTOR_DATA: typing.ClassVar[str] = "MALICIOUS_SECTOR_DATA"

    def extractable(self, filename=None):
        return not (not filename and self.encrypted)

    @staticmethod
    def _need_to_decompress(decompressed_so_far, remaining, sector_size):
        if decompressed_so_far + 2 > sector_size:
            return False
        if decompressed_so_far + 2 > remaining:
            return False
        # if remaining > sector_size and decompressed_so_far + 2 < sector_size:
        #     return True
        return True

    def extract_file(
        self, stream: typing.BinaryIO, sector_size: int, 
        filename: bytes = b'',offset=0
    ) -> bytes:
        if self.uncompressed_size == 0:
            return b''

        if not self.exists:
            return b''

        if not self.extractable(filename):
            return b''

        stream.seek(self.file_position + offset)

        key = None
        if self.encrypted:
            key = _hash(filename, 'TABLE')
            if self.decrypt_key:
                key = (key + self.file_position) ^ self.uncompressed_size

        positions = self.sectors_positions(
            stream, sector_size, decrypt_key=key and key - 1, offset=offset
        )

        methods = []
        if self.uncompressed_size > self.compressed_size and self.pkware_imploded:
            methods = [("explode", explode.explode)]

        result = bytearray()
        raw_bytes_to_read = stream.read(positions[-1])

        for i, (start, end) in enumerate(_pairwise(positions)):
            to_read = raw_bytes_to_read[start:end]

            if self.encrypted:
                to_read = _decrypt(to_read, _HashType(key + i))

            if self.other_compressions and self._need_to_decompress(
                    decompressed_so_far=len(to_read),
                    remaining=self.uncompressed_size - len(result),
                    sector_size=sector_size):
                methods = self._uncompress(to_read[0])
                to_read = to_read[1:]

            # if we can gain space by decompression
            for desc, method in methods:
                if self._need_to_decompress(
                        decompressed_so_far=len(to_read),
                        remaining=self.uncompressed_size - len(result),
                        sector_size=sector_size):
                    try:
                        to_read = method(to_read)
                    except Exception as e:
                        self.errors.append(e)
                        logging.exception(f"Error when decompressing a chunk of {filename} with "
                                          f"method {desc}, content: {str(to_read)}")
                        return bytes(raw_bytes_to_read)

                result += to_read


        return bytes(result)

    compressions: typing.ClassVar[dict] = {
        # 0x20: ("sparse", lambda x: x),  # todo: implement
        0x40: ("monowav", _huffman.monowav),  # lambda x: audioop.adpcm2lin(x, 1, None)[0]),
        0x80: ("stereowav", _huffman.stereowav),  # lambda x: audioop.adpcm2lin(x, 2, None)[0]),
        0x01: ("huffman", _huffman.uncompress),
        0x02: ("zlib", zlib.decompress),
        0x08: ("pkware", explode.explode),
        0x10: ("bzip2", bz2.decompress)
    }

    def _uncompress(self, query: int) -> list:
        ret = []
        for mask, (short, meth) in reversed([*self.compressions.items()]):
            if query & mask:
                ret.append((short, meth))
                query ^= mask
        if query != 0:
            self.errors.append(f"Wrongly assumed compression {bin(query)}")
            raise NotImplementedError(f"Wrongly assumed compression {bin(query)}")
        return ret

    def pack(self, contents: bytes, destination: typing.BinaryIO, sector_size: int):
        compressed = zlib.compress(contents)

        self.other_compressions = True
        self.exists = True
        self.uncompressed_size = len(contents)
        self.compressed_size = len(compressed)
        self.file_position = _FilePosition(destination.tell())

        if self.uncompressed_size <= sector_size:
            self.single_sector = True
            if self.compressed_size < self.uncompressed_size:
                destination.write(b'\x02')
                destination.write(compressed)
            else:
                self.other_compressions = False
                destination.write(contents)
        else:
            offsets = [0]
            buffer = io.BytesIO()
            for i in range(1 + (len(compressed) // sector_size)):
                chunk = zlib.compress(contents[i * sector_size: (i + 1) * sector_size])
                buffer.write(b'\x02')
                buffer.write(chunk)
                offsets.append(len(chunk))
            destination.write(struct.pack(
                "<%dI" % (len(offsets) + 1), offsets + [self.uncompressed_size])
            )
            destination.write(buffer.getvalue())


def _init_mpq_block_accessors():
    for k, (prop, desc) in MPQBlockEntry.flags_table.items():
        setattr(
            MPQBlockEntry, prop, property(
                lambda instance, key_=k: bool(instance.flags & key_),
                lambda instance, value, key_=k: setattr(
                    instance, 'flags', getattr(instance, 'flags') ^ (
                            bool(value) and not (getattr(instance, 'flags') & key_) and key_
                            or getattr(instance, 'flags') & key_ and key_
                    )  # Bitflip the correct bit with its antivalue or value
                    # whether we want it to become 1 or 0
                ),
                doc=desc
            )
        )


_init_mpq_block_accessors()


class MPQArchive:
    start_pad: typing.ClassVar[int] = 0x200
    raw_pre_archive: bytes
    user_data: typing.Optional[_MPQUserData]
    header: MPQHeader
    hash_table: typing.List[MPQHashEntry]
    block_table: typing.List[MPQBlockEntry]
    tested_filenames: set
    stream: typing.BinaryIO
    boot_file_path: pathlib.Path

    lang_id: typing.ClassVar[dict] = {
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

    def __init__(self,
                 boot_stream: typing.BinaryIO = None,
                 *,
                 filenames_to_test: typing.Tuple[bytes] = tuple(),
                 boot_file_path: typing.Optional[typing.Union[str, pathlib.PurePath]] = None,
                 start_pad=None,
                 print_listfile=False
                 ):
        """If given a stream, we don't close it"""

        self.hash_table = []
        self.block_table = []
        self.start_pad = start_pad
        self.tested_filenames = set()
        self.stream = None
        self.boot_file_path = None

        if boot_stream:
            stream = boot_stream
            self.stream = boot_stream
        elif boot_file_path:
            self.boot_file_path = pathlib.Path(boot_file_path)
            stream = open(boot_file_path, 'rb')
        else:
            raise RuntimeError("Neither a stream nor a filepath has been provided.")

        if start_pad is None:
            self.start_pad = find_mpq_header(stream)

        self.load_existing_stream(stream, filenames_to_test)  # delay until it is really needed?

        if boot_file_path:
            stream.close()

        if print_listfile:
            if listfile_name not in self:
                logging.info("Asked listfile but none found.")
            else:
                file_, _ = self.read_file(
                    FilePath(listfile_name),
                    reason="asked to print listfile"
                )
                logging.info(file_)

    def __contains__(self, item):
        return self._hash_entry(item, 0, 0) is not None

    def load_existing_stream(self, stream, filenames_to_test):
        self.raw_pre_archive = stream.read(self.start_pad)
        stream.seek(self.start_pad)

        # at this point, if we don't find the user data block, we can assume this map is protected.
        self._fill_user_data(stream)
        self.header = self._fill_header(stream)

        self.hash_table = list(self._fill_table(b'hash', MPQHashEntry, stream))
        self.block_table = list(self._fill_table(b'block', MPQBlockEntry, stream))

        for filename in filenames_to_test:
            self.test_filename(filename, "list given at init")

    def iter_hashes(self) -> typing.Iterator[MPQHashEntry]:
        for h in self.hash_table:
            if not (h.was_deleted or h.was_always_empty):
                yield h

    def test_filename(self, name: FilePath, reason: str, locale=0, platform=0):
        hash_entry_ = self._hash_entry(name, locale, platform)

        if name.decode() not in map(operator.itemgetter(2), self.tested_filenames):
            self.tested_filenames.add((bool(hash_entry_), time.time_ns(), name.decode(), reason))

        maybe_better = None
        if b'\\\\' in name:
            maybe_better = self.test_filename(
                FilePath(name.replace(b'\\\\', b'\\')),
                "recursively try to remove repeated double slashes",
                locale,
                platform
            )

        if maybe_better is not None and hash_entry_ is None:
            return maybe_better
        else:
            return hash_entry_

    def _fill_user_data(self, stream):
        contents = stream.read(struct.calcsize(_MPQUserData.format_string))
        stream.seek(self.start_pad)

        if contents[:4] != _MPQ_USER_DATA_MAGIC:
            return

        self.user_data = _MPQUserData(
            *struct.unpack(
                _MPQUserData.format_string,
                contents[:struct.calcsize(_MPQUserData.format_string)]
            )
        )

    def _fill_header(self, stream):
        contents = stream.read(struct.calcsize(MPQHeader.format_string))
        stream.seek(self.start_pad)

        if contents[:4] != _MPQ_HEADER_MAGIC:
            raise TypeError

        header = MPQHeader(
            *struct.unpack(
                MPQHeader.format_string,
                contents[:struct.calcsize(MPQHeader.format_string)]
            )
        )

        if header.format_version != 0:
            raise NotImplementedError("Burning crusade format not supported.")

        return header

    def _fill_table(self, which: bytes, instance, stream):
        stream.seek(
            getattr(
                self.header,
                (self.header.offset_format % which).decode()
            ) + self.start_pad, io.SEEK_SET
        )

        size = struct.calcsize(instance.format_string)
        contents = stream.read(
            size * getattr(self.header, (self.header.entries_format % which).decode())
        )
        contents = _decrypt(
            contents[:16 * getattr(
                self.header, (self.header.entries_format % which).decode()
            )],
            _hash(b'(%s table)' % which, 'TABLE')
        )

        for i in range(getattr(
                self.header, (self.header.entries_format % which).decode()
        )):
            try:
                yield instance(
                    *struct.unpack(instance.format_string, contents[size * i:size * i + size])
                )
            except Exception as e:
                logging.error(e)

        stream.seek(
            getattr(
                self.header,
                (self.header.offset_format % which).decode()
            ) + self.start_pad, io.SEEK_SET
        )

    @property
    def has_listfile(self):
        return FilePath(b"(listfile)") in self

    def _hash_entry(self, filename: FilePath, locale=0, platform=0) \
            -> typing.Optional[MPQHashEntry]:
        hash_a, hash_b = filename_to_hash_pair(filename)
        index = index_for_path(filename, self.header.hash_table_entries)

        best = None
        for value in (self.hash_table[index:] + self.hash_table[:index]):
            if value.name_part_a == hash_a and value.name_part_b == hash_b:
                best = value
                if value.locale == locale and value.platform == platform:
                    break

        return best

    def read_file(self, filename: FilePath,
                  *, locale=0, platform=0, reason="direct read", stream=None
                  ) -> typing.Tuple[bytes, list]:
        """Extract the `filename` from the same stream that was used to fill
        up header and block data previously. We pass in a new stream to not keep
        the file always open and to not have to parse header, hash and block
        data every time.
        The reason is where we have found the file name (listfile, guess, mentioned...)
        it can help to decypher MPQ contents with incomplete listfiles for future reads.

        Returns a tuple with file contents as bytes and a set that has every
        error encountered trying to read the file or an empty set if the
        read happened without errors."""

        ad_hoc = False
        if not stream and self.stream:
            stream = self.stream
        elif not stream and self.boot_file_path:
            stream = self.boot_file_path.open('rb')
            ad_hoc = True

        hash_ = self.test_filename(filename, reason, locale, platform)
        if not hash_:
            if ad_hoc:
                stream.close()
            return b'', ["Hash not found " + filename.decode()]

        block = self.block_table[hash_.block_index]

        contents = block.extract_file(
            stream, self.header.sector_size,
            filename=pathlib.PurePath(filename.decode()).name.encode(),
            offset=self.start_pad
        )
        if block.errors:
            logging.warning("Problem extracting %s : %s", filename, str(block.errors))
        if ad_hoc:
            stream.close()
        return contents, block.errors

    def all_files(self):
        for hash_ in self.hash_table:
            if hash_.was_deleted or hash_.was_always_empty:
                continue
            yield a_and_b_hashes_to_path_names[(hash_.name_part_a, hash_.name_part_b)]

    def unknown_files(self):
        return [file_ for file_ in self.all_files() if isinstance(file_, tuple)]

    def can_be_extracted(self, filename: bytes):
        hash_ = self._hash_entry(FilePath(filename))
        block = self.block_table[hash_.block_index]
        return block.extractable(filename)


def find_mpq_header(stream: typing.BinaryIO):
    orig = stream.tell()
    found = None

    while True:
        ct = stream.read(4)
        if ct == _MPQ_HEADER_MAGIC:
            found = stream.tell() - 4
            break
    stream.seek(orig)
    return found


_hash_types = {
    'TABLE_OFFSET': 0,
    'HASH_A': 1,
    'HASH_B': 2,
    'TABLE': 3
}

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


@functools.lru_cache(maxsize=None)
def filename_to_hash_pair(filename: bytes) -> typing.Tuple[_HashType, _HashType]:
    hash_a = _hash(filename, 'HASH_A')
    hash_b = _hash(filename, 'HASH_B')
    a_and_b_hashes_to_path_names[(hash_a, hash_b)] = filename
    return hash_a, hash_b


@functools.lru_cache(maxsize=None)
def _hash(string: bytes, hash_type: str) -> _HashType:
    """Hash a string using MPQ's hash function."""
    seed1 = 0x7FED7FED
    seed2 = 0xEEEEEEEE
    offset = _hash_types[hash_type] << 8
    string = string.decode('latin')

    for ch in string.upper():
        ch = ord(ch)
        value = _crypt_table[offset + ch]
        seed1 = (value ^ (seed1 + seed2)) & 0xFFFFFFFF
        seed2 = ch + seed1 + seed2 + (seed2 << 5) + 0b11 & 0xFFFFFFFF

    return seed1


def _decrypt(data: bytes, key: _HashType) -> bytearray:
    """Decrypt hash or block table or a sector."""
    seed = 0xEEEEEEEE
    result = bytearray()

    for i in range(len(data) // 4):
        seed += _crypt_table[0x400 + (key & 0xFF)]
        seed &= 0xFFFFFFFF
        dat = data[i * 4:i * 4 + 4]
        finval, = struct.unpack("<I", dat)
        finval = (finval ^ (key + seed)) & 0xFFFFFFFF

        key = ((~key << 21) + 0x11111111) | (key >> 11)
        key &= 0xFFFFFFFF
        seed = (finval + seed + (seed << 5) + 0b11) & 0xFFFFFFFF

        result += struct.pack("<I", finval)
    result += data[len(data) // 4 * 4: (len(data) // 4 * 4) + len(data) % 4]

    return result


def _encrypt(data: bytes, key: _HashType) -> bytearray:
    seed = 0xEEEEEEEE
    result = bytearray()

    for i in range(len(data) // 4):
        seed += _crypt_table[0x400 + (key & 0xFF)]
        dat = data[i * 4:i * 4 + 4]
        orval, = struct.unpack("<I", dat)
        finval = (orval ^ (key + seed)) & 0xFFFFFFFF

        key = ((~key << 0x15) + 0x11111111) | (key >> 0x0B)
        key &= 0xFFFFFFFF
        seed = (orval + seed + (seed << 5) + 3) & 0xFFFFFFFF

        result += struct.pack("<I", finval)
    result += data[len(data) // 4 * 4: (len(data) // 4 * 4) + len(data) % 4]

    return result


def index_for_path(path: bytes, hash_table_entries: HashTableEntries):
    """Returns the default index for a given path"""
    return _hash(path, 'TABLE_OFFSET') & (hash_table_entries - 1)


def add_file(to_add: typing.Dict[bytes, typing.Dict],
             name: bytes,
             *,
             md5_path: pathlib.Path = None,
             contents=b'',
             locale=0, platform=0):

    to_add[name] = {
        'md5_path': md5_path,
        'locale': locale,
        'platform': platform,
        'contents': contents,
    }


def flush(
        target: typing.BinaryIO,
        to_add: typing.Dict[bytes, typing.Dict],
        pre_header: bytes = b''):

    target.write(pre_header)

    header = MPQHeader(
        magic=_MPQ_HEADER_MAGIC,
        header_size=struct.calcsize(MPQHeader.format_string),
        mpq_size=0,
        format_version=0,
        block_size_exp=3,
        hash_table_offset=0,
        block_table_offset=0,
        hash_table_entries=HashTableEntries(0),
        block_table_entries=len(to_add) + 1
    )
    block_table = []
    hash_table = []

    target.write(struct.pack(MPQHeader.format_string, *dataclasses.astuple(header)))

    list_file = io.BytesIO()
    for path in to_add.keys():
        list_file.write(path)
        list_file.write(b'\r\n')

    add_file(to_add, b'(listfile)', contents=list_file.getvalue())

    for path, file_data in to_add.items():
        if file_data['md5_path']:
            with open(file_data['md5_path'], "rb") as f:
                content = f.read()
        else:
            content = file_data['contents']
        block = MPQBlockEntry(_FilePosition(target.tell()), 0, len(content), 0)
        a, b = filename_to_hash_pair(path)
        hash_ = MPQHashEntry(
            a,
            b,
            locale=file_data['locale'],
            platform=file_data['platform'],
            block_index=len(block_table)
        )
        hash_table.append(hash_)
        block_table.append(block)
        block.pack(content, target, header.sector_size)

    header.hash_table_offset = target.tell()
    buffer = io.BytesIO()
    for hash_ in hash_table:
        buffer.write(struct.pack(MPQHashEntry.format_string, *dataclasses.astuple(hash_)))
    buffer = _encrypt(
        buffer.getvalue(), _hash(b'(hash table)', 'TABLE')
    )
    target.write(buffer)
    header.block_table_offset = target.tell()
    buffer = bytearray()
    for block in block_table:
        buffer += struct.pack(MPQBlockEntry.format_string, *block.pack_tuple())
    buffer = _encrypt(
        bytes(buffer), _hash(b'(block table)', 'TABLE')
    )

    target.write(buffer)
    header.mpq_size = target.tell()
    header.hash_table_entries = _closest_power_of_two(len(hash_table))

    target.seek(len(pre_header))
    target.write(struct.pack(MPQHeader.format_string, *dataclasses.astuple(header)))
