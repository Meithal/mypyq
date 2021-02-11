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
import math

import explode
import subprocess

__version__ = "0.0.1"
write_errors = False
HashType = typing.NewType('HashType', int)
FilePosition = typing.NewType('FilePosition', int)  # an offset in the stream, not a counter


@functools.lru_cache(maxsize=None)
def closest_power_of_two(x):
    return math.ceil(math.log(x, 2))

def pairwise(iterable):  # from python manual
    """s -> (s0,s1), (s1,s2), (s2, s3), ..."""
    a, b = itertools.tee(iterable)
    next(b, None)
    return zip(a, b)

WAR3MAGIC = b"HM3W"
MPQ_USER_DATA_MAGIC = b"MPQ\x1B"
MPQ_HEADER_MAGIC = b"MPQ\x1A"

class _ABHashes(dict):
    def __missing__(self, key_):
        return key_

a_and_b_hashes_to_path_names = _ABHashes()

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

    offset_format: typing.ClassVar = b"%s_table_offset"
    entries_format: typing.ClassVar = b"%s_table_entries"

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

    @property
    def was_always_empty(self):
        return self.block_index == 0xFFFFFFFF

    @property
    def was_deleted(self):
        return self.block_index == 0xFFFFFFFE


@dataclasses.dataclass
class MPQBlockEntry(FormattedTuple, format_string="4I"):
    """
    A packed file with a locale and a platform.
    Size and flags tell how to uncompress the file.
    Flags: 
        pkware_imploded: All the file is compressed with pkware implode, no need to look for first byte of each sector.
        other_compressions: Sectors can be compressed or not, in pkware or other methods, as described by first byte of each sector.
        encrypted: File is encrypted by it's file name (aka "imported\\foo.txt" -> "foo.txt" is the encryption key).
        decrypt_key: Additionally file is encrypted by its offset in the archive and its uncompressed size.
        is_patch: File is patching an other one (that has the deleted key? Is it used to look up in mpq loading order? aka war3patch.mpq -> war3.mpq) 
        single_sector: This block doesn't have sector positions data, only compressed_size data is enough.
        deleted: This block has been deleted, probably an other block with the same name and is_patch should be looked for
                 by the user of the library.
                 hash table also have a deleted semantic, what happens if this is deleted but not the hash table entry, and vice versa?
        has_crc: Uses an extra chuck of data at the end of each sector to ensure it has been not tempered with. todo: We don't implement this.
        exists: Not sure what it is used for, looking that "deleted" isn't set should be enough?
    After the flags comes the encoded file.
    """
    file_position: FilePosition
    compressed_size: int
    uncompressed_size: int
    flags: int

    # these are dummies replaced by getter/setter properties, are here only to shut lint warnings
    def pkware_imploded(self) -> bool: pass
    def other_compressions(self) -> bool: pass
    def encrypted(self) -> bool: pass
    def decrypt_key(self) -> bool: pass
    def is_patch(self) -> bool: pass
    def single_sector(self) -> bool: pass
    def deleted(self) -> bool: pass
    def has_crc(self) -> bool: pass
    def exists(self) -> bool: pass

    flags_table: typing.ClassVar = {
        0x00000100: ('pkware_imploded', "PKWare compressed file (imploded)."),
        0x00000200: ('other_compressions', "Other compression than PKWare is used."),
        0x00010000: ('encrypted', "File is encrypted from its name (without path)."),
        0x00020000: ('decrypt_key', "Additional layer of encryption from offset in archive and final file size."),
        0x00100000: ('is_patch', "File is a patch."),
        0x01000000: ('single_sector', "Single block file."),
        0x02000000: ('deleted', "File is deleted by patch."),
        0x04000000: ('has_crc', "Each sector of file has CRC."),
        0x80000000: ('exists', "File exists.")
    }

    ZERO_SIZE: typing.ClassVar = "ZERO_SIZE"
    FLAG_NOT_EXISTS: typing.ClassVar = "FLAG_NOT_EXISTS"
    MALFORMED_DCL_CHUNK: typing.ClassVar = "Malformed PKWARE DCL chunk"
    CANT_EXTRACT_FILE_WITH_UNKNOWN_NAME: typing.ClassVar = "Can't extract an encrypted file from archive if we don't know it's name"

    def __post_init__(self):
        self._sectors_positions = None

    def __repr__(self):
        dic = dataclasses.asdict(self)
        dic.update({'flags': bin(self.flags)})

        return f"{dic} - {self.describe_flags()} Positions: {self._sectors_positions}"

    def pack_tuple(self):
        return (self.file_position, self.compressed_size, self.uncompressed_size, self.flags)

    def describe_flags(self):
        return ', '.join(desc for key, (_, desc) in self.flags_table.items() if self.flags & key)

    def sectors_positions(self, stream: io.BytesIO, sector_size: int, *,
                          decrypt_key: HashType = None,
                          offset=0
                          ):
        if self.single_sector:
            return [0, self.compressed_size]

        sectors, remainder = divmod(self.uncompressed_size, sector_size)

        sectors += bool(remainder)
        sectors += bool(self.has_crc)

        file_pos = stream.tell()
        stream.seek(self.file_position + offset)

        positions_data = stream.read(struct.calcsize("<I") * (sectors + 1))
        if isinstance(decrypt_key, int):
            positions_data = _decrypt(positions_data, HashType(decrypt_key))
        positions = struct.unpack('<%dI' % (sectors + 1), positions_data)

        stream.seek(file_pos)
        self._sectors_positions = positions
        return positions

    def extract_file(self, stream: typing.BinaryIO, sector_size: int,
                     filename: bytes = b'',
                     offset = 0) -> typing.Tuple[bytes, set]:
        errors = set()
        if self.uncompressed_size == 0:
            return b'', set()

        if not self.exists:
            return b'', {f"{self.FLAG_NOT_EXISTS} {self!r}"}

        if not filename and self.encrypted:
            return b'', {f"{self.CANT_EXTRACT_FILE_WITH_UNKNOWN_NAME} {self!r}"}

        stream.seek(self.file_position + offset)

        key = None
        if self.encrypted:
            key = _hash(filename, 'TABLE')
            if self.decrypt_key:
                key = (key + self.file_position) ^ self.uncompressed_size

        if self.single_sector:
            if self.other_compressions and self.uncompressed_size > self.compressed_size:
                errors_, value = self._uncompress(stream.read(self.compressed_size), (filename, "whole"))
                errors.update(errors_ and {f"single: {errors_} {self!r}"})
            else:
                value = stream.read(self.uncompressed_size)
            if errors:
                errors.add(repr(self))
            return value, errors

        positions = self.sectors_positions(stream, sector_size, decrypt_key=key and key - 1, offset=offset)

        if self.other_compressions or self.pkware_imploded:
            result = bytearray()
            raw_bytes_to_read = stream.read(positions[-1])
            for i, (start, end) in enumerate(pairwise([p for p in positions[:-1]] + [positions[-1]])):
                # todo: use a single iterator ?
                to_read = raw_bytes_to_read[start:end]
                errors_ = set()

                if self.encrypted:
                    to_read = _decrypt(to_read, HashType(key + i))

                if self.other_compressions:
                    needed_chunk = self.uncompressed_size - len(result)
                    if needed_chunk > sector_size:
                        needed_chunk = sector_size
                    if needed_chunk != (end - start):
                        # todo: we could probably detect that early and simply read it into the result
                        # but we have to be sure that we decrypt every block if it is even possible
                        errors_, uncompress = self._uncompress(to_read, (filename, i + 1, len(positions) - 1))
                    else:
                        uncompress = to_read
                else:  # pkware
                    try:
                        uncompress = explode.explode(to_read)
                    except Exception as e:
                        logging.error(f"Failed to PKWARE explode {filename}: {e}")

                result += uncompress
                errors.update(errors_ and {f"{i + 1} on {len(positions) - 1}: {errors_} {self!r}"})

            value = bytes(result)
        else:
            if self.encrypted:
                raise ValueError("Should never happen.")
            value = stream.read(self.uncompressed_size)

        return value, errors

    UNSUPPORTED_COMPRESSION: typing.ClassVar = "UNSUPPORTED_COMPRESSION"
    ZLIB_ERROR: typing.ClassVar = "ZLIB_ERROR"
    DECOMPRESSION_ERROR: typing.ClassVar = "DECOMPRESSION_ERROR"
    compressions: typing.ClassVar = {
        0x40: ("monowav", lambda x: -1),  # todo: implement
        0x80: ("stereowav", lambda x: -1),  # todo: implement
        0x01: ("huffman", lambda x: -1),  # todo: implement
        0x02: ("zlib", zlib.decompress),
        0x08: ("pkware", explode.explode),
        0x10: ("bzip2", bz2.decompress)
    }

    def _uncompress(self, raw: bytes, debug_diag) -> typing.Tuple[set, bytes]:
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
                    with open(f"{filename} {part}-{max_parts} GOOD", 'wb') as f:
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
            except Exception as e:
                logging.error(f"Generic error on {short}: {e} for {debug_diag}")
            else:
                continue

            if write_errors:
                filename, part, max_parts = debug_diag
                with open(f"{filename} {part}-{max_parts} BAD", 'wb') as f:
                    f.write(orig)

            dec = orig
            break

        return errors, dec

    def pack(self, contents: bytes, destination: io.BytesIO, sector_size: int):
        compressed = zlib.compress(contents)
        
        self.other_compressions = True
        self.exists = True
        self.uncompressed_size = len(contents)
        self.compressed_size = len(compressed)
        self.file_position = destination.tell()

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
            for i in range(1 + (compressed // sector_size)):
                chunk = zlib.compress(contents[i * sector_size : (i + 1) * sector_size])
                buffer.write(b'\x02')
                buffer.write(chunk)
                offsets.append(len(chunk))
            destination.write(struct.pack("<%dI" % (len(offsets) + 1), offsets + [self.uncompressed_size]))
            destination.write(buffer)

def _init_mpq_block_accessors():
    for k, (prop, desc) in MPQBlockEntry.flags_table.items():
        setattr(MPQBlockEntry, prop, property(
                lambda instance, key_=k: bool(instance.flags & key_),
                lambda instance, value, key_=k: setattr(
                    instance, 'flags', getattr(instance, 'flags') ^ (
                        bool(value) and not(getattr(instance, 'flags') & key_) and key_ 
                        or getattr(instance, 'flags') & key_ and key_
                        )  # Bitflip the correct bit with its antivalue or value
                           # whether we want it to become 1 or 0
                ),
                doc=desc
            )
        )


_init_mpq_block_accessors()


class MPQArchive:
    hash_: typing.AnyStr
    header_offset: typing.ClassVar[int] = 0x200
    raw_pre_archive: bytes
    user_data: typing.Optional[MPQUserData]
    header: MPQHeader
    hash_table: typing.List[MPQHashEntry]
    block_table: typing.List[MPQBlockEntry]
    filenames_to_test: typing.Tuple[bytes]
    tested_filenames: set
    ab_hashes_to_dict: typing.Dict[typing.Tuple[int, int], typing.Dict]
    boot_file_path: typing.Union[str, bytes, pathlib.PurePath]

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

    def __init__(self,
                 boot_stream=None,
                 hash_: typing.AnyStr=None,
                 *,
                 filenames_to_test: typing.Tuple[bytes] = tuple(),
                 boot_file_path=None,
                 header_offset=0x200
                 ):
        self.ab_hashes_to_dict = {}
        self.boot_file_path = boot_file_path
        self.hash_table = []
        self.block_table = []
        self.header_offset = header_offset

        if boot_stream or boot_file_path:
            if not hash_:
                raise ValueError("If providing a stream you must provide a hash of it so already parsed files don't get parsed again")
            self.hash_ = hash_
            if boot_file_path:
                self.boot_file_path = boot_file_path
                if not boot_stream:
                    boot_stream = open(boot_file_path, 'rb')
            if boot_stream.closed:
                raise OSError("File is closed.")
            if not boot_stream.readable() or not boot_stream.seekable():
                raise OSError(f"Something wrong with the stream.")
            self.tested_filenames = set()
            self.load_existing_stream(boot_stream, filenames_to_test)
            if boot_file_path:
                boot_stream.close()

    def __hash__(self):
        if not hasattr(self, 'hash_'):
            return hash(id(self))
        return hash(self.hash_)  # required so successive instances of the same mpq map to the same filename persist

    def __contains__(self, item):
        return self._hash_entry(item, 0, 0) is not None

    def load_existing_stream(self, stream, filenames_to_test):
        self.raw_pre_archive = stream.read(self.header_offset)
        stream.seek(self.header_offset)

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

    def test_filename(self, name: bytes, reason: str, locale=0, platform=0):
        hash_entry_ = self._hash_entry(name, locale, platform)
        
        self.tested_filenames.add((bool(hash_entry_), name.decode(), reason))
        
        return hash_entry_

    def _fill_user_data(self, stream):
        contents = stream.read(struct.calcsize(MPQUserData.format_string))
        stream.seek(self.header_offset)

        if contents[:4] != MPQ_USER_DATA_MAGIC:
            return

        self.user_data = MPQUserData(
            *struct.unpack(MPQUserData.format_string, contents[:struct.calcsize(MPQUserData.format_string)])
        )

    def _fill_header(self, stream):
        contents = stream.read(struct.calcsize(MPQHeader.format_string))
        stream.seek(self.header_offset)

        if contents[:4] != MPQ_HEADER_MAGIC:
            raise TypeError

        header = MPQHeader(
            *struct.unpack(MPQHeader.format_string, contents[:struct.calcsize(MPQHeader.format_string)])
        )

        if header.format_version != 0:
            raise NotImplementedError("Burning crusade format not supported.")

        return header

    def _fill_table(self, which: bytes, instance, stream):
        stream.seek(
            getattr(
                self.header,
                (self.header.offset_format % which).decode()
            ) + self.header_offset, io.SEEK_SET
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
            ) + self.header_offset, io.SEEK_SET
        )

    @property
    def has_listfile(self):
        return self._hash_entry(b"(listfile)", 0, 0) is not None

    def _hash_entry(self, filename: bytes, locale=0, platform=0) -> typing.Optional[MPQHashEntry]:
        hash_a, hash_b = filename_to_hash_pair(filename)

        best = None
        for value in self.hash_table:
            if value.name_part_a == hash_a and value.name_part_b == hash_b:
                best = value
                if value.locale == locale and value.platform == platform:
                    break

        return best

    def read_file(self, filename: bytes, *, stream: typing.BinaryIO=None,
        locale=0, platform=0, reason="direct read") -> typing.Tuple[bytes, set]:
        """Extract the `filename` from the same stream that was used to fill
        up header and block data previously. We pass in a new stream to not keep the file always open
        and to not have to parse header, hash and block data every time.
        The reason is where we have found the file name (listfile, guess, mentioned...) it can help
        to decypher MPQ contents with incomplete listfiles for future reads.
        
        Returns a tuple with file contents as bytes and a set that has every error encountered trying
        to read the file or an empty set if the read happened without errors."""
        # todo: find out why 7ff1a2-DotA Allstars v603b\PASBTNBlue_Lightning.blp takes so long
        ad_hoc = False
        if not stream:
            if not self.boot_file_path:
                raise RuntimeError("MyPQ didn't get a file stream nor it knows where to open it.")
            ad_hoc = True
            stream = self.boot_file_path.open('rb')

        hash_ = self.test_filename(filename, reason, locale, platform)
        if not hash_:
            return b'', {"Hash not found " + filename.decode()}

        block = self.block_table[hash_.block_index]

        contents = block.extract_file(
            stream, self.header.sector_size,
            filename=(pathlib.PurePath(filename.decode()).name).encode(),
            offset=self.header_offset
        )
        if ad_hoc:
            stream.close()
        return contents

    def all_files(self):
        for hash_ in self.hash_table:
            if hash_.was_deleted or hash_.was_always_empty:
                continue
            yield a_and_b_hashes_to_path_names[(hash_.name_part_a, hash_.name_part_b)]

    def unknown_files(self):
        return [file_ for file_ in self.all_files() if isinstance(file_, tuple)]

    def add_file(self, name: bytes, md5_path: pathlib.Path=None, contents=b'', locale=0, platform=0):
        a, b = filename_to_hash_pair(name)
        self.ab_hashes_to_dict[(a, b)] = {
            'archive_path': name,
            'md5_path': md5_path,
            'locale': locale,
            'platform': platform,
            'contents': contents,
        }


    def flush(self, target: typing.BinaryIO, pre_header: bytes = b''):
        target.write(pre_header)

        header = MPQHeader(
            magic=MPQ_HEADER_MAGIC, 
            header_size=struct.calcsize(MPQHeader.format_string),
            mpq_size=0,
            format_version=0,
            block_size_exp=3,
            hash_table_offset=0,
            block_table_offset=0,
            hash_table_entries=math.ceil(math.log(len(self.ab_hashes_to_dict) + 1, 2)) * 2,
            block_table_entries=len(self.ab_hashes_to_dict) + 1
        )
        block_table = []
        hash_table = []

        target.write(struct.pack(MPQHeader.format_string, *dataclasses.astuple(header)))

        listfile = io.BytesIO()
        for file_data in self.ab_hashes_to_dict.values():
            listfile.write(file_data['archive_path'])
            listfile.write(b'\r\n')

        self.add_file(b'(listfile)', contents=listfile.getvalue())


        for ab_tuple, file_data in self.ab_hashes_to_dict.items():
            if file_data['md5_path']:
                with open(file_data['md5_path'], "rb") as f:
                    content = f.read()
            else:
                content = file_data['contents']
            block = MPQBlockEntry(target.tell(), 0, len(content), 0)
            hash_ = MPQHashEntry(
                ab_tuple[0],
                ab_tuple[1],
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

        target.seek(len(pre_header))
        target.write(struct.pack(MPQHeader.format_string, *dataclasses.astuple(header)))
        


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
def filename_to_hash_pair(filename: bytes) -> typing.Tuple[HashType, HashType]:
    hash_a = _hash(filename, 'HASH_A')
    hash_b = _hash(filename, 'HASH_B')
    a_and_b_hashes_to_path_names[(hash_a, hash_b)] = filename
    return (hash_a, hash_b)


@functools.lru_cache(maxsize=None)
def _hash(string: bytes, hash_type: str) -> HashType:
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


# @functools.lru_cache(maxsize=None)
def _decrypt(data: bytes, key: HashType) -> (bytearray, int):
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

def _encrypt(data: bytes, key: HashType):
    seed = 0xEEEEEEEE

    result = bytearray()
    for i in range(len(data) // 4):
        seed += _crypt_table[0x400 + (key & 0xFF)]
        dat = data[i*4:i*4+4]
        orval, = struct.unpack("<I", dat)
        finval = (orval ^ (key + seed)) & 0xFFFFFFFF

        key = ((~key << 0x15) + 0x11111111) | (key >> 0x0B)
        key &= 0xFFFFFFFF
        seed = (orval + seed + (seed << 5) + 3) & 0xFFFFFFFF

        result += struct.pack("<I", finval)
    result += data[len(data) // 4 * 4: (len(data) // 4 * 4) + len(data) % 4]

    return result
