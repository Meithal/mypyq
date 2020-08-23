import typing
import dataclasses
import pathlib
import io

class yield_file_stream:
    keep_open: bool

class FormattedTuple:
    format_string: typing.ClassVar[str]


class MPQBlockEntry(FormattedTuple, format_string="4I"):
    file_position: int
    compressed_size: int
    uncompressed_size: int
    flags: int
    archive: 'MPQArchive'
    positions: list
    flags_table: dict

    def pkware_imploded(self) -> bool:
        pass

    def other_compressions(self) -> bool:
        pass

    def encrypted(self) -> bool:
        pass

    def decrypt_key(self) -> bool:
        pass

    def is_patch(self) -> bool:
        pass

    def single_sector(self) -> bool:
        pass

    def deleted(self) -> bool:
        pass

    def has_crc(self) -> bool:
        pass

    def exists(self) -> bool:
        pass

@dataclasses.dataclass()
class MPQUserData(FormattedTuple, format_string="4s3I"):
    magic: bytes
    max_size: int
    offset_to_header: int
    this_size: int


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

class MPQHashEntry(FormattedTuple, format_string="2IHBBI"):
    name_part_a: int
    name_part_b: int
    locale: int
    platform: int
    reserved: int
    block_index: int
    archive: dataclasses.InitVar['MPQArchive']


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
    filesize: int = 0

    def __post_init__(self, keep_open: bool, filenames_to_test: typing.Tuple[str]=tuple()):
        pass

    def read_file(self, filename: str, locale=0, platform=0) -> typing.Tuple[bytes, set]:
        pass
    
    @property
    def has_listfile(self) -> bool:
        pass

    def done_with_file(self):
        pass
    
    def insight(self) -> dict:
        pass