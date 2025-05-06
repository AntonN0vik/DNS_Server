import struct
from dataclasses import dataclass
from enum import Enum
from typing import List


class QueryType(int, Enum):
    A = 1
    NS = 2
    PTR = 12
    AAAA = 28


class QueryClass(int, Enum):
    IN = 1


@dataclass
class DNSHeader:
    id: int
    flags: int
    qd_count: int
    an_count: int
    ns_count: int
    ar_count: int


@dataclass
class DNSQuestion:
    q_name: str
    q_type: QueryType
    q_class: QueryClass


@dataclass
class DNSResourceRecord:
    r_name: str
    r_type: QueryType
    r_class: QueryClass
    r_ttl: int
    rd_length: int
    r_data: str


@dataclass
class DNSPackage:
    data: bytes
    _pointer: int = 0
    header: DNSHeader = None
    questions: List[DNSQuestion] = None
    answer_records: List[DNSResourceRecord] = None
    authoritative_records: List[DNSResourceRecord] = None
    additional_records: List[DNSResourceRecord] = None

    def __post_init__(self):
        self.questions = []
        self.answer_records = []
        self.authoritative_records = []
        self.additional_records = []
        self._parse_header()
        self._parse_questions()
        self._parse_resource_records()

    def _parse_header(self):
        self.header = DNSHeader(*struct.unpack("!6H", self.data[:12]))
        self._pointer += 12

    def _parse_questions(self):
        for _ in range(self.header.qd_count):
            q_name = self._read_name()
            q_type, q_class = struct.unpack("!HH", self.data[self._pointer:self._pointer + 4])
            self.questions.append(DNSQuestion(q_name, q_type, q_class))
            self._pointer += 4

    def _parse_resource_records(self):
        record_types = [
            (self.answer_records, self.header.an_count),
            (self.authoritative_records, self.header.ns_count),
            (self.additional_records, self.header.ar_count),
        ]
        for record_list, count in record_types:
            self._populate_records(record_list, count)

    def _populate_records(self, record_list: List[DNSResourceRecord], count: int):
        for _ in range(count):
            r_name = self._read_name()
            r_type, r_class, r_ttl, rd_length = struct.unpack("!HHIH", self.data[self._pointer:self._pointer + 10])
            self._pointer += 10
            r_data = self._read_resource_data(r_type, rd_length)
            record_list.append(DNSResourceRecord(r_name, r_type, r_class, r_ttl, rd_length, r_data))

    def _read_name(self) -> str:
        name_parts = []
        position = self._pointer
        jumped = False

        while True:
            length = self.data[position]
            if length > 63:  # Pointer to another label
                if not jumped:
                    self._pointer = position + 2
                position = ((length - 192) << 8) + self.data[position + 1]
                jumped = True
            elif length == 0:  # End of name
                if not jumped:
                    self._pointer = position + 1
                break
            else:  # Label
                position += 1
                name_parts.append(self.data[position:position + length])
                position += length

        return ".".join(label.decode("utf-8") for label in name_parts)

    def _read_resource_data(self, r_type: int, rd_length: int) -> str:
        if r_type == QueryType.A.value:
            ipv4 = struct.unpack(f"!{rd_length}B", self.data[self._pointer:self._pointer + rd_length])
            self._pointer += rd_length
            return ".".join(map(str, ipv4))
        elif r_type in (QueryType.NS.value, QueryType.PTR.value):
            return self._read_name()
        elif r_type == QueryType.AAAA.value:
            ipv6 = struct.unpack(f"!{rd_length // 2}H", self.data[self._pointer:self._pointer + rd_length])
            self._pointer += rd_length
            return ":".join(f"{block:x}" for block in ipv6)
        else:
            raise ValueError(f"Unsupported query type: {r_type}")
