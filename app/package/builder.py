import struct
from typing import List, Tuple

from app.package.data import (
    DNSHeader,
    DNSQuestion,
    DNSResourceRecord,
    QueryClass,
    QueryType,
)


def build_unsupported_response(header_id: bytes) -> bytes:
    return header_id + struct.pack(
        "!5H", (2 << 14) + (2 << 9) + (2 << 2), 0, 0, 0, 0
    )


def build_response(
        header: DNSHeader,
        questions: List[DNSQuestion],
        answers: List[DNSResourceRecord],
) -> bytes:
    response = struct.pack(
        "!6H",
        header.id,
        (2 << 14) + (2 << 9),
        len(questions),
        len(answers),
        0,
        0,
    )

    for question in questions:
        response += pack_domain_name(question.q_name)[1] + struct.pack(
            "!HH", question.q_type, question.q_class
        )

    for answer in answers:
        response += (
                pack_domain_name(answer.r_name)[1]
                + struct.pack("!HHI", answer.r_type, answer.r_class, answer.r_ttl)
                + pack_resource_data(answer.r_type, answer.rd_length, answer.r_data)
        )

    return response


def pack_resource_data(r_type: int, data_length: int, data: str) -> bytes:
    if r_type == QueryType.A.value:
        return struct.pack(f"!H{data_length}B", 4, *map(int, data.split(".")))
    elif r_type in {QueryType.NS.value, QueryType.PTR.value}:
        rd_length, packed_data = pack_domain_name(data)
        return struct.pack("!H", rd_length) + packed_data
    elif r_type == QueryType.AAAA.value:
        octets = [int(octet, 16) for octet in data.split(":")]
        return struct.pack(f"!H{data_length // 2}H", 16, *octets)
    else:
        raise ValueError(f"Unsupported resource data type: {r_type}")


def pack_domain_name(name: str) -> Tuple[int, bytes]:
    parts = [(len(segment), segment) for segment in name.split(".")]
    packed_name = b"".join(struct.pack("!B", len_part) + segment.encode() for len_part, segment in parts)
    packed_name += struct.pack("!B", 0)

    total_length = len(parts) + sum(len_part for len_part, _ in parts) + 1
    return total_length, packed_name


def pack_question(domain: str, q_type: QueryType, q_class: QueryClass) -> bytes:
    _, packed_domain = pack_domain_name(domain)
    return packed_domain + struct.pack("!HH", q_type, q_class)


def build_request(
        request_id: int, domain_name: str, q_type: QueryType, q_class: QueryClass
) -> bytes:
    return struct.pack("!6H", request_id, 0, 1, 0, 0, 0) + pack_question(
        domain=domain_name, q_type=q_type, q_class=q_class
    )
