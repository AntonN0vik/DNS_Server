import socket
from typing import List, Optional

from app.package import builder
from app import dependencies
from app.package.data import DNSPackage, QueryClass, QueryType

settings = dependencies.get_server_settings()


def resolve(
        q_request: bytes,
        server_ip: str = settings["root_server_ip"],
        server_port: int = settings["root_server_port"],
) -> Optional[DNSPackage]:
    response = _send_dns_request(q_request, server_ip, server_port)
    response_package = DNSPackage(response)

    if response_package.header.an_count > 0:
        return response_package

    if response_package.header.ns_count > 0:
        for auth_record in response_package.authoritative_records:
            for additional_record in response_package.additional_records:
                if additional_record.r_type == QueryType.A:
                    return resolve(q_request, additional_record.r_data)

            for ip in _resolve_authority_ips(response_package.header.id, auth_record.r_data):
                return resolve(q_request, ip)


def _resolve_authority_ips(
        request_id: int,
        name: str,
        server_ip: str = settings["root_server_ip"],
        server_port: int = settings["root_server_port"],
) -> Optional[List[str]]:
    query = builder.get_request(request_id, name, QueryType.A, QueryClass.IN)
    resolved_package = resolve(query, server_ip, server_port)

    if resolved_package:
        return [record.r_data for record in resolved_package.answer_records]


def _send_dns_request(request: bytes, dns_server_ip: str, dns_server_port=53) -> bytes:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(5)
        sock.connect((dns_server_ip, dns_server_port))
        sock.send(request)
        return sock.recv(settings["request_size"])
