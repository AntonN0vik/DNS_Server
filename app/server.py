import signal
import socket

from app.package import builder
from app import dependencies, resolver
from app.cacher import Cacher
from app.package.data import DNSPackage

settings = dependencies.get_server_settings()


class Server:
    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((settings["server_ip"], settings["server_port"]))
        self.running = True
        self._setup_cacher()
        signal.signal(signal.SIGINT, self._shutdown)

    def _setup_cacher(self):
        self.cacher = Cacher(settings["cache_filepath"], settings["clean_period"])
        self.cacher.load()
        self.cacher.start()

    def run(self):
        while self.running:
            request, client_address = self.socket.recvfrom(settings["request_size"])
            self._process_request(request, client_address)

    def _process_request(self, request: bytes, client_address: str):
        request_package = DNSPackage(request)
        total_records = []

        for query in request_package.questions:
            query_request = builder.get_request(
                request_package.header.id, query.q_name, query.q_type, query.q_class
            )

            cached_result = self._get_cached_result(query.q_name, query.q_type)

            if cached_result:
                _, records = cached_result
                print("From cache")
            else:
                records = self._get_query_result(query_request, client_address)
                if records is None:
                    return
                self.cacher.add(query.q_name, query.q_type, records)

            total_records.extend(records)

        self._send_response(request_package, total_records, client_address)

    def _get_cached_result(self, q_name, q_type):
        return self.cacher.get(q_name, q_type)

    def _get_query_result(self, query_request, client_address):
        try:
            response = resolver.resolve(q_request=query_request)
            return response.answer_records
        except Exception as error:
            print(error)
            error_response = builder.get_unsupported_response(query_request[:2])
            self.socket.sendto(error_response, client_address)
            return None

    def _send_response(self, request_package, records, client_address):
        response = builder.get_response(
            request_package.header, request_package.questions, records
        )
        self.socket.sendto(response, client_address)

    def _shutdown(self, signum, frame):
        self.running = False
        self.socket.close()
        self.cacher.save()
        self.cacher.close()
