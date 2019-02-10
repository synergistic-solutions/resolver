import socket
import random

from synergistic.resolver import dns


class Resolver(socket.socket):

    callback = None

    def __init__(self, server: str = '9.9.9.9', port: int = 53):
        socket.socket.__init__(self, socket.AF_INET, socket.SOCK_DGRAM)
        self.settimeout(3)
        self.server = (server, port)
        self._closed = False

    def on_receive(self):
        message, addr = self.recvfrom(4096)
        if not message:
            self.close()
            return

        parser = dns.DNSPacket.from_packet(message)

        for answer in parser.answers:
            if self.callback:
                self.callback(answer.value, answer.TYPE)

        self._closed = True

    def request(self, hostname: str, type: int = dns.Type.A):
        questions = [dns.Question(hostname, type, 1)]
        transaction_id = random.randint(0, 65536)
        builder = dns.DNSPacket(transaction_id, 256, questions, [], [], [])
        encoded = builder.to_packet().to_bytes()
        self.sendto(encoded, ("9.9.9.9", 53))
