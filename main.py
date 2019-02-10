import socket

from synergistic.poller import Poll
from synergistic.broker import Client, Type
from synergistic.resolver import Resolver

poller = Poll(catch_errors=False)
broker = Client("127.0.0.1", 8891, Type.RESOLVER)

def resolve(channel, msg_id, payload):
    resolver = Resolver()
    resolver.callback = callback
    poller.add_client(resolver)
    resolver.request(payload['hostname'], payload['type'])


def callback(ip, type):
    print(ip, type)
    try:
        socket.inet_aton(ip)
    except TypeError or OSError:
        return
    else:
        if type == 1:
            broker.publish('crawl', ip)


if __name__ == "__main__":
    poller.add_client(broker)
    broker.subscribe('resolve', resolve)

    poller.serve_forever()
