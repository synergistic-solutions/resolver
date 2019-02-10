from synergistic.poller import Poll
from synergistic.broker import Client
from synergistic.resolver import Resolver


def resolve(channel, msg_id, payload):
    resolver.request(payload['hostname'], payload['type'])


def callback(data):
    if isinstance(data, str) and data.count('.') == 3:
        resolver.publish('crawl', data)


if __name__ == "__main__":
    poller = Poll(catch_errors=False)

    broker = Client("127.0.0.1", 8891, broker.Type.Indexer)
    poller.add_client(broker)
    broker.subscribe('resolve', resolve)

    resolver = Resolver()
    resolver.callback = callback
    poller.add_client(resolver)

    poller.serve_forever()
