import struct

from synergistic.resolver.packet import Packet


class Type:
    A = 1
    NS = 2
    MD = 3
    MF = 4
    CNAME = 5
    SOA = 6
    MB = 7
    MG = 8
    MR = 9
    NULL = 10
    WKS = 11
    PTR = 12
    HINFO = 13
    MINFO = 14
    MX = 15
    TXT = 16
    RP = 17
    AFSDB = 18
    X25 = 19
    ISDN = 20
    RT = 21
    NSAP = 22
    NSAP_PTR = 23
    SIG = 24
    KEY = 25
    PX = 26
    GPOS = 27
    AAAA = 28
    LOC = 29
    NXT = 30
    EID = 31
    NIMLOC = 32
    SRV = 33
    ATMA = 34
    NAPTR = 35
    KX = 36
    CERT = 37
    A6 = 38
    DNAME = 39
    SINK = 40
    OPT = 41
    APL = 42
    DS = 43
    SSHFP = 44
    IPSECKEY = 45
    RRSIG = 46
    NSEC = 47
    DNSKEY = 48
    DHCID = 49
    NSEC3 = 50
    NSEC3PARAM = 51
    TLSA = 52
    SMIMEA = 53
    HIP = 55
    NINFO = 56
    RKEY = 57
    TALINK = 58
    CDS = 59
    CDNSKEY = 60
    OPENPGPKEY = 61
    CSYNC = 62
    ZONEMD = 63
    SPF = 99
    UINFO = 100
    UID = 101
    GID = 102
    UNSPEC = 103
    NID = 104
    L32 = 105
    L64 = 106
    LP = 107
    EUI48 = 108
    EUI64 = 109
    TKEY = 249
    TSIG = 250
    IXFR = 251
    AXFR = 252
    MAILB = 253
    MAILA = 254
    ANY = 255
    URI = 256
    CAA = 257
    AVC = 258
    DOA = 259
    AMTRELAY = 260


class Flags:

    def __init__(self, *args):
        self.bits = [False] * 16

        count = 0
        for arg in args:
            if isinstance(arg, bool):
                self.bits[count] = arg

            elif isinstance(arg, int):
                bin_opcode = [bool(x) for x in '{0:04b}'.format(arg)]
                for i, bit in enumerate(bin_opcode):
                    print(i, bit, count, self.bits)
                    self.bits[count + i] = bit

            elif arg is None:
                pass

            else:
                raise Exception

            count += 1

    @classmethod
    def from_int(cls, value):
        str_bits = '{0:016b}'.format(value)
        bits = [bool(int(bit)) for bit in str_bits]
        return cls(*bits)

    def to_int(self):
        return sum(v << i for i, v in enumerate(self.bits[::-1]))


class Question:

    def __init__(self, qname: str, qtype: int, qclass: int):
        self.QNAME = qname
        self.QTYPE = qtype
        self.QCLASS = qclass

    @classmethod
    def from_packet(cls, packet: Packet):
        qname = packet.unpack_hostname()
        qtype, qclass = packet.unpack("!HH")
        return cls(qname, qtype, qclass)

    def to_packet(self, packet: Packet):
        packet.pack_name(self.QNAME)
        packet.pack('!HH', self.QTYPE, self.QCLASS)
        return packet


class Answer:

    def __init__(self, name: str, type_: int, class_: int, ttl: int, data: bytes):
        self.NAME = name
        self.TYPE = type_
        self.CLASS = class_
        self.TTL = ttl
        self.DATA = data

        if self.TYPE == Type.A:
            self.value = "{}.{}.{}.{}".format(*struct.unpack("!BBBB", self.DATA))

        elif self.TYPE == Type.AAAA:
            ip = bytearray(self.DATA).hex()
            self.value = ':'.join(ip[i:i+4] for i in range(0, 32, 4))

        elif self.TYPE == Type.TXT:
            txt_length = struct.unpack("!B", self.DATA[:1])[0]  # len(self.DATA) - 1
            self.value = b''.join(struct.unpack('!{}c'.format(txt_length), self.DATA[1:txt_length+1])).decode()

        elif self.TYPE == Type.CNAME:
            self.value = data

    @classmethod
    def from_packet(cls, packet: Packet):
        name = packet.unpack_hostname()
        type_, class_, ttl, data_length = packet.unpack("!HHIH")
        data = b''

        for i in range(data_length):
            data += packet.unpack('!c')[0]

        return cls(name, type_, class_, ttl, data)

    def to_packet(self, packet: Packet):
        packet.pack_name(self.NAME)
        packet.pack('!HHIH', self.TYPE, self.CLASS, self.TTL, len(self.DATA))

        for i in list(self.DATA):
            packet.pack('!c', bytes([i]))

        return packet


class Authority(Answer):
    pass


class Additional(Answer):
    pass


class DNSPacket:

    def __init__(self, transaction_id, flags, questions, answers, authorities, additonal):
        self.transaction_id = transaction_id
        if isinstance(flags, int):
            flags = Flags.from_int(flags)
        self.flags = flags
        self.questions = questions
        self.answers = answers
        self.authorities = authorities
        self.additional = additonal

    @classmethod
    def from_packet(cls, packet):
        packet = Packet(packet)
        tid, flags, qdcount, ancount, nscount, arcount = packet.unpack('!HHHHHH')

        flags = Flags.from_int(flags)

        qd = [Question.from_packet(packet) for _ in range(qdcount)]
        an = [Answer.from_packet(packet) for _ in range(ancount)]
        ns = [Authority.from_packet(packet) for _ in range(nscount)]
        ar = [Additional.from_packet(packet) for _ in range(arcount)]

        return cls(tid, flags, qd, an, ns, ar)

    def to_packet(self, packet=Packet()):
        packet.pack('!HHHHHH', self.transaction_id, self.flags.to_int(), len(self.questions), len(self.answers), 0,
                    len(self.additional))
        for question in self.questions:
            question.to_packet(packet)

        for answer in self.answers:
            answer.to_packet(packet)

        return packet
