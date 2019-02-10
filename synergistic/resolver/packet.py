import socket
import struct

class Packet:

    def __init__(self, packet=b''):
        self.packet = bytearray(packet)
        self.position = 0
        self.offset = 0
        self.names = {}

    def unpack(self, fmt):
        size = struct.calcsize(fmt)
        new_position = self.position + size
        unpacked_data = struct.unpack(fmt, self.packet[self.position + self.offset:new_position + self.offset])

        if self.offset == 0:
            self.position = new_position
        else:
            self.offset += size

        return unpacked_data

    def pack(self, fmt, *args):
        self.packet += struct.pack(fmt, *args)

    def unpack_hostname(self):
        length = self.unpack('!B')[0]
        hostname = ''
        while length > 0:

            if length >= 192:
                # next byte is going to be a pointer
                self.offset = self.unpack("!B")[0] - self.position
                hostname += self.unpack_hostname()
                self.offset = 0
                length = 0

            else:
                chars = self.unpack('!{}c'.format(length))
                hostname += (b''.join(chars)).decode('utf-8') + '.'
                length = self.unpack('!B')[0]

        return hostname

    def pack_name(self, name):
        if not name.endswith('.'):
            name += '.'

        if name in self.names:
            self.pack('!H', 192 + self.names[name])
            return

        # else:
        split_name = name.split(".")
        names = []
        for i in range(len(split_name)-1):
            names.append('.'.join(split_name[i:]))

        for count, label in enumerate(split_name):
            self.pack("!B", len(label))

            if label:
                self.names[names[count]] = len(self.packet) - 1

            for byte in label.encode():
                self.pack("!c", chr(byte).encode())

    def to_bytes(self):
        return self.packet
