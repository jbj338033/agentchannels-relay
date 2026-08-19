#!/usr/bin/env python3
import base64
import json
import os
import socket
import struct
import sys


def read_exact(stream, length):
    value = stream.read(length)
    if value is None or len(value) != length:
        raise RuntimeError("WebSocket closed before the protocol response")
    return value


def read_frame(stream):
    first, second = read_exact(stream, 2)
    length = second & 0x7F
    if length == 126:
        length = struct.unpack("!H", read_exact(stream, 2))[0]
    elif length == 127:
        length = struct.unpack("!Q", read_exact(stream, 8))[0]
    if second & 0x80:
        mask = read_exact(stream, 4)
        payload = read_exact(stream, length)
        payload = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
    else:
        payload = read_exact(stream, length)
    if first & 0x0F != 1:
        raise RuntimeError("Relay did not send a text frame")
    return json.loads(payload)


def send_text(connection, value):
    payload = json.dumps(value, separators=(",", ":")).encode()
    mask = os.urandom(4)
    header = bytearray([0x81])
    if len(payload) < 126:
        header.append(0x80 | len(payload))
    else:
        header.append(0x80 | 126)
        header.extend(struct.pack("!H", len(payload)))
    header.extend(mask)
    header.extend(byte ^ mask[index % 4] for index, byte in enumerate(payload))
    connection.sendall(header)


host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 8787
with socket.create_connection((host, port), timeout=5) as connection:
    key = base64.b64encode(os.urandom(16)).decode()
    connection.sendall(
        (
            "GET /v1/connect HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
        ).encode()
    )
    stream = connection.makefile("rb")
    if b"101" not in stream.readline():
        raise RuntimeError("Relay refused the WebSocket upgrade")
    while stream.readline() not in (b"\r\n", b"\n", b""):
        pass
    challenge = read_frame(stream)
    if challenge.get("type") != "challenge" or challenge.get("protocol") != 1:
        raise RuntimeError("Relay did not send a protocol-1 challenge")
    send_text(
        connection,
        {
            "type": "authenticate",
            "protocol": 2,
            "installationId": "probe",
            "signatureBase64": "c3ludGhldGlj",
        },
    )
    response = read_frame(stream)
    if response.get("code") != "unsupported_protocol":
        raise RuntimeError("Relay did not reject the unsupported protocol explicitly")

print("unsupported_protocol=passed")
