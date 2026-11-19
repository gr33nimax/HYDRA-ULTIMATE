"""Read cumulative authenticated-user counters from loopback V2Ray StatsService."""
from __future__ import annotations

STATS_PORT = 19091


def user_counters(port: int = STATS_PORT, *, timeout: float = 3.0) -> dict[str, int]:
    import grpc

    if type(port) is not int or not 1 <= port <= 65535 or not 0 < timeout <= 30:
        raise ValueError("invalid local stats endpoint or timeout")
    with grpc.insecure_channel(f"127.0.0.1:{port}", options=[("grpc.max_receive_message_length", 2 * 1024 * 1024)]) as channel:
        query = channel.unary_unary("/v2ray.core.app.stats.command.StatsService/QueryStats",
                                    request_serializer=lambda value: value, response_deserializer=lambda value: value)
        response = query(b"\x1a\x07user>>>", timeout=timeout)  # patterns[0], reset=false
    totals = {}
    for number, stat in _fields(response):
        if number != 1 or not isinstance(stat, bytes):
            raise ValueError("invalid stats response")
        fields = dict(_fields(stat))
        name, value = fields.get(1, b""), fields.get(2, 0)
        if not isinstance(name, bytes) or type(value) is not int or value >= 2**63:
            raise ValueError("invalid user counter")
        parts = name.decode("utf-8").split(">>>")
        if len(parts) == 4 and parts[0] == "user" and parts[2] == "traffic" and parts[3] in {"uplink", "downlink"}:
            totals[parts[1]] = totals.get(parts[1], 0) + value
    return totals


def _varint(data: bytes, position: int):
    result = 0
    for shift in range(0, 70, 7):
        if position >= len(data):
            raise ValueError("truncated stats message")
        value = data[position]
        position += 1
        result |= (value & 127) << shift
        if value < 128:
            return result, position
    raise ValueError("invalid stats integer")


def _fields(data: bytes):
    position = 0
    while position < len(data):
        tag, position = _varint(data, position)
        number, wire = tag >> 3, tag & 7
        if not number:
            raise ValueError("invalid stats field")
        if wire == 0:
            value, position = _varint(data, position)
        elif wire == 2:
            length, position = _varint(data, position)
            if length > len(data) - position:
                raise ValueError("truncated stats field")
            value, position = data[position:position + length], position + length
        else:
            raise ValueError("unsupported stats wire type")
        yield number, value
