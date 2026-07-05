import base64
import zlib
import struct

# The user's Mieru sn:// link
url = "sn://mieru?eNpjYGBgMDQx0zM0MNYzNDLTM99xn52BIcT5QklqcUlq0aa1rj4B2f5l-lUVjunOJk5OuZaWxlUm6SnpXqEm-lk5jt6lWUE-HsFJHpWl6baMQMMg-owUfDNTi742NgIATSwecg"

b64_data = url.split("?")[1]
# Add padding if needed
b64_data += "=" * ((4 - len(b64_data) % 4) % 4)
compressed = base64.urlsafe_b64decode(b64_data)
data = zlib.decompress(compressed)

print(f"Data length: {len(data)}")
print("Raw data hex:", data.hex())

# Let's inspect the fields in the raw bytes:
# SagerNet/NekoBox serializer format:
# String serialization ends with MSB set on the last byte.
def deserialize_string(b: bytes) -> tuple[str, bytes]:
    # Find the byte with MSB set (bit 7 is 1)
    for idx, val in enumerate(b):
        if val & 0x80:
            part = b[:idx+1]
            # clear the high bit of the last byte
            last_byte = part[-1] & ~0x80
            decoded = part[:-1] + bytes([last_byte])
            return decoded.decode('utf-8'), b[idx+1:]
    return "", b

# Deserialize Mieru fields:
# Type (int32)
# Server (string)
# Port (int32)
# Protocol (string)
# Username (string)
# Password (string)
# ...

# Read type
m_type = struct.unpack('<I', data[:4])[0]
rem = data[4:]
print(f"Type: {m_type}")

# Read server
server, rem = deserialize_string(rem)
print(f"Server: {server}")

# Read port
port = struct.unpack('<I', rem[:4])[0]
rem = rem[4:]
print(f"Port: {port}")

# Read protocol
protocol, rem = deserialize_string(rem)
print(f"Protocol: {protocol}")

# Read username
username, rem = deserialize_string(rem)
print(f"Username: {username}")

# Read password
password, rem = deserialize_string(rem)
print(f"Password: {password}")

# Remaining bytes
print("Remaining hex:", rem.hex())
