"""Thrift TBinaryProtocol decoder for XChat message events.

XChat messages are Thrift binary structs, base64-encoded. This module
decodes them into Python dicts for processing.

Field map (reverse-engineered from XChat API responses):
  Message event:
    1: message_id (string)
    2: request_uuid (string)
    3: sender_id (string)
    4: conversation_id (string)
    5: jwt_envelope (string)
    6: timestamp_ms (string)
    7: content (struct)
       └ 1 (struct): message payload
           └ 100: encrypted_text (string, base64)
           └ 101: key_version (string)
           └ 102: affects_sort (bool)
    8: message_type (i32, 1=text)
    9: signature_info (struct)
       └ 1: signature (string, base64)
       └ 2: key_version (string)
       └ 4: signing_public_key (string, base64 SPKI)

  Key change event:
    Contains per-participant encrypted conversation keys.
"""

from __future__ import annotations

import base64
import struct
from typing import Any

# Thrift type constants
T_STOP = 0
T_BOOL = 2
T_BYTE = 3
T_I16 = 6
T_I32 = 8
T_I64 = 10
T_STRING = 11
T_STRUCT = 12
T_MAP = 13
T_SET = 14
T_LIST = 15

_TYPE_NAMES = {
    0: "stop", 2: "bool", 3: "byte", 6: "i16", 8: "i32",
    10: "i64", 11: "string", 12: "struct", 13: "map",
    14: "set", 15: "list",
}

MAX_DEPTH = 8
MAX_COLLECTION = 200


def decode_struct(data: bytes, offset: int = 0, depth: int = 0) -> tuple[dict, int]:
    """Decode a Thrift binary struct into {field_id: value} dict."""
    fields: dict[int, Any] = {}
    while offset < len(data):
        field_type = data[offset]
        if field_type == T_STOP:
            offset += 1
            break
        if offset + 2 >= len(data):
            break
        field_id = struct.unpack(">H", data[offset + 1:offset + 3])[0]
        offset += 3
        val, offset = _decode_value(data, offset, field_type, depth)
        fields[field_id] = val
    return fields, offset


def _decode_value(data: bytes, offset: int, field_type: int, depth: int) -> tuple[Any, int]:
    """Decode a single Thrift value."""
    if field_type == T_BOOL:
        return data[offset] != 0, offset + 1
    if field_type == T_BYTE:
        return data[offset], offset + 1
    if field_type == T_I16:
        return struct.unpack(">h", data[offset:offset + 2])[0], offset + 2
    if field_type == T_I32:
        return struct.unpack(">i", data[offset:offset + 4])[0], offset + 4
    if field_type == T_I64:
        return struct.unpack(">q", data[offset:offset + 8])[0], offset + 8
    if field_type == T_STRING:
        length = struct.unpack(">I", data[offset:offset + 4])[0]
        offset += 4
        raw = data[offset:offset + length]
        try:
            return raw.decode("utf-8"), offset + length
        except UnicodeDecodeError:
            return base64.b64encode(raw).decode(), offset + length
    if field_type == T_STRUCT:
        if depth >= MAX_DEPTH:
            return {}, offset
        return decode_struct(data, offset, depth + 1)
    if field_type == T_LIST:
        elem_type = data[offset]
        count = struct.unpack(">I", data[offset + 1:offset + 5])[0]
        offset += 5
        items = []
        for _ in range(min(count, MAX_COLLECTION)):
            v, offset = _decode_value(data, offset, elem_type, depth + 1)
            items.append(v)
        return items, offset
    if field_type == T_MAP:
        key_type = data[offset]
        val_type = data[offset + 1]
        count = struct.unpack(">I", data[offset + 2:offset + 6])[0]
        offset += 6
        items = {}
        for _ in range(min(count, MAX_COLLECTION)):
            k, offset = _decode_value(data, offset, key_type, depth + 1)
            v, offset = _decode_value(data, offset, val_type, depth + 1)
            items[str(k)] = v
        return items, offset
    if field_type == T_SET:
        elem_type = data[offset]
        count = struct.unpack(">I", data[offset + 1:offset + 5])[0]
        offset += 5
        items = []
        for _ in range(min(count, MAX_COLLECTION)):
            v, offset = _decode_value(data, offset, elem_type, depth + 1)
            items.append(v)
        return items, offset
    return None, offset


def decode_message_event(b64_data: str) -> dict[str, Any]:
    """Decode a base64-encoded XChat message event into structured data.

    Returns dict with keys: message_id, request_uuid, sender_id,
    conversation_id, timestamp_ms, encrypted_text, key_version,
    message_type, raw_fields.
    """
    raw = base64.b64decode(b64_data)
    fields, _ = decode_struct(raw)

    result: dict[str, Any] = {"raw_fields": fields}
    result["message_id"] = fields.get(1, "")
    result["request_uuid"] = fields.get(2, "")
    result["sender_id"] = fields.get(3, "")
    result["conversation_id"] = fields.get(4, "")
    result["timestamp_ms"] = fields.get(6, "")
    result["message_type"] = fields.get(8, 0)

    # Extract encrypted content from field 7 (content struct)
    content = fields.get(7, {})
    if isinstance(content, dict):
        payload = content.get(1, {})
        if isinstance(payload, dict):
            result["encrypted_text"] = payload.get(100, "")
            result["key_version"] = payload.get(101, "")
            result["affects_sort"] = payload.get(102, False)

    # Extract signature info from field 9
    sig_info = fields.get(9, {})
    if isinstance(sig_info, dict):
        result["signature"] = sig_info.get(1, "")
        result["sig_key_version"] = sig_info.get(2, "")
        result["signing_public_key"] = sig_info.get(4, "")

    return result


def decode_key_event(b64_data: str) -> dict[str, Any]:
    """Decode a base64-encoded XChat key change event.

    Returns dict with raw_fields and any extracted key data.
    """
    raw = base64.b64decode(b64_data)
    fields, _ = decode_struct(raw)
    return {"raw_fields": fields}


def extract_encrypted_conv_keys(key_events: list[str]) -> dict[str, str]:
    """Extract per-participant encrypted conversation keys from key events.

    Returns {user_id: encrypted_conv_key_b64} mapping.
    """
    keys: dict[str, str] = {}
    for ke_b64 in key_events:
        try:
            raw = base64.b64decode(ke_b64)
            fields, _ = decode_struct(raw)
            _walk_for_conv_keys(fields, keys)
        except Exception:
            continue
    return keys


def _walk_for_conv_keys(fields: dict, keys: dict[str, str]) -> None:
    """Recursively walk Thrift fields looking for conversation key data."""
    for _fid, val in fields.items():
        if isinstance(val, dict):
            _walk_for_conv_keys(val, keys)
        elif isinstance(val, list):
            for item in val:
                if isinstance(item, dict):
                    _walk_for_conv_keys(item, keys)
        elif isinstance(val, str) and len(val) > 80:
            # Could be an encrypted conversation key (base64-encoded)
            try:
                decoded = base64.b64decode(val)
                # Encrypted conv key starts with 0x04 (uncompressed EC point)
                if len(decoded) >= 65 and decoded[0] == 0x04:
                    keys[str(len(keys))] = val
            except Exception:
                pass
