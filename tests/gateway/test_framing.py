"""Adversarial framing bounds for the MCP gateway (phase 1.1)."""

from __future__ import annotations

import io

import pytest

from agent_dna.execution_v01 import sha256_bytes_digest
from agent_dna.gateway.errors import FramingProtocolError, GatewayStartupError
from agent_dna.gateway.framing import (
    DEFAULT_MAX_MESSAGE_BYTES,
    MAX_HEADER_BYTES,
    FrameBuffer,
    FramingMode,
    encode_jsonrpc_message,
    frame_stdio,
    freeze_tools_call_bytes,
    parse_content_length,
    parse_jsonrpc,
)
from agent_dna.gateway.runtime import GatewayConfig
from agent_dna.gateway.stdio_proxy import _read_stdio_message


class CountingStream(io.BytesIO):
    """Tracks read sizes so oversized body reads are detectable."""

    def __init__(self, data: bytes = b"") -> None:
        super().__init__(data)
        self.read_sizes: list[int] = []

    def read(self, size: int | None = -1) -> bytes:  # noqa: A003
        n = -1 if size is None else size
        self.read_sizes.append(n)
        if n > DEFAULT_MAX_MESSAGE_BYTES:
            raise AssertionError(f"oversized read attempted: {n}")
        return super().read(n)


def _cl_frame(body: bytes) -> bytes:
    return frame_stdio(body)


def test_header_exceeding_max_without_terminator_is_protocol_error():
    buf = FrameBuffer(mode=FramingMode.CONTENT_LENGTH)
    # Grow past the cap without sending \r\n\r\n.
    chunk = b"X" * (MAX_HEADER_BYTES + 1)
    with pytest.raises(FramingProtocolError, match="MAX_HEADER_BYTES"):
        buf.push(chunk)
    assert len(buf.pending) <= MAX_HEADER_BYTES + 1


@pytest.mark.parametrize(
    "header_line",
    [
        b"Content-Length: -1\r\n\r\n",
        b"Content-Length: abc\r\n\r\n",
        b"Content-Type: application/json\r\n\r\n",
        f"Content-Length: {DEFAULT_MAX_MESSAGE_BYTES + 1}\r\n\r\n".encode("ascii"),
    ],
)
def test_invalid_content_length_is_protocol_error_without_body_read(header_line):
    stream = CountingStream(header_line)
    buffer = FrameBuffer(mode=FramingMode.CONTENT_LENGTH)
    with pytest.raises(FramingProtocolError):
        _read_stdio_message(stream, buffer)
    assert all(n <= 1 or n <= DEFAULT_MAX_MESSAGE_BYTES for n in stream.read_sizes)
    assert not any(n > DEFAULT_MAX_MESSAGE_BYTES for n in stream.read_sizes)


def test_parse_content_length_rejects_negatives_and_oversize():
    with pytest.raises(FramingProtocolError):
        parse_content_length(
            b"Content-Length: -5", max_message_bytes=DEFAULT_MAX_MESSAGE_BYTES
        )
    with pytest.raises(FramingProtocolError):
        parse_content_length(
            b"Content-Length: nope", max_message_bytes=DEFAULT_MAX_MESSAGE_BYTES
        )
    with pytest.raises(FramingProtocolError, match="missing"):
        parse_content_length(b"X: 1", max_message_bytes=DEFAULT_MAX_MESSAGE_BYTES)
    with pytest.raises(FramingProtocolError, match="exceeds"):
        parse_content_length(
            f"Content-Length: {DEFAULT_MAX_MESSAGE_BYTES + 1}".encode(),
            max_message_bytes=DEFAULT_MAX_MESSAGE_BYTES,
        )


def test_body_shorter_than_declared_length_never_partial_parses():
    body = b'{"jsonrpc":"2.0","id":1,"method":"x"}'
    # Declare longer than actual remaining bytes.
    header = f"Content-Length: {len(body) + 10}\r\n\r\n".encode("ascii")
    buf = FrameBuffer(mode=FramingMode.CONTENT_LENGTH)
    buf.push(header + body)
    # Incomplete body: must not yield a message (never a partial parse).
    assert buf.take_message() is None
    assert buf.take_all() == []
    assert len(buf.pending) == len(header) + len(body)


def test_content_length_literal_in_body_does_not_change_parser_path():
    inner = encode_jsonrpc_message(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "echo",
                "arguments": {"note": "Content-Length: 999\nhijack"},
            },
        }
    )
    frame = _cl_frame(inner)
    buf = FrameBuffer(mode=FramingMode.CONTENT_LENGTH)
    buf.push(frame)
    got = buf.take_message()
    assert got == inner
    parsed = parse_jsonrpc(got)
    assert "Content-Length: 999" in parsed["params"]["arguments"]["note"]


def test_two_frames_in_one_push_both_parsed_none_dropped():
    a = encode_jsonrpc_message({"jsonrpc": "2.0", "id": 1, "method": "a"})
    b = encode_jsonrpc_message({"jsonrpc": "2.0", "id": 2, "method": "b"})
    buf = FrameBuffer(mode=FramingMode.CONTENT_LENGTH)
    buf.push(_cl_frame(a) + _cl_frame(b))
    msgs = buf.take_all()
    assert msgs == [a, b]
    assert buf.pending == b""


def test_frame_split_across_small_reads_matches_single_read():
    payload = encode_jsonrpc_message({"jsonrpc": "2.0", "id": 3, "method": "ping"})
    frame = _cl_frame(payload)
    one = FrameBuffer(mode=FramingMode.CONTENT_LENGTH)
    one.push(frame)
    assert one.take_message() == payload

    many = FrameBuffer(mode=FramingMode.CONTENT_LENGTH)
    for i in range(0, len(frame), 3):
        many.push(frame[i : i + 3])
        # Not complete until the end.
    assert many.take_message() == payload


def test_duplicate_json_keys_rejected():
    with pytest.raises(FramingProtocolError, match="duplicate"):
        parse_jsonrpc(b'{"jsonrpc":"2.0","jsonrpc":"2.0","id":1}')


@pytest.mark.parametrize(
    "raw",
    [
        b'{"id":1,"method":"x"}',
        b'{"jsonrpc":"1.0","id":1,"method":"x"}',
        b'{"jsonrpc":null,"id":1}',
    ],
)
def test_jsonrpc_field_absent_or_wrong_rejected(raw):
    with pytest.raises(FramingProtocolError, match="jsonrpc"):
        parse_jsonrpc(raw)


def test_freeze_roundtrip_byte_identical_same_digest():
    wire, digest = freeze_tools_call_bytes(
        request_id=1,
        tool_name="crm.read_contact",
        arguments={"note": "exact"},
        framed=True,
    )
    buf = FrameBuffer(mode=FramingMode.CONTENT_LENGTH)
    buf.push(wire)
    body = buf.take_message()
    assert body is not None
    rebuilt = frame_stdio(body)
    assert rebuilt == wire
    assert sha256_bytes_digest(rebuilt) == digest
    assert sha256_bytes_digest(wire) == digest


def test_key_order_different_arguments_same_digest():
    _, d1 = freeze_tools_call_bytes(
        request_id=1,
        tool_name="t",
        arguments={"a": 1, "b": 2},
        framed=True,
    )
    _, d2 = freeze_tools_call_bytes(
        request_id=1,
        tool_name="t",
        arguments={"b": 2, "a": 1},
        framed=True,
    )
    assert d1 == d2


def test_unicode_visually_identical_arguments_different_digests():
    # Latin 'e' + combining acute vs precomposed é
    a = {"name": "cafe\u0301"}
    b = {"name": "caf\u00e9"}
    assert a["name"] != b["name"]
    _, d1 = freeze_tools_call_bytes(request_id=1, tool_name="t", arguments=a)
    _, d2 = freeze_tools_call_bytes(request_id=1, tool_name="t", arguments=b)
    assert d1 != d2


def test_newline_framing_rejected_without_test_flag(credentials):
    from agent_dna.gateway.runtime import McpGateway
    from agent_dna.gateway.upstream import RecordingUpstream

    with pytest.raises(GatewayStartupError, match="test-only"):
        McpGateway(
            None,
            config=GatewayConfig(
                agent_api_key="pv_x",
                client_identity="x",
                transport="stdio",
                framing_mode=FramingMode.NEWLINE,
                _test_allow_newline_framing=False,
            ),
            credentials=credentials,
            upstream=RecordingUpstream(),
        )


def test_newline_framing_still_requires_runtime_even_with_test_flag(credentials):
    from agent_dna.gateway.runtime import McpGateway
    from agent_dna.gateway.upstream import RecordingUpstream

    with pytest.raises(GatewayStartupError, match="without a configured runtime"):
        McpGateway(
            None,
            config=GatewayConfig(
                agent_api_key="pv_x",
                client_identity="x",
                transport="stdio",
                framing_mode=FramingMode.NEWLINE,
                _test_allow_newline_framing=True,
            ),
            credentials=credentials,
            upstream=RecordingUpstream(),
        )
