from collections import deque
from io import BytesIO
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from amnezia_router.system import DockerConnection, Runner


class DockerSocketStub:
    def __init__(self, responses, requests):
        self.responses = responses
        self.requests = requests

    def sendall(self, data):
        self.requests.append(data.split(b"\r\n", 1)[0].decode())

    def makefile(self, _mode):
        status, data = self.responses.popleft()
        body = json.dumps(data).encode()
        header = f"HTTP/1.1 {status} Response\r\nContent-Length: {len(body)}\r\n\r\n"
        return BytesIO(header.encode() + body)

    def close(self):
        pass


class DockerInspectionTests(unittest.TestCase):
    def setUp(self):
        self.requests = []
        self.responses = deque()
        transport = patch.object(DockerConnection, "connect", autospec=True, side_effect=self.connect)
        transport.start()
        self.addCleanup(transport.stop)

    def connect(self, connection):
        connection.sock = DockerSocketStub(self.responses, self.requests)

    def test_reads_fresh_identity_and_daemon_version(self):
        before = {"Id": "before", "State": {"Pid": 42}}
        after = {"Id": "after", "State": {"Pid": 43}}
        self.responses.extend([(200, {"ApiVersion": "1.44"}), (200, before),
                               (200, {"ApiVersion": "1.52"}), (200, after)])

        runner = Runner()
        self.assertEqual(runner.inspect("egress1"), before)
        self.assertEqual(runner.inspect("egress1"), after)
        self.assertEqual(self.requests, ["GET /version HTTP/1.1", "GET /v1.44/containers/egress1/json HTTP/1.1",
                                         "GET /version HTTP/1.1", "GET /v1.52/containers/egress1/json HTTP/1.1"])

    def test_missing_container_raises_without_exposing_response(self):
        self.responses.extend([(200, {"ApiVersion": "1.52"}),
                               (404, {"message": "private-response-body"})])

        with self.assertRaisesRegex(RuntimeError, "Docker API returned HTTP 404") as error:
            Runner().inspect("egress1")
        self.assertNotIn("private-response-body", str(error.exception))
