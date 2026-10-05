"""Offline regression tests: loopback IRC peer; no external IRC network needed."""
import os
import pty
import re
import select
import shutil
import socket
import ssl
import subprocess
import tempfile
import termios
import time
import unittest
from pathlib import Path

BIN = Path(__file__).resolve().parent.parent / "tinyirc"
TLS_TESTS = os.environ.get("TINYIRC_TEST_TLS") == "1"


class Peer:
    def __init__(self, sock):
        self.sock = sock
        self.pending = b""

    def line(self, timeout=5):
        deadline = time.monotonic() + timeout
        while b"\n" not in self.pending:
            remain = deadline - time.monotonic()
            if remain <= 0:
                raise TimeoutError("No IRC line received")
            ready, _, _ = select.select([self.sock], [], [], remain)
            if not ready:
                raise TimeoutError("No IRC line received")
            data = self.sock.recv(4096)
            if not data:
                raise EOFError("Client closed the connection")
            self.pending += data
        line, self.pending = self.pending.split(b"\n", 1)
        if not line.endswith(b"\r"):
            raise AssertionError(f"Missing CRLF: {line!r}")
        return line[:-1]

    def send(self, data):
        self.sock.sendall(data)


class Harness:
    def __init__(self, *, tls=False, cert=None, key=None, terminal=False, no_color=False):
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.listener.settimeout(8)
        port = self.listener.getsockname()[1]
        self.master = self.slave = None
        env = dict(os.environ, TERM="xterm" if terminal else "dumb")
        env.pop("NO_COLOR", None)
        if no_color:
            env["NO_COLOR"] = "1"
        args = [str(BIN), "--nick", "tester", "--server", "127.0.0.1",
                "--port", str(port)]
        if tls:
            args.append("--tls")
            env["SSL_CERT_FILE"] = str(cert)
        if not terminal:
            args.append("-dumb")
            std_in = subprocess.PIPE
            std_out = subprocess.PIPE
        else:
            self.master, self.slave = pty.openpty()
            self.old_term = termios.tcgetattr(self.slave)
            std_in = std_out = self.slave
        self.proc = subprocess.Popen(args, stdin=std_in, stdout=std_out,
                                     stderr=subprocess.PIPE, env=env)
        connection, _ = self.listener.accept()
        self.listener.close()
        if tls:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certfile=str(cert), keyfile=str(key))
            connection = context.wrap_socket(connection, server_side=True)
        self.peer = Peer(connection)

    def write(self, data):
        if isinstance(data, str):
            data = data.encode("utf-8")
        if self.master is not None:
            os.write(self.master, data)
        else:
            self.proc.stdin.write(data)
            self.proc.stdin.flush()

    def finish(self):
        # Every caller has already sent QUIT and observed it on the wire.
        # Writing another command here races with the client's normal exit.
        if self.master is None:
            stdout, stderr = self.proc.communicate(timeout=8)
        else:
            self.proc.wait(timeout=8)
            stdout = b""
            stderr = self.proc.stderr.read()
        self.peer.sock.close()
        if self.master is not None:
            os.close(self.master)
            os.close(self.slave)
        return stdout, stderr


class TestClient(unittest.TestCase):
    def test_usage_and_local_help_are_in_english(self):
        help_result = subprocess.run([str(BIN), "--help"], capture_output=True, timeout=5)
        self.assertEqual(help_result.returncode, 0)
        self.assertIn(b"Usage:", help_result.stderr)
        self.assertIn(b"--tls requires an OpenSSL-enabled build", help_result.stderr)
        bad_nick = subprocess.run([str(BIN), "--nick", "invalid:credential"],
                                  capture_output=True, timeout=5)
        self.assertNotEqual(bad_nick.returncode, 0)
        self.assertNotIn(b"credential", bad_nick.stdout + bad_nick.stderr)
        h = Harness()
        h.peer.line(); h.peer.line()
        h.write("/help\n/msg\n/quit done\n")
        self.assertEqual(h.peer.line(), b"QUIT :done")
        output, err = h.finish()
        self.assertEqual(h.proc.returncode, 0, err)
        self.assertIn(b"*** /msg nick text", output)
        self.assertIn(b"*** Usage: /msg target message", output)
        self.assertIn(b"*** Warning: unencrypted TCP connection", output)

    def test_registration_join_ping_ctcp_and_sanitization(self):
        h = Harness()
        self.assertEqual(h.peer.line(), b"NICK tester")
        self.assertTrue(h.peer.line().startswith(b"USER "))
        h.peer.send(b":srv 001 tester :Welcome\r\n")
        h.write("/join #test\n")
        self.assertEqual(h.peer.line(), b"JOIN #test")
        h.peer.send(b":tester!u@h JOIN :#test\r\n")
        self.assertEqual(h.peer.line(), b"MODE #test")
        h.write("hello\n")
        self.assertEqual(h.peer.line(), b"PRIVMSG #test :hello")
        h.peer.send(b"PING :tok")
        h.peer.send(b"en\r\n")
        self.assertEqual(h.peer.line(), b"PONG :token")
        h.peer.send(b"@time=2026-09-23T00:00:00Z :srv PING one :two\r\n")
        self.assertEqual(h.peer.line(), b"PONG one :two")
        h.peer.send(b":alice!x@y PRIVMSG tester :\x01VERSION\x01\r\n")
        self.assertEqual(h.peer.line(), b"NOTICE alice :\x01VERSION TinyIRC 1.2.0\x01")
        h.peer.send(b":bad!x@y PRIVMSG #test :hello\x1b[2Jworld\r\n")
        h.peer.send(b":bad!x@y PRIVMSG #test :@1b000a\r\n")
        h.peer.send(b"A" * 8500 + b"\r\nPING :afterbad\r\n")
        self.assertEqual(h.peer.line(), b"PONG :afterbad")
        h.write("/quit goodbye\n")
        self.assertEqual(h.peer.line(), b"QUIT :goodbye")
        output, err = h.finish()
        self.assertEqual(h.proc.returncode, 0, err)
        self.assertIn(b"*** TinyIRC 1.2.0\n"
                      b"*** Copyright (C) 1991-2007 Nathan I. Laredo\n"
                      b"*** Modified 2026 by @mmoroca & Arena.ai\n", output)
        self.assertNotIn(b"\x1b", output)
        self.assertIn(b"hello?[2Jworld", output)
        self.assertIn(b"Incoming line too long", output)

    def test_ping_measures_only_its_matching_server_or_ctcp_reply(self):
        h = Harness()
        self.assertEqual(h.peer.line(), b"NICK tester")
        self.assertTrue(h.peer.line().startswith(b"USER "))
        h.peer.send(b":srv 001 tester :Welcome\r\n")

        def server_probe(command):
            h.write(command + "\n")
            line = h.peer.line()
            match = re.fullmatch(rb"PING :(tinyirc-[0-9]+-[0-9]+)", line)
            self.assertIsNotNone(match, line)
            return match.group(1)

        def peer_probe(name):
            h.write("/ping " + name + "\n")
            line = h.peer.line()
            prefix = b"PRIVMSG " + name.encode() + b" :\x01PING "
            self.assertTrue(line.startswith(prefix) and line.endswith(b"\x01"), line)
            token = line[len(prefix):-1]
            self.assertRegex(token, rb"^tinyirc-[0-9]+-[0-9]+$")
            return token

        first = server_probe("/ping")
        second = server_probe("/PING server")
        third = server_probe("/ping molybdenum.libera.chat")
        alice = peer_probe("Alice")
        bob = peer_probe("Bob")
        silent = peer_probe("NoReply")
        self.assertEqual(len({first, second, third, alice, bob, silent}), 6)
        h.write("/ping Alice extra\n/ping #room\n/raw PING :opaque\n")
        self.assertEqual(h.peer.line(), b"PING :opaque")
        h.peer.send(b":srv PONG srv :bogus\r\n")
        h.peer.send(b":Mallory!u@h PONG srv :" + third + b"\r\n")
        h.peer.send(b":srv PONG srv :" + alice + b"\r\n")
        h.peer.send(b":srv PONG srv :" + silent + b"\r\n")
        h.peer.send(b":Mallory!u@h NOTICE tester :\x01PING " + alice + b"\x01\r\n")
        h.peer.send(b":Alice!u@h NOTICE someone-else :\x01PING " + alice + b"\x01\r\n")
        h.peer.send(b":Bob!u@h NOTICE tester :\x01PING " + alice + b"\x01\r\n")
        h.peer.send(b":bOb!u@h NOTICE tester :\x01PING " + bob + b"\x01\r\n")
        h.peer.send(b":aLiCe!u@h NOTICE tester :\x01PING " + alice + b"\x01\r\n")
        h.peer.send(b":srv PONG srv :" + third + b"\r\n")
        h.peer.send(b":srv PONG :" + first + b"\r\n")
        h.peer.send(b":srv PONG srv :" + second + b"\r\n")
        h.peer.send(b":srv PONG srv :" + second + b"\r\n")
        h.peer.send(b"PING :all-replies-seen\r\n")
        self.assertEqual(h.peer.line(), b"PONG :all-replies-seen")
        h.write("/quit done\n")
        self.assertEqual(h.peer.line(), b"QUIT :done")
        output, err = h.finish()
        self.assertEqual(h.proc.returncode, 0, err)
        self.assertEqual(len(re.findall(rb"\*\*\* Server PING 127\.0\.0\.1: [0-9]+ ms", output)), 3)
        self.assertEqual(len(re.findall(rb"\*\*\* CTCP PING (?:Alice|Bob): [0-9]+ ms", output)), 2)
        self.assertNotRegex(output, rb"\*\*\* CTCP PING NoReply: [0-9]+ ms")
        self.assertIn(b"*** CTCP PING sent to NoReply", output)
        self.assertIn(b"*** PONG srv " + third + b" [Mallory!u@h]", output)
        self.assertIn(b"Usage: /ping", output)
        self.assertIn(b"Raw command sent", output)

    def test_forwarded_channel_parts_once_without_a_stale_join(self):
        h = Harness()
        h.peer.line(); h.peer.line()
        h.peer.send(b":srv 001 tester :Welcome\r\n")
        h.write("/join #trivia\n")
        self.assertEqual(h.peer.line(), b"JOIN #trivia")
        h.peer.send(b":srv 470 tester #trivia ##Trivia :Forwarding to another channel\r\n"
                    b":tester!u@h JOIN :##Trivia\r\n")
        self.assertEqual(h.peer.line(), b"MODE ##Trivia")
        h.write("/targets\nplay\n")
        self.assertEqual(h.peer.line(), b"PRIVMSG ##Trivia :play")
        h.write("/part\n")
        self.assertEqual(h.peer.line(), b"PART ##Trivia")
        h.peer.send(b":tester!u@h PART ##Trivia :Bye\r\n")
        h.write("/targets\n/part\n/quit done\n")
        self.assertEqual(h.peer.line(), b"QUIT :done")
        output, err = h.finish()
        self.assertEqual(h.proc.returncode, 0, err)
        self.assertIn(b"*** Leaving ##Trivia...", output)
        self.assertIn(b"*** No open targets.", output)
        self.assertIn(b"*** Usage: /part [#channel] [reason]", output)
        self.assertNotIn(b"Pending JOIN cancelled for #trivia", output)
        self.assertNotIn(b"#trivia (pending)", output)

    def test_forwarded_channel_reconnects_to_final_destination(self):
        h = Harness()
        h.peer.line(); h.peer.line()
        h.peer.send(b":srv 001 tester :Welcome\r\n")
        h.write("/join #old old-key\n")
        self.assertEqual(h.peer.line(), b"JOIN #old old-key")
        h.peer.send(b":srv 470 tester #old ##Middle :Forwarded\r\n"
                    b":srv 470 tester ##Middle ###Final :Forwarded again\r\n"
                    b"PING :processed\r\n")
        self.assertEqual(h.peer.line(), b"PONG :processed")
        h.peer.sock.close()
        h.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        port = int(h.proc.args[h.proc.args.index("--port") + 1])
        h.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        h.listener.bind(("127.0.0.1", port))
        h.listener.listen(1)
        h.listener.settimeout(5)
        connection, _ = h.listener.accept()
        h.listener.close()
        h.peer = Peer(connection)
        self.assertEqual(h.peer.line(), b"NICK tester")
        self.assertTrue(h.peer.line().startswith(b"USER "))
        h.peer.send(b":srv 001 tester :Welcome back\r\n")
        self.assertEqual(h.peer.line(), b"JOIN ###Final")
        h.peer.send(b":tester!u@h JOIN :###Final\r\n")
        self.assertEqual(h.peer.line(), b"MODE ###Final")
        h.write("/part\n")
        self.assertEqual(h.peer.line(), b"PART ###Final")
        h.peer.send(b":tester!u@h PART ###Final :Bye\r\n")
        h.write("/targets\n/quit done\n")
        self.assertEqual(h.peer.line(), b"QUIT :done")
        output, err = h.finish()
        self.assertEqual(h.proc.returncode, 0, err)
        self.assertIn(b"*** No open targets.", output)
        self.assertNotIn(b"Pending JOIN cancelled", output)

    def test_forward_to_existing_target_does_not_duplicate_it(self):
        h = Harness()
        h.peer.line(); h.peer.line()
        h.peer.send(b":srv 001 tester :Welcome\r\n")
        h.write("/join ##Trivia\n")
        self.assertEqual(h.peer.line(), b"JOIN ##Trivia")
        h.peer.send(b":tester!u@h JOIN :##Trivia\r\n")
        self.assertEqual(h.peer.line(), b"MODE ##Trivia")
        h.write("/join #trivia\n")
        self.assertEqual(h.peer.line(), b"JOIN #trivia")
        h.peer.send(b":srv 470 tester #trivia ##Trivia :Already here\r\n"
                    b"PING :processed\r\n")
        self.assertEqual(h.peer.line(), b"PONG :processed")
        h.write("/targets\n/part\n")
        self.assertEqual(h.peer.line(), b"PART ##Trivia")
        h.peer.send(b":tester!u@h PART ##Trivia :Bye\r\n")
        h.write("/targets\n/quit done\n")
        self.assertEqual(h.peer.line(), b"QUIT :done")
        output, err = h.finish()
        self.assertEqual(h.proc.returncode, 0, err)
        self.assertNotIn(b"#trivia (pending)", output)
        self.assertIn(b"*** No open targets.", output)

    def test_irc_color_codes_are_stripped_in_dumb_mode(self):
        h = Harness()
        h.peer.line(); h.peer.line()
        h.peer.send(b":srv 001 tester :Welcome\r\n")
        h.peer.send(b":srv 332 tester ##Trivia :Welcome \x0308,01yellow\x0f "
                    b"\x02bold\x02 \x04FF8800orange\x0f end\r\n")
        h.peer.send(":bot!u@h PRIVMSG ##Trivia :  ▐▓▒░  \x0311!info\x0f "
                    "\x1funderlined\x1f\r\n".encode())
        h.peer.send(b"PING :fmt\r\n")
        self.assertEqual(h.peer.line(), b"PONG :fmt")
        h.write("/quit test\n")
        self.assertEqual(h.peer.line(), b"QUIT :test")
        output, err = h.finish()
        self.assertEqual(h.proc.returncode, 0, err)
        self.assertNotIn(b"\x1b", output)
        self.assertNotIn(b"\x03", output)
        self.assertNotIn(b"\x04", output)
        self.assertNotIn(b"?8,01", output)
        self.assertNotIn(b"?11!info", output)
        self.assertIn(b"Welcome yellow bold orange end", output)
        self.assertIn("  ▐▓▒░  !info underlined".encode(), output)

    def test_irc_colors_are_rendered_only_in_terminal(self):
        for no_color in (False, True):
            with self.subTest(no_color=no_color):
                h = Harness(terminal=True, no_color=no_color)
                h.peer.line(); h.peer.line()
                h.peer.send(b":srv 001 tester :Welcome\r\n")
                h.peer.send(b":bot!u@h PRIVMSG #trivia :\x0308,01Hello\x0f "
                            b"\x02friend\x02 \x04FF8800Orange\x0f\r\n")
                h.peer.send(b"PING :fmt\r\n")
                self.assertEqual(h.peer.line(), b"PONG :fmt")
                chunks = []
                deadline = time.monotonic() + 1
                while time.monotonic() < deadline:
                    ready, _, _ = select.select([h.master], [], [], .12)
                    if not ready:
                        break
                    chunks.append(os.read(h.master, 65536))
                output = b"".join(chunks)
                self.assertIn(b"Hello", output)
                self.assertIn(b"friend", output)
                self.assertIn(b"Orange", output)
                self.assertNotIn(b"\x03", output)
                self.assertNotIn(b"\x04", output)
                self.assertNotIn(b"?8,01", output)
                if no_color:
                    self.assertNotIn(b"\x1b[0;93;40m", output)
                    self.assertNotIn(b"\x1b[0;38;2;255;136;0m", output)
                else:
                    self.assertIn(b"\x1b[0;93;40m", output)
                    self.assertIn(b"\x1b[0;38;2;255;136;0m", output)
                h.write("/quit test\r")
                self.assertEqual(h.peer.line(), b"QUIT :test")
                h.proc.wait(timeout=8)
                h.peer.sock.close()
                h.proc.stderr.close()
                os.close(h.master)
                os.close(h.slave)

    def test_utf8_splitting_and_input_limits(self):
        h = Harness()
        h.peer.line(); h.peer.line()
        h.peer.send(b":srv 001 tester :Welcome\r\n")
        h.write("/join #test\n")
        self.assertEqual(h.peer.line(), b"JOIN #test")
        h.peer.send(b":tester!u@h JOIN #test\r\n")
        self.assertEqual(h.peer.line(), b"MODE #test")
        text = "😊naïve" * 280
        h.write(text + "\n")
        prefix = b"PRIVMSG #test :"
        received = b""
        while len(received) < len(text.encode()):
            line = h.peer.line()
            self.assertLessEqual(len(line) + 2, 512)
            self.assertTrue(line.startswith(prefix), line[:60])
            chunk = line[len(prefix):]
            chunk.decode("utf-8")  # never split in the middle of a character
            received += chunk
        self.assertEqual(received, text.encode())
        h.write("/raw PRIVMSG #test :" + "x" * 5000 + "\n")
        h.write(b"/raw PING :malicious\rINJECTED\n")
        h.write("/raw PING :ok\n")
        self.assertEqual(h.peer.line(), b"PING :ok")
        h.write("/part\n")
        self.assertEqual(h.peer.line(), b"PART #test")
        h.peer.send(b":tester!u@h PART #test :bye\r\n")
        h.write("/quit test\n")
        self.assertEqual(h.peer.line(), b"QUIT :test")
        output, err = h.finish()
        self.assertEqual(h.proc.returncode, 0, err)
        self.assertIn(b"Oversized or binary input", output)

    def test_network_specific_nick_password_without_echo(self):
        h = Harness()
        h.peer.line(); h.peer.line()
        h.peer.send(b":srv 433 tester tester :This nickname is registered\r\n")
        h.write("/nick mmoroca:paß:phrase\n")
        self.assertEqual(h.peer.line(), "NICK mmoroca:paß:phrase".encode())
        h.peer.send(b":srv 001 mmoroca :Welcome\r\n")
        h.write("/nick mmoroca:\n")
        h.write("/nick mmoroca:hidden extra\n")
        h.write(b"/nick mmoroca:pass\rINJECTED\n")
        h.write("/raw PING :still-safe\n")
        self.assertEqual(h.peer.line(), b"PING :still-safe")
        h.write("/quit test\n")
        self.assertEqual(h.peer.line(), b"QUIT :test")
        output, err = h.finish()
        self.assertEqual(h.proc.returncode, 0, err)
        self.assertIn(b"*** Nick change requested: mmoroca", output)
        self.assertIn(b"*** Usage: /nick NICK[:PASSWORD]", output)
        self.assertIn(b"Warning: nickname password queued over unencrypted IRC", output)
        for forbidden in ("paß:phrase".encode(), b"mmoroca:hidden", b"pass\rINJECTED"):
            self.assertNotIn(forbidden, output)
        self.assertNotIn(b"*** Nick change requested: mmoroca:", output)

    def test_nickserv_bare_identify_in_private_target_is_private(self):
        h = Harness()
        h.peer.line(); h.peer.line()
        h.peer.send(b":srv 001 tester :Welcome\r\n")
        h.write("/msg NickServ IDENTIFY tester first-guess\n")
        self.assertEqual(h.peer.line(), b"PRIVMSG NickServ :IDENTIFY tester first-guess")
        h.peer.send(b":NickServ!service@host NOTICE tester :Incorrect password\r\n"
                    b"PING :ready\r\n")
        self.assertEqual(h.peer.line(), b"PONG :ready")
        h.write("iDeNtIfY tester second-guess\n")
        self.assertEqual(h.peer.line(), b"PRIVMSG NickServ :iDeNtIfY tester second-guess")
        h.write("hello\n")
        self.assertEqual(h.peer.line(), b"PRIVMSG NickServ :hello")
        h.write("/quit done\n")
        self.assertEqual(h.peer.line(), b"QUIT :done")
        output, err = h.finish()
        self.assertEqual(h.proc.returncode, 0, err)
        self.assertEqual(output.count(b"NickServ identification message sent (arguments hidden)"), 2)
        self.assertIn(b"> hello", output)
        self.assertNotIn(b"first-guess", output)
        self.assertNotIn(b"second-guess", output)

    def test_nickserv_bare_identify_masks_and_skips_history(self):
        h = Harness(terminal=True)
        h.peer.line(); h.peer.line()
        h.peer.send(b":srv 001 tester :Welcome\r\n")
        h.write("/help\r")
        h.write("/msg NickServ IDENTIFY tester first-guess\r")
        self.assertEqual(h.peer.line(), b"PRIVMSG NickServ :IDENTIFY tester first-guess")
        h.peer.send(b":NickServ!service@host NOTICE tester :Incorrect password\r\n"
                    b"PING :ready\r\n")
        self.assertEqual(h.peer.line(), b"PONG :ready")
        h.write("iDeNtIfY tester second-sëcret")
        chunks = []
        deadline = time.monotonic() + 1
        while time.monotonic() < deadline:
            ready, _, _ = select.select([h.master], [], [], .15)
            if not ready:
                break
            chunks.append(os.read(h.master, 65536))
        prompt = b"".join(chunks)
        self.assertIn(b"iDeNtIfY " + b"*" * len("tester second-sëcret".encode()), prompt)
        self.assertNotIn("second-sëcret".encode(), prompt)
        h.write("\r")
        self.assertEqual(h.peer.line(), "PRIVMSG NickServ :iDeNtIfY tester second-sëcret".encode())
        h.write(b"\x10\r/quit done\r")  # Ctrl-P must recall /help
        self.assertEqual(h.peer.line(), b"QUIT :done")
        self.assertEqual(h.proc.wait(timeout=8), 0)
        tail = []
        while select.select([h.master], [], [], .05)[0]:
            tail.append(os.read(h.master, 65536))
        output = prompt + b"".join(tail)
        self.assertNotIn(b"first-guess", output)
        self.assertNotIn("second-sëcret".encode(), output)
        self.assertIn(b"NickServ identification message sent (arguments hidden)", output)
        h.peer.sock.close()
        h.proc.stderr.close()
        os.close(h.master)
        os.close(h.slave)

    def test_bare_identify_keyword_reappears_after_erasing_password(self):
        h = Harness(terminal=True)
        h.peer.line(); h.peer.line()
        h.peer.send(b":srv 001 tester :Welcome\r\n")
        h.write("/msg NickServ IDENTIFY tester first-guess\r")
        self.assertEqual(h.peer.line(), b"PRIVMSG NickServ :IDENTIFY tester first-guess")
        h.write("identify lost-secret")
        initial = []
        deadline = time.monotonic() + 1
        while time.monotonic() < deadline:
            ready, _, _ = select.select([h.master], [], [], .15)
            if not ready:
                break
            initial.append(os.read(h.master, 65536))
        self.assertNotIn(b"lost-secret", b"".join(initial))
        h.write(b"\x7f" * len(b"lost-secret") + b"\x7f")  # password, then space
        changed = []
        deadline = time.monotonic() + 1
        while time.monotonic() < deadline:
            ready, _, _ = select.select([h.master], [], [], .15)
            if not ready:
                break
            changed.append(os.read(h.master, 65536))
        self.assertIn(b"> identify", b"".join(changed))
        self.assertNotIn(b"lost-secret", b"".join(changed))
        h.write(" retry-secret\r")
        self.assertEqual(h.peer.line(), b"PRIVMSG NickServ :identify retry-secret")
        h.write("/quit done\r")
        self.assertEqual(h.peer.line(), b"QUIT :done")
        self.assertEqual(h.proc.wait(timeout=8), 0)
        tail = []
        while select.select([h.master], [], [], .05)[0]:
            tail.append(os.read(h.master, 65536))
        self.assertNotIn(b"retry-secret", b"".join(initial + changed + tail))
        h.peer.sock.close()
        h.proc.stderr.close()
        os.close(h.master)
        os.close(h.slave)

    def test_editing_identify_command_cannot_expose_its_secret(self):
        h = Harness(terminal=True)
        h.peer.line(); h.peer.line()
        h.peer.send(b":srv 001 tester :Welcome\r\n")
        h.write("/msg NickServ IDENTIFY tester visible-if-edited")
        chunks = []
        for _ in range(2):
            while select.select([h.master], [], [], .15)[0]:
                chunks.append(os.read(h.master, 65536))
        self.assertNotIn(b"visible-if-edited", b"".join(chunks))
        h.write(b"\x01X")  # edit the command prefix after typing the secret
        while select.select([h.master], [], [], .15)[0]:
            chunks.append(os.read(h.master, 65536))
        self.assertNotIn(b"visible-if-edited", b"".join(chunks))
        h.write("\r/raw PING :safe\r")
        self.assertEqual(h.peer.line(), b"PING :safe")
        h.write("/quit done\r")
        self.assertEqual(h.peer.line(), b"QUIT :done")
        self.assertEqual(h.proc.wait(timeout=8), 0)
        while select.select([h.master], [], [], .05)[0]:
            chunks.append(os.read(h.master, 65536))
        output = b"".join(chunks)
        self.assertNotIn(b"visible-if-edited", output)
        self.assertIn(b"Protected identification input changed; nothing sent", output)
        h.peer.sock.close()
        h.proc.stderr.close()
        os.close(h.master)
        os.close(h.slave)

    def test_explicit_identify_keyword_reappears_after_erasing_password(self):
        h = Harness(terminal=True)
        h.peer.line(); h.peer.line()
        h.peer.send(b":srv 001 tester :Welcome\r\n")
        h.write("/msg NickServ IDENTIFY old-pass")
        chunks = []
        while select.select([h.master], [], [], .15)[0]:
            chunks.append(os.read(h.master, 65536))
        self.assertNotIn(b"old-pass", b"".join(chunks))
        h.write(b"\x7f" * (len(b"old-pass") + 1))
        changed = []
        while select.select([h.master], [], [], .15)[0]:
            changed.append(os.read(h.master, 65536))
        self.assertIn(b"> /msg NickServ IDENTIFY", b"".join(changed))
        h.write(" new-pass\r")
        self.assertEqual(h.peer.line(), b"PRIVMSG NickServ :IDENTIFY new-pass")
        h.write("/quit done\r")
        self.assertEqual(h.peer.line(), b"QUIT :done")
        self.assertEqual(h.proc.wait(timeout=8), 0)
        while select.select([h.master], [], [], .05)[0]:
            chunks.append(os.read(h.master, 65536))
        output = b"".join(chunks + changed)
        self.assertNotIn(b"old-pass", output)
        self.assertNotIn(b"new-pass", output)
        h.peer.sock.close()
        h.proc.stderr.close()
        os.close(h.master)
        os.close(h.slave)

    def test_explicit_identify_can_erase_password_and_edit_keyword(self):
        h = Harness(terminal=True)
        h.peer.line(); h.peer.line()
        h.peer.send(b":srv 001 tester :Welcome\r\n")
        h.write("/msg nIcKsErV identify old-password")
        chunks = []
        while select.select([h.master], [], [], .15)[0]:
            chunks.append(os.read(h.master, 65536))
        h.write(b"\x7f" * (len(b"old-password") + len(b" y")))
        edited = []
        while select.select([h.master], [], [], .15)[0]:
            edited.append(os.read(h.master, 65536))
        h.write("y new-password\r")
        self.assertEqual(h.peer.line(), b"PRIVMSG nIcKsErV :identify new-password")
        h.write("/quit done\r")
        self.assertEqual(h.peer.line(), b"QUIT :done")
        self.assertEqual(h.proc.wait(timeout=8), 0)
        while select.select([h.master], [], [], .05)[0]:
            chunks.append(os.read(h.master, 65536))
        self.assertIn(b"> /msg nIcKsErV identif", b"".join(edited))
        self.assertNotIn(b"old-password", b"".join(chunks + edited))
        self.assertNotIn(b"new-password", b"".join(chunks + edited))
        h.peer.sock.close()
        h.proc.stderr.close()
        os.close(h.master)
        os.close(h.slave)

    def test_explicit_identify_can_edit_keyword_with_trailing_space_after_erasing_password(self):
        h = Harness(terminal=True)
        h.peer.line(); h.peer.line()
        h.peer.send(b":srv 001 tester :Welcome\r\n")
        h.write("/msg NickServ identify old-password")
        chunks = []
        while select.select([h.master], [], [], .15)[0]:
            chunks.append(os.read(h.master, 65536))
        h.write(b"\x7f" * len(b"old-password") + b"\x02\x02\x1b[3~")
        edited = []
        while select.select([h.master], [], [], .15)[0]:
            edited.append(os.read(h.master, 65536))
        h.write(b"y\x05new-password\r")
        self.assertEqual(h.peer.line(), b"PRIVMSG NickServ :identify new-password")
        h.write("/quit done\r")
        self.assertEqual(h.peer.line(), b"QUIT :done")
        self.assertEqual(h.proc.wait(timeout=8), 0)
        while select.select([h.master], [], [], .05)[0]:
            chunks.append(os.read(h.master, 65536))
        self.assertIn(b"> /msg NickServ identif ", b"".join(edited))
        self.assertNotIn(b"old-password", b"".join(chunks + edited))
        self.assertNotIn(b"new-password", b"".join(chunks + edited))
        h.peer.sock.close()
        h.proc.stderr.close()
        os.close(h.master)
        os.close(h.slave)

    def test_erasing_all_arguments_allows_insertions_in_command_prefix(self):
        h = Harness(terminal=True)
        h.peer.line(); h.peer.line()
        h.peer.send(b":srv 001 tester :Welcome\r\n")
        h.write("/msg NickServ IDENTIFY old-password")
        chunks = []
        while select.select([h.master], [], [], .15)[0]:
            chunks.append(os.read(h.master, 65536))
        h.write(b"\x7f" * len(b"old-password") + b"\x01X")
        edited = []
        while select.select([h.master], [], [], .15)[0]:
            edited.append(os.read(h.master, 65536))
        h.write("\r/msg NickServ IDENTIFY new-password\r")
        self.assertEqual(h.peer.line(), b"PRIVMSG NickServ :IDENTIFY new-password")
        h.write("/quit done\r")
        self.assertEqual(h.peer.line(), b"QUIT :done")
        self.assertEqual(h.proc.wait(timeout=8), 0)
        while select.select([h.master], [], [], .05)[0]:
            chunks.append(os.read(h.master, 65536))
        self.assertIn(b"> X/msg NickServ IDENTIFY ", b"".join(edited))
        self.assertNotIn(b"old-password", b"".join(chunks + edited))
        self.assertNotIn(b"new-password", b"".join(chunks + edited))
        h.peer.sock.close()
        h.proc.stderr.close()
        os.close(h.master)
        os.close(h.slave)

    def test_bare_identify_can_erase_password_and_edit_keyword(self):
        h = Harness(terminal=True)
        h.peer.line(); h.peer.line()
        h.peer.send(b":srv 001 tester :Welcome\r\n")
        h.write("/msg NickServ IDENTIFY initial-secret\r")
        self.assertEqual(h.peer.line(), b"PRIVMSG NickServ :IDENTIFY initial-secret")
        h.write("identify old-password")
        chunks = []
        while select.select([h.master], [], [], .15)[0]:
            chunks.append(os.read(h.master, 65536))
        h.write(b"\x7f" * (len(b"old-password") + len(b" y")))
        edited = []
        while select.select([h.master], [], [], .15)[0]:
            edited.append(os.read(h.master, 65536))
        h.write("y new-password\r")
        self.assertEqual(h.peer.line(), b"PRIVMSG NickServ :identify new-password")
        h.write("/quit done\r")
        self.assertEqual(h.peer.line(), b"QUIT :done")
        self.assertEqual(h.proc.wait(timeout=8), 0)
        while select.select([h.master], [], [], .05)[0]:
            chunks.append(os.read(h.master, 65536))
        self.assertIn(b"> identif", b"".join(edited))
        self.assertNotIn(b"old-password", b"".join(chunks + edited))
        self.assertNotIn(b"new-password", b"".join(chunks + edited))
        h.peer.sock.close()
        h.proc.stderr.close()
        os.close(h.master)
        os.close(h.slave)

    def test_nick_can_erase_password_and_colon(self):
        h = Harness(terminal=True)
        h.peer.line(); h.peer.line()
        h.peer.send(b":srv 001 tester :Welcome\r\n")
        h.write("/nick tester:old-password")
        chunks = []
        while select.select([h.master], [], [], .15)[0]:
            chunks.append(os.read(h.master, 65536))
        h.write(b"\x7f" * (len(b"old-password") + 1))
        edited = []
        while select.select([h.master], [], [], .15)[0]:
            edited.append(os.read(h.master, 65536))
        h.write(":new-password\r")
        self.assertEqual(h.peer.line(), b"NICK tester:new-password")
        h.write("/quit done\r")
        self.assertEqual(h.peer.line(), b"QUIT :done")
        self.assertEqual(h.proc.wait(timeout=8), 0)
        while select.select([h.master], [], [], .05)[0]:
            chunks.append(os.read(h.master, 65536))
        self.assertIn(b"> /nick tester", b"".join(edited))
        self.assertNotIn(b"old-password", b"".join(chunks + edited))
        self.assertNotIn(b"new-password", b"".join(chunks + edited))
        h.peer.sock.close()
        h.proc.stderr.close()
        os.close(h.master)
        os.close(h.slave)

    def test_delete_key_after_erasing_password_leaves_prefix_visible(self):
        h = Harness(terminal=True)
        h.peer.line(); h.peer.line()
        h.peer.send(b":srv 001 tester :Welcome\r\n")
        chunks = []
        h.write("/msg NickServ IDENTIFY old-secret")
        while select.select([h.master], [], [], .15)[0]:
            chunks.append(os.read(h.master, 65536))
        h.write(b"\x7f" * (len(b"old-secret") + 1) + b"\x02\x1b[3~")
        edited = []
        while select.select([h.master], [], [], .15)[0]:
            edited.append(os.read(h.master, 65536))
        self.assertIn(b"> /msg NickServ IDENTIF", b"".join(edited))
        h.write("Y new-secret\r")
        self.assertEqual(h.peer.line(), b"PRIVMSG NickServ :IDENTIFY new-secret")
        h.write("/nick tester:another-secret")
        while select.select([h.master], [], [], .15)[0]:
            chunks.append(os.read(h.master, 65536))
        h.write(b"\x7f" * len(b"another-secret") + b"\x02\x1b[3~")
        changed = []
        while select.select([h.master], [], [], .15)[0]:
            changed.append(os.read(h.master, 65536))
        self.assertIn(b"> /nick tester", b"".join(changed))
        h.write(":replacement\r")
        self.assertEqual(h.peer.line(), b"NICK tester:replacement")
        h.write("/quit done\r")
        self.assertEqual(h.peer.line(), b"QUIT :done")
        self.assertEqual(h.proc.wait(timeout=8), 0)
        while select.select([h.master], [], [], .05)[0]:
            chunks.append(os.read(h.master, 65536))
        output = b"".join(chunks + edited + changed)
        for secret in (b"old-secret", b"new-secret", b"another-secret", b"replacement"):
            self.assertNotIn(secret, output)
        h.peer.sock.close()
        h.proc.stderr.close()
        os.close(h.master)
        os.close(h.slave)

    def test_changing_target_silently_clears_masked_draft_and_accepts_input(self):
        h = Harness(terminal=True)
        h.peer.line(); h.peer.line()
        h.peer.send(b":srv 001 tester :Welcome\r\n")
        h.write("/join #other\r")
        self.assertEqual(h.peer.line(), b"JOIN #other")
        h.peer.send(b":tester!u@h JOIN :#other\r\n")
        self.assertEqual(h.peer.line(), b"MODE #other")
        h.write("/msg NickServ hello\r")
        self.assertEqual(h.peer.line(), b"PRIVMSG NickServ :hello")
        chunks = []
        for cmd, switches, fresh in (
            ("/msg NickServ IDENTIFY explicit-secret", b"\x17\x17", "fresh-one"),
            ("/nick tester:nick-secret", b"\x17\x17\x17", "fresh-two"),
        ):
            h.write(cmd)
            while select.select([h.master], [], [], .15)[0]:
                chunks.append(os.read(h.master, 65536))
            h.write(switches)  # repeat Ctrl-W without an intervening Enter
            after = []
            while select.select([h.master], [], [], .15)[0]:
                after.append(os.read(h.master, 65536))
            h.write(fresh + "\r")  # normal input must work immediately
            self.assertEqual(h.peer.line(), f"PRIVMSG NickServ :{fresh}".encode())
            chunks.extend(after)
        h.write("/quit done\r")
        self.assertEqual(h.peer.line(), b"QUIT :done")
        self.assertEqual(h.proc.wait(timeout=8), 0)
        while select.select([h.master], [], [], .05)[0]:
            chunks.append(os.read(h.master, 65536))
        output = b"".join(chunks)
        for secret in (b"explicit-secret", b"nick-secret"):
            self.assertNotIn(secret, output)
        self.assertNotIn(b"Target changed: protected input discarded", output)
        self.assertNotIn(b"Input discarded.", output)
        self.assertIn(b"Current target: #other", output)
        self.assertIn(b"Current target: NickServ", output)
        h.peer.sock.close()
        h.proc.stderr.close()
        os.close(h.master)
        os.close(h.slave)

    def test_target_switch_keeps_recognized_prefix_without_masked_characters(self):
        h = Harness(terminal=True)
        h.peer.line(); h.peer.line()
        h.peer.send(b":srv 001 tester :Welcome\r\n")
        h.write("/join #other\r")
        self.assertEqual(h.peer.line(), b"JOIN #other")
        h.peer.send(b":tester!u@h JOIN :#other\r\n")
        self.assertEqual(h.peer.line(), b"MODE #other")
        h.write("/msg NickServ hello\r")
        self.assertEqual(h.peer.line(), b"PRIVMSG NickServ :hello")
        h.write("/msg NickServ IDENTIFY")
        h.write(b"\x17")  # no password masked yet: keep the draft
        h.write(" first-secret\r")
        self.assertEqual(h.peer.line(), b"PRIVMSG NickServ :IDENTIFY first-secret")
        h.write("/nick tester:")
        h.write(b"\x17")  # colon but no password: keep the draft
        h.write("second-secret\r")
        self.assertEqual(h.peer.line(), b"NICK tester:second-secret")
        h.write("/quit done\r")
        self.assertEqual(h.peer.line(), b"QUIT :done")
        self.assertEqual(h.proc.wait(timeout=8), 0)
        chunks = []
        while select.select([h.master], [], [], .05)[0]:
            chunks.append(os.read(h.master, 65536))
        output = b"".join(chunks)
        self.assertNotIn(b"first-secret", output)
        self.assertNotIn(b"second-secret", output)
        self.assertNotIn(b"Target changed: protected input discarded", output)
        self.assertNotIn(b"Input discarded.", output)
        h.peer.sock.close()
        h.proc.stderr.close()
        os.close(h.master)
        os.close(h.slave)

    def test_single_private_target_cycles_to_server_without_closing(self):
        h = Harness(terminal=True)
        h.peer.line(); h.peer.line()
        h.peer.send(b":srv 001 tester :Welcome\r\n")
        h.write("/join NickServ\r")  # opens a private target, no JOIN on the wire
        h.write(b"\x17")  # NickServ -> server, even with only one open target
        h.write("/targets\r")
        h.write(b"\x17")  # server -> NickServ
        h.write("hello\r")
        self.assertEqual(h.peer.line(), b"PRIVMSG NickServ :hello")
        h.write("/quit done\r")
        self.assertEqual(h.peer.line(), b"QUIT :done")
        self.assertEqual(h.proc.wait(timeout=8), 0)
        chunks = []
        while select.select([h.master], [], [], .05)[0]:
            chunks.append(os.read(h.master, 65536))
        output = b"".join(chunks)
        self.assertIn(b"*** Current target: server", output)
        self.assertIn(b"> * (server)", output)
        self.assertIn(b"*** Current target: NickServ", output)
        h.peer.sock.close()
        h.proc.stderr.close()
        os.close(h.master)
        os.close(h.slave)

    def test_server_console_is_a_cycle_target_with_open_conversations(self):
        h = Harness(terminal=True)
        h.peer.line(); h.peer.line()
        h.peer.send(b":srv 001 tester :Welcome\r\n")
        h.write("/join #alpha\r")
        self.assertEqual(h.peer.line(), b"JOIN #alpha")
        h.peer.send(b":tester!u@h JOIN :#alpha\r\n")
        self.assertEqual(h.peer.line(), b"MODE #alpha")
        h.write("/msg NickServ hello\r")
        self.assertEqual(h.peer.line(), b"PRIVMSG NickServ :hello")
        h.write(b"\x17")  # from #alpha to the server console
        h.write("/WHOIS tester\r/targets\r")
        self.assertEqual(h.peer.line(), b"WHOIS tester")
        h.write("/switch\rhello\r")  # server -> NickServ with no argument
        self.assertEqual(h.peer.line(), b"PRIVMSG NickServ :hello")
        h.write("/switch\rchannel-hi\r")
        self.assertEqual(h.peer.line(), b"PRIVMSG #alpha :channel-hi")
        h.write("/switch\r")  # #alpha -> server again
        h.write("/quit done\r")
        self.assertEqual(h.peer.line(), b"QUIT :done")
        self.assertEqual(h.proc.wait(timeout=8), 0)
        chunks = []
        while select.select([h.master], [], [], .05)[0]:
            chunks.append(os.read(h.master, 65536))
        output = b"".join(chunks)
        self.assertIn(b"*** Current target: server", output)
        self.assertIn(b"> * (server)", output)
        self.assertIn(b"#alpha", output)
        self.assertIn(b"NickServ", output)
        h.peer.sock.close()
        h.proc.stderr.close()
        os.close(h.master)
        os.close(h.slave)

    def test_server_console_switch_discards_masked_draft_without_enter(self):
        h = Harness(terminal=True)
        h.peer.line(); h.peer.line()
        h.peer.send(b":srv 001 tester :Welcome\r\n")
        h.write("/join #alpha\r")
        self.assertEqual(h.peer.line(), b"JOIN #alpha")
        h.peer.send(b":tester!u@h JOIN :#alpha\r\n")
        self.assertEqual(h.peer.line(), b"MODE #alpha")
        h.write("/msg NickServ IDENTIFY server-console-secret")
        chunks = []
        while select.select([h.master], [], [], .15)[0]:
            chunks.append(os.read(h.master, 65536))
        h.write(b"\x17")  # #alpha -> server; clear the masked draft
        h.write("/WHOIS tester\r/targets\r")  # no extra Enter required
        self.assertEqual(h.peer.line(), b"WHOIS tester")
        h.write("/quit done\r")
        self.assertEqual(h.peer.line(), b"QUIT :done")
        self.assertEqual(h.proc.wait(timeout=8), 0)
        while select.select([h.master], [], [], .05)[0]:
            chunks.append(os.read(h.master, 65536))
        output = b"".join(chunks)
        self.assertIn(b"*** Current target: server", output)
        self.assertIn(b"> * (server)", output)
        self.assertNotIn(b"server-console-secret", output)
        self.assertNotIn(b"Target changed: protected input discarded", output)
        h.peer.sock.close()
        h.proc.stderr.close()
        os.close(h.master)
        os.close(h.slave)

    def test_explicit_server_console_selection_survives_new_private_targets(self):
        h = Harness(terminal=True)
        h.peer.line(); h.peer.line()
        h.peer.send(b":srv 001 tester :Welcome\r\n")
        h.write("/switch *\r")
        h.peer.send(b":NickServ!service@host PRIVMSG tester :Hello\r\nPING :ready\r\n")
        self.assertEqual(h.peer.line(), b"PONG :ready")
        h.write("/msg guest hello\r")
        self.assertEqual(h.peer.line(), b"PRIVMSG guest :hello")
        h.write("/targets\r/switch NickServ\r")
        h.write("hello\r")
        self.assertEqual(h.peer.line(), b"PRIVMSG NickServ :hello")
        h.write("/switch *\r/WHOIS tester\r")
        self.assertEqual(h.peer.line(), b"WHOIS tester")
        h.write("/quit done\r")
        self.assertEqual(h.peer.line(), b"QUIT :done")
        self.assertEqual(h.proc.wait(timeout=8), 0)
        chunks = []
        while select.select([h.master], [], [], .05)[0]:
            chunks.append(os.read(h.master, 65536))
        output = b"".join(chunks)
        self.assertIn(b"> * (server)", output)
        self.assertIn(b"*** Current target: server", output)
        self.assertNotIn(b"Unknown target.", output)
        h.peer.sock.close()
        h.proc.stderr.close()
        os.close(h.master)
        os.close(h.slave)

    def test_ordinary_draft_survives_target_switch(self):
        h = Harness(terminal=True)
        h.peer.line(); h.peer.line()
        h.peer.send(b":srv 001 tester :Welcome\r\n")
        h.write("/join #other\r")
        self.assertEqual(h.peer.line(), b"JOIN #other")
        h.peer.send(b":tester!u@h JOIN :#other\r\n")
        self.assertEqual(h.peer.line(), b"MODE #other")
        h.write("/msg NickServ hello\r")
        self.assertEqual(h.peer.line(), b"PRIVMSG NickServ :hello")
        h.write("ordinary draft")
        h.write(b"\x17\x17")  # from #other through the console to NickServ
        h.write(" continues\r")
        self.assertEqual(h.peer.line(), b"PRIVMSG NickServ :ordinary draft continues")
        h.write("/quit done\r")
        self.assertEqual(h.peer.line(), b"QUIT :done")
        self.assertEqual(h.proc.wait(timeout=8), 0)
        chunks = []
        while select.select([h.master], [], [], .05)[0]:
            chunks.append(os.read(h.master, 65536))
        self.assertNotIn(b"protected input discarded", b"".join(chunks))
        h.peer.sock.close()
        h.proc.stderr.close()
        os.close(h.master)
        os.close(h.slave)

    def test_server_forward_discards_protected_draft_without_leaking(self):
        h = Harness(terminal=True)
        h.peer.line(); h.peer.line()
        h.peer.send(b":srv 001 tester :Welcome\r\n")
        h.write("/join #old\r")
        self.assertEqual(h.peer.line(), b"JOIN #old")
        h.write("/msg NickServ IDENTIFY server-change-secret")
        chunks = []
        while select.select([h.master], [], [], .15)[0]:
            chunks.append(os.read(h.master, 65536))
        h.peer.send(b":srv 470 tester #old ##New :Forwarding\r\nPING :ready\r\n")
        self.assertEqual(h.peer.line(), b"PONG :ready")
        while select.select([h.master], [], [], .15)[0]:
            chunks.append(os.read(h.master, 65536))
        h.write("ordinary-after-forward\r/raw PING :safe\r")
        self.assertEqual(h.peer.line(), b"PRIVMSG ##New :ordinary-after-forward")
        self.assertEqual(h.peer.line(), b"PING :safe")
        h.write("/quit done\r")
        self.assertEqual(h.peer.line(), b"QUIT :done")
        self.assertEqual(h.proc.wait(timeout=8), 0)
        while select.select([h.master], [], [], .05)[0]:
            chunks.append(os.read(h.master, 65536))
        output = b"".join(chunks)
        self.assertNotIn(b"server-change-secret", output)
        self.assertNotIn(b"Target changed: protected input discarded", output)
        self.assertNotIn(b"Input discarded.", output)
        h.peer.sock.close()
        h.proc.stderr.close()
        os.close(h.master)
        os.close(h.slave)

    def test_removing_nick_separator_does_not_reveal_or_send_password(self):
        h = Harness(terminal=True)
        h.peer.line(); h.peer.line()
        h.peer.send(b":srv 001 tester :Welcome\r\n")
        h.write("/nick tester:private-pass")
        chunks = []
        while select.select([h.master], [], [], .15)[0]:
            chunks.append(os.read(h.master, 65536))
        self.assertNotIn(b"private-pass", b"".join(chunks))
        h.write(b"\x01" + b"\x06" * len(b"/nick tester") + b"\x1b[3~")
        while select.select([h.master], [], [], .15)[0]:
            chunks.append(os.read(h.master, 65536))
        self.assertNotIn(b"private-pass", b"".join(chunks))
        h.write("\r/raw PING :safe\r")
        self.assertEqual(h.peer.line(), b"PING :safe")
        h.write("/quit done\r")
        self.assertEqual(h.peer.line(), b"QUIT :done")
        self.assertEqual(h.proc.wait(timeout=8), 0)
        while select.select([h.master], [], [], .05)[0]:
            chunks.append(os.read(h.master, 65536))
        output = b"".join(chunks)
        self.assertNotIn(b"private-pass", output)
        self.assertIn(b"Protected identification input changed; nothing sent", output)
        h.peer.sock.close()
        h.proc.stderr.close()
        os.close(h.master)
        os.close(h.slave)

    def test_bare_identify_is_protected_before_password_if_target_changes(self):
        h = Harness(terminal=True)
        h.peer.line(); h.peer.line()
        h.peer.send(b":srv 001 tester :Welcome\r\n")
        h.write("/join #other\r")
        self.assertEqual(h.peer.line(), b"JOIN #other")
        h.peer.send(b":tester!u@h JOIN :#other\r\n")
        self.assertEqual(h.peer.line(), b"MODE #other")
        h.write("/msg NickServ IDENTIFY initial-pass\r")
        self.assertEqual(h.peer.line(), b"PRIVMSG NickServ :IDENTIFY initial-pass")
        h.write("/switch NickServ\r")
        h.write("identify")
        chunks = []
        while select.select([h.master], [], [], .15)[0]:
            chunks.append(os.read(h.master, 65536))
        self.assertIn(b"> identify", b"".join(chunks))
        h.write(b"\x17\x17\x17")  # #other -> server -> NickServ; keep unmasked prefix
        h.write(" before-switch-secret\r")
        self.assertEqual(h.peer.line(), b"PRIVMSG NickServ :identify before-switch-secret")
        h.write("/quit done\r")
        self.assertEqual(h.peer.line(), b"QUIT :done")
        self.assertEqual(h.proc.wait(timeout=8), 0)
        while select.select([h.master], [], [], .05)[0]:
            chunks.append(os.read(h.master, 65536))
        output = b"".join(chunks)
        self.assertNotIn(b"initial-pass", output)
        self.assertNotIn(b"before-switch-secret", output)
        self.assertNotIn(b"Target changed: protected input discarded", output)
        self.assertNotIn(b"Input discarded.", output)
        h.peer.sock.close()
        h.proc.stderr.close()
        os.close(h.master)
        os.close(h.slave)

    def test_explicit_identify_is_protected_before_password_if_prefix_changes(self):
        h = Harness(terminal=True)
        h.peer.line(); h.peer.line()
        h.peer.send(b":srv 001 tester :Welcome\r\n")
        h.write("/msg NickServ IDENTIFY")
        chunks = []
        while select.select([h.master], [], [], .15)[0]:
            chunks.append(os.read(h.master, 65536))
        h.write(b"\x01X")  # change the recognized prefix before typing a password
        while select.select([h.master], [], [], .15)[0]:
            chunks.append(os.read(h.master, 65536))
        h.write(" before-prefix-secret")
        while select.select([h.master], [], [], .15)[0]:
            chunks.append(os.read(h.master, 65536))
        self.assertNotIn(b"before-prefix-secret", b"".join(chunks))
        h.write("\r/raw PING :safe\r")
        self.assertEqual(h.peer.line(), b"PING :safe")
        h.write("/quit done\r")
        self.assertEqual(h.peer.line(), b"QUIT :done")
        self.assertEqual(h.proc.wait(timeout=8), 0)
        while select.select([h.master], [], [], .05)[0]:
            chunks.append(os.read(h.master, 65536))
        output = b"".join(chunks)
        self.assertNotIn(b"before-prefix-secret", output)
        self.assertIn(b"Protected identification input changed; nothing sent", output)
        h.peer.sock.close()
        h.proc.stderr.close()
        os.close(h.master)
        os.close(h.slave)

    def test_nick_password_is_protected_before_password_if_colon_removed(self):
        h = Harness(terminal=True)
        h.peer.line(); h.peer.line()
        h.peer.send(b":srv 001 tester :Welcome\r\n")
        h.write("/nick tester:")
        chunks = []
        while select.select([h.master], [], [], .15)[0]:
            chunks.append(os.read(h.master, 65536))
        h.write(b"\x01" + b"\x06" * len(b"/nick tester") + b"\x1b[3~")
        while select.select([h.master], [], [], .15)[0]:
            chunks.append(os.read(h.master, 65536))
        h.write("before-colon-secret")
        while select.select([h.master], [], [], .15)[0]:
            chunks.append(os.read(h.master, 65536))
        self.assertNotIn(b"before-colon-secret", b"".join(chunks))
        h.write("\r/raw PING :safe\r")
        self.assertEqual(h.peer.line(), b"PING :safe")
        h.write("/quit done\r")
        self.assertEqual(h.peer.line(), b"QUIT :done")
        self.assertEqual(h.proc.wait(timeout=8), 0)
        while select.select([h.master], [], [], .05)[0]:
            chunks.append(os.read(h.master, 65536))
        output = b"".join(chunks)
        self.assertNotIn(b"before-colon-secret", output)
        self.assertIn(b"Protected identification input changed; nothing sent", output)
        h.peer.sock.close()
        h.proc.stderr.close()
        os.close(h.master)
        os.close(h.slave)

    def test_bare_identify_is_not_exposed_if_target_changes_while_typing(self):
        h = Harness(terminal=True)
        h.peer.line(); h.peer.line()
        h.peer.send(b":srv 001 tester :Welcome\r\n")
        h.write("/join #other\r")
        self.assertEqual(h.peer.line(), b"JOIN #other")
        h.peer.send(b":tester!u@h JOIN :#other\r\n")
        self.assertEqual(h.peer.line(), b"MODE #other")
        h.write("/msg NickServ IDENTIFY tester initial-guess\r")
        self.assertEqual(h.peer.line(), b"PRIVMSG NickServ :IDENTIFY tester initial-guess")
        h.write("/switch NickServ\r")
        h.write("IDENTIFY tester stay-private")
        chunks = []
        deadline = time.monotonic() + 1
        while time.monotonic() < deadline:
            ready, _, _ = select.select([h.master], [], [], .15)
            if not ready:
                break
            chunks.append(os.read(h.master, 65536))
        self.assertIn(b"IDENTIFY " + b"*" * len(b"tester stay-private"), b"".join(chunks))
        h.write(b"\x17")  # Ctrl-W changes from NickServ to #other and clears the draft
        h.write("fresh-after-switch\r/raw PING :still-safe\r")
        self.assertEqual(h.peer.line(), b"PRIVMSG #other :fresh-after-switch")
        self.assertEqual(h.peer.line(), b"PING :still-safe")
        h.write("/quit done\r")
        self.assertEqual(h.peer.line(), b"QUIT :done")
        self.assertEqual(h.proc.wait(timeout=8), 0)
        while select.select([h.master], [], [], .05)[0]:
            chunks.append(os.read(h.master, 65536))
        output = b"".join(chunks)
        self.assertNotIn(b"stay-private", output)
        self.assertNotIn(b"initial-guess", output)
        self.assertNotIn(b"Target changed: protected input discarded", output)
        self.assertNotIn(b"Input discarded.", output)
        h.peer.sock.close()
        h.proc.stderr.close()
        os.close(h.master)
        os.close(h.slave)

    def test_nickserv_identify_does_not_send_before_registration(self):
        h = Harness()
        h.peer.line(); h.peer.line()
        h.peer.send(b":srv 433 * tester :Nickname is already in use.\r\nPING :ready\r\n")
        self.assertEqual(h.peer.line(), b"PONG :ready")
        h.write("/msg NickServ IDENTIFY tester unregistered-secret\n")
        h.write("/raw PING :still-alive\n")
        self.assertEqual(h.peer.line(), b"PING :still-alive")
        h.write("/quit done\n")
        self.assertEqual(h.peer.line(), b"QUIT :done")
        output, err = h.finish()
        self.assertEqual(h.proc.returncode, 0, err)
        self.assertIn(b"433 * tester Nickname is already in use.", output)
        self.assertIn(b"Wait for server registration", output)
        self.assertNotIn(b"use /nick NICK:PASSWORD", output)
        self.assertNotIn(b"unregistered-secret", output)

    def test_nickserv_identify_sends_exact_text_without_local_echo(self):
        h = Harness()
        h.peer.line(); h.peer.line()
        h.peer.send(b":srv 001 tester :Welcome\r\n")
        h.write("/msg NickServ IDENTIFY tester secret:one\n")
        self.assertEqual(h.peer.line(), b"PRIVMSG NickServ :IDENTIFY tester secret:one")
        h.write("/PrIvMsG nIcKsErV identify secret-two\n")
        self.assertEqual(h.peer.line(), b"PRIVMSG nIcKsErV :identify secret-two")
        h.write("/notice NickServ identify notice-secret\n")
        self.assertEqual(h.peer.line(), b"NOTICE NickServ :identify notice-secret")
        h.write(b"/msg NickServ IDENTIFY tester injected\rCOMMAND\n")
        h.write("/msg friend hello\n")
        self.assertEqual(h.peer.line(), b"PRIVMSG friend :hello")
        h.write("/msg NickServ IDENTIFYING nonsensitive\n")
        self.assertEqual(h.peer.line(), b"PRIVMSG NickServ :IDENTIFYING nonsensitive")
        h.write("/msg NickServ IDENTIFY tester " + "x" * 500 + "\n")
        h.write("/quit test\n")
        self.assertEqual(h.peer.line(), b"QUIT :test")
        output, err = h.finish()
        self.assertEqual(h.proc.returncode, 0, err)
        self.assertIn(b"-> friend: hello", output)
        self.assertIn(b"-> NickServ: IDENTIFYING nonsensitive", output)
        self.assertIn(b"NickServ IDENTIFY too long; nothing sent", output)
        self.assertIn(b"NickServ identification message sent (arguments hidden)", output)
        self.assertIn(b"Warning: NickServ identification queued over unencrypted IRC", output)
        self.assertNotIn(b"secret:one", output)
        self.assertNotIn(b"secret-two", output)
        self.assertNotIn(b"notice-secret", output)
        self.assertNotIn(b"injected", output)

    def test_nickserv_identify_masks_arguments_and_skips_history(self):
        h = Harness(terminal=True)
        h.peer.line(); h.peer.line()
        h.peer.send(b":srv 001 tester :Welcome\r\n")
        h.write("/help\r")
        h.write("/MsG nickserv iDeNtIfY tester Sëcret123")
        chunks = []
        deadline = time.monotonic() + 1
        while time.monotonic() < deadline:
            ready, _, _ = select.select([h.master], [], [], .15)
            if not ready:
                break
            chunks.append(os.read(h.master, 65536))
        prompt = b"".join(chunks)
        self.assertIn(b"/MsG nickserv iDeNtIfY " + b"*" * len("tester Sëcret123".encode()), prompt)
        self.assertNotIn("Sëcret123".encode(), prompt)
        h.write("\r")
        self.assertEqual(h.peer.line(), "PRIVMSG nickserv :iDeNtIfY tester Sëcret123".encode())
        h.write(b"\x10")  # Ctrl-P should recall /help, never the credential
        h.write("\r/quit done\r")
        self.assertEqual(h.peer.line(), b"QUIT :done")
        self.assertEqual(h.proc.wait(timeout=8), 0)
        tail = []
        while select.select([h.master], [], [], .05)[0]:
            tail.append(os.read(h.master, 65536))
        terminal_output = prompt + b"".join(tail)
        self.assertNotIn("Sëcret123".encode(), terminal_output)
        self.assertIn(b"NickServ identification message sent (arguments hidden)", terminal_output)
        h.peer.sock.close()
        h.proc.stderr.close()
        os.close(h.master)
        os.close(h.slave)

    def test_nick_password_is_not_saved_while_disconnected(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
        listener.close()  # connection is deliberately refused
        result = subprocess.run([str(BIN), "-dumb", "--nick", "tester",
                                 "--server", "127.0.0.1", "--port", str(port)],
                                input=b"/nick offline:never-store-this\n/quit done\n",
                                capture_output=True, timeout=8, env=dict(os.environ, TERM="dumb"))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(b"Not connected; password not stored", result.stdout)
        self.assertNotIn(b"never-store-this", result.stdout + result.stderr)

    def test_nick_password_is_masked_and_not_in_history(self):
        h = Harness(terminal=True)
        h.peer.line(); h.peer.line()
        h.peer.send(b":srv 001 tester :Welcome\r\n")
        h.write("/help\r")
        h.write("/nick alice:secrÉt")
        chunks = []
        deadline = time.monotonic() + 1
        while time.monotonic() < deadline:
            ready, _, _ = select.select([h.master], [], [], .15)
            if not ready:
                break
            chunks.append(os.read(h.master, 65536))
        prompt = b"".join(chunks)
        self.assertIn(b"/nick alice:*******", prompt)
        self.assertNotIn("secrÉt".encode(), prompt)
        h.write("\r")
        self.assertEqual(h.peer.line(), "NICK alice:secrÉt".encode())
        h.peer.send(b":tester!u@h NICK :alice\r\nPING :nick-ack\r\n")
        self.assertEqual(h.peer.line(), b"PONG :nick-ack")
        h.write(b"\x10")  # Ctrl-P must recall /help, not /nick alice:password
        h.write("\r")
        h.write("/quit done\r")
        self.assertEqual(h.peer.line(), b"QUIT :done")
        self.assertEqual(h.proc.wait(timeout=8), 0)
        tail = []
        while select.select([h.master], [], [], .05)[0]:
            tail.append(os.read(h.master, 65536))
        terminal_output = prompt + b"".join(tail)
        self.assertNotIn("secrÉt".encode(), terminal_output)
        self.assertIn(b"Nick change requested: alice", terminal_output)
        self.assertIn(b"/help", terminal_output)
        h.peer.sock.close()
        h.proc.stderr.close()
        os.close(h.master)
        os.close(h.slave)

    def test_reconnect_rejoins_channel(self):
        h = Harness()
        h.peer.line(); h.peer.line()
        h.peer.send(b":srv 001 tester :Welcome\r\n")
        h.write("/join #again\n")
        self.assertEqual(h.peer.line(), b"JOIN #again")
        h.peer.send(b":tester!u@h JOIN #again\r\n")
        self.assertEqual(h.peer.line(), b"MODE #again")
        h.write("/ping\n/ping Alice\n")
        old_server_token = h.peer.line().split(b" :", 1)[1]
        old_peer_token = h.peer.line().split(b"PING ", 1)[1][:-1]
        h.peer.sock.close()
        h.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Reconnection uses the same port: bind it anew after the previous listener closed.
        port = int(h.proc.args[h.proc.args.index("--port") + 1])
        h.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        h.listener.bind(("127.0.0.1", port))
        h.listener.listen(1)
        h.listener.settimeout(5)
        connection, _ = h.listener.accept()
        h.listener.close()
        h.peer = Peer(connection)
        self.assertEqual(h.peer.line(), b"NICK tester")
        self.assertTrue(h.peer.line().startswith(b"USER "))
        h.peer.send(b":srv 001 tester :Welcome back\r\n")
        self.assertEqual(h.peer.line(), b"JOIN #again")
        h.peer.send(b":srv PONG srv :" + old_server_token + b"\r\n")
        h.peer.send(b":Alice!u@h NOTICE tester :\x01PING " + old_peer_token + b"\x01\r\n")
        h.peer.send(b"PING :freshstream\r\n")
        self.assertEqual(h.peer.line(), b"PONG :freshstream")
        h.write("/quit bye\n")
        self.assertEqual(h.peer.line(), b"QUIT :bye")
        output, err = h.finish()
        self.assertEqual(h.proc.returncode, 0, err)
        self.assertNotRegex(output, rb"\*\*\* Server PING .*: [0-9]+ ms")
        self.assertNotRegex(output, rb"\*\*\* CTCP PING Alice: [0-9]+ ms")

    def test_ipv6_loopback(self):
        try:
            listener = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            listener.bind(("::1", 0))
        except OSError:
            self.skipTest("IPv6 loopback is unavailable")
        with listener:
            listener.listen(1)
            listener.settimeout(5)
            env = dict(os.environ, TERM="dumb")
            proc = subprocess.Popen([str(BIN), "-dumb", "--nick", "ipv6nick",
                                     "--server", "[::1]", "--port",
                                     str(listener.getsockname()[1])],
                                    stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, env=env)
            connection, _ = listener.accept()
            with connection:
                peer = Peer(connection)
                self.assertEqual(peer.line(), b"NICK ipv6nick")
                self.assertTrue(peer.line().startswith(b"USER "))
                peer.send(b"PING :v6\r\n")
                self.assertEqual(peer.line(), b"PONG :v6")
                proc.stdin.write(b"/quit test\n")
                proc.stdin.flush()
                self.assertEqual(peer.line(), b"QUIT :test")
            _, stderr = proc.communicate(timeout=6)
            self.assertEqual(proc.returncode, 0, stderr)

    def test_terminal_editor_and_tty_restore(self):
        h = Harness(terminal=True)
        h.peer.line(); h.peer.line()
        h.peer.send(b":srv 001 tester :Welcome\r\n")
        h.write("/join #test\r")
        self.assertEqual(h.peer.line(), b"JOIN #test")
        h.peer.send(b":tester!u@h JOIN #test\r\n")
        self.assertEqual(h.peer.line(), b"MODE #test")
        h.write(b"abc\x1b[DX\r")
        self.assertEqual(h.peer.line(), b"PRIVMSG #test :abXc")
        h.write("/quit done\r")
        self.assertEqual(h.peer.line(), b"QUIT :done")
        self.assertEqual(h.proc.wait(timeout=8), 0)
        new_term = termios.tcgetattr(h.slave)
        self.assertEqual(new_term[3], h.old_term[3])
        h.peer.sock.close()
        h.proc.stderr.close()
        os.close(h.master)
        os.close(h.slave)

    @unittest.skipUnless(TLS_TESTS and shutil.which("openssl"), "make TLS=1 test / OpenSSL needed")
    def test_verified_tls(self):
        with tempfile.TemporaryDirectory() as directory:
            cert = Path(directory) / "cert.pem"
            key = Path(directory) / "key.pem"
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048",
                            "-nodes", "-keyout", str(key), "-out", str(cert),
                            "-days", "1", "-subj", "/CN=localhost",
                            "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            h = Harness(tls=True, cert=cert, key=key)
            self.assertEqual(h.peer.line(), b"NICK tester")
            self.assertTrue(h.peer.line().startswith(b"USER "))
            h.peer.send(b"PING :secure\r\n")
            self.assertEqual(h.peer.line(), b"PONG :secure")
            h.peer.send(b":srv 001 tester :Welcome\r\nPING :registered\r\n")
            self.assertEqual(h.peer.line(), b"PONG :registered")
            h.write("/ping\n/ping Alice\n")
            server_token = h.peer.line().split(b" :", 1)[1]
            peer_token = h.peer.line().split(b"PING ", 1)[1][:-1]
            h.peer.send(b":srv PONG srv :" + server_token + b"\r\n")
            h.peer.send(b":Alice!u@h NOTICE tester :\x01PING " + peer_token + b"\x01\r\n")
            h.peer.send(b"PING :pings-processed\r\n")
            self.assertEqual(h.peer.line(), b"PONG :pings-processed")
            h.write("/nick secure:tlscredential\n")
            self.assertEqual(h.peer.line(), b"NICK secure:tlscredential")
            h.write("/msg NickServ IDENTIFY tester tls-nickserv-credential\n")
            self.assertEqual(h.peer.line(),
                             b"PRIVMSG NickServ :IDENTIFY tester tls-nickserv-credential")
            h.write("/quit bye\n")
            self.assertEqual(h.peer.line(), b"QUIT :bye")
            output, err = h.finish()
            self.assertEqual(h.proc.returncode, 0, err)
            self.assertIn(b"TLS certificate verified", output)
            self.assertRegex(output, rb"\*\*\* Server PING 127\.0\.0\.1: [0-9]+ ms")
            self.assertRegex(output, rb"\*\*\* CTCP PING Alice: [0-9]+ ms")
            self.assertNotIn(b"tlscredential", output)
            self.assertNotIn(b"tls-nickserv-credential", output)
            self.assertNotIn(b"nickname password queued over unencrypted IRC", output)
            self.assertNotIn(b"NickServ identification queued over unencrypted IRC", output)


    @unittest.skipUnless(TLS_TESTS and shutil.which("openssl"), "make TLS=1 test / OpenSSL needed")
    def test_tls_rejects_wrong_hostname(self):
        with tempfile.TemporaryDirectory() as directory:
            cert = Path(directory) / "cert.pem"
            key = Path(directory) / "key.pem"
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048",
                            "-nodes", "-keyout", str(key), "-out", str(cert),
                            "-days", "1", "-subj", "/CN=localhost",
                            "-addext", "subjectAltName=DNS:localhost"],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            listener.settimeout(6)
            port = listener.getsockname()[1]
            env = dict(os.environ, TERM="dumb", SSL_CERT_FILE=str(cert))
            proc = subprocess.Popen([str(BIN), "--tls", "-dumb", "--nick", "tester",
                                     "--server", "127.0.0.1", "--port", str(port)],
                                    stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, env=env)
            connection, _ = listener.accept()
            listener.close()
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certfile=str(cert), keyfile=str(key))
            try:
                connection = context.wrap_socket(connection, server_side=True)
                connection.settimeout(2)
                self.assertEqual(connection.recv(512), b"")  # no NICK before verification
            except ssl.SSLError:
                pass  # peer aborting a failed handshake is also correct
            finally:
                connection.close()
            proc.stdin.write(b"/quit\n")
            proc.stdin.flush()
            output, err = proc.communicate(timeout=6)
            self.assertEqual(proc.returncode, 0, err)
            self.assertNotIn(b"TLS certificate verified", output)
            self.assertIn(b"TLS handshake", output)


if __name__ == "__main__":
    unittest.main()
