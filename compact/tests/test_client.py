"""Loopback IRC and pseudo-terminal tests for TinyIRC 1.1.2.
Run: make test (after installing a C compiler and Python 3).
No external network or third-party packages required.
"""
import fcntl
import os
import pty
import re
import select
import socket
import subprocess
import termios
import threading
import time
import unittest
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1]
BINARY = Path(os.environ.get("TINYIRC_TEST_BINARY", SOURCE / "tinyirc"))


class FakeServer:
    def __init__(self):
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.listener.settimeout(4)
        self.port = self.listener.getsockname()[1]
        self.conn = None
        self.buffer = b""

    def accept(self, timeout=4):
        self.listener.settimeout(timeout)
        self.conn, _ = self.listener.accept()
        self.buffer = b""
        return self

    def line(self, timeout=3):
        deadline = time.monotonic() + timeout
        while b"\n" not in self.buffer:
            self.conn.settimeout(max(0.01, deadline - time.monotonic()))
            data = self.conn.recv(4096)
            if not data:
                raise AssertionError("client disconnected before sending a complete line")
            self.buffer += data
            if time.monotonic() > deadline:
                raise AssertionError("timed out waiting for IRC line")
        line, self.buffer = self.buffer.split(b"\n", 1)
        return line.rstrip(b"\r")

    def send(self, line):
        self.conn.sendall(line + b"\r\n")

    def expect_no_line(self, timeout=0.20):
        if b"\n" in self.buffer:
            raise AssertionError(f"unexpected buffered line: {self.buffer!r}")
        self.conn.settimeout(timeout)
        try:
            data = self.conn.recv(4096)
        except socket.timeout:
            return
        if data:
            self.buffer += data
            raise AssertionError(f"unexpected IRC data: {data!r}")

    def close(self):
        if self.conn:
            self.conn.close()
            self.conn = None
        self.listener.close()


class ClientTests(unittest.TestCase):
    def setUp(self):
        self.server = FakeServer()
        self.process = subprocess.Popen(
            [str(BINARY), "tester", "127.0.0.1", str(self.server.port), "-dumb"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self.server.accept()
        self.assertEqual(self.server.line(), b"NICK tester")
        self.assertTrue(self.server.line().startswith(b"USER "))

    def tearDown(self):
        if self.process.poll() is None:
            self.process.terminate()
        try:
            self.process.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.communicate(timeout=3)
        self.server.close()

    def command(self, data):
        if isinstance(data, str):
            data = data.encode()
        self.process.stdin.write(data + b"\n")
        self.process.stdin.flush()

    def welcome(self):
        self.server.send(b":irc 001 tester :Welcome")

    def finish(self):
        self.command("/quit")
        self.assertTrue(self.server.line().startswith(b"QUIT :"))
        stdout, stderr = self.process.communicate(timeout=4)
        self.assertEqual(self.process.returncode, 0, stderr)
        return stdout

    def test_registration_ping_commands_and_target_context(self):
        self.server.send(b"PING :heartbeat")
        self.assertEqual(self.server.line(), b"PONG :heartbeat")
        self.welcome()
        self.command("/join #room")
        self.assertEqual(self.server.line(), b"JOIN #room")
        self.server.send(b":tester!u@h JOIN :#room")
        self.assertEqual(self.server.line(), b"MODE #room")
        self.command("/join #room")
        self.server.expect_no_line()
        self.command("hello world")
        self.assertEqual(self.server.line(), b"PRIVMSG #room :hello world")
        self.command("/topic #room a topic with spaces")
        self.assertEqual(self.server.line(), b"TOPIC #room :a topic with spaces")
        self.command("/kick #room someNick the reason")
        self.assertEqual(self.server.line(), b"KICK #room someNick :the reason")
        self.command("/away testing status")
        self.assertEqual(self.server.line(), b"AWAY :testing status")
        self.command("/whois someNick")
        self.assertEqual(self.server.line(), b"WHOIS someNick")
        self.command("/part #room bye bye")
        self.assertEqual(self.server.line(), b"PART #room :bye bye")
        self.server.send(b":tester!u@h PART #room :bye bye")
        stdout = self.finish()
        self.assertIn(b"001 tester Welcome", stdout)

    def test_private_target_hex_and_incoming_decoding(self):
        self.welcome()
        self.command("/join Alice")
        self.server.expect_no_line()
        self.command("@Hi!")
        self.assertEqual(self.server.line(), b"PRIVMSG Alice :@486921")
        self.server.send(b":Alice!u@h PRIVMSG tester :@4869")
        self.command("#4869")
        self.server.expect_no_line()
        self.command("/part")
        self.server.expect_no_line()
        stdout = self.finish()
        self.assertIn(b"*Alice* Hi", stdout)
        self.assertIn(b"*** Hex: Hi", stdout)
        self.assertIn(b"Closed: Alice", stdout)

    def test_original_ctcp_ping_and_version_with_safe_payloads(self):
        self.welcome()
        self.server.send(b":Alice!u@h PRIVMSG tester :\x01PING 12345\x01")
        self.assertEqual(self.server.line(), b"NOTICE Alice :\x01PING 12345\x01")
        self.server.send(b":Alice!u@h PRIVMSG tester :\x01VERSION\x01")
        self.assertEqual(self.server.line(),
                         b"NOTICE Alice :\x01VERSION TinyIRC 1.1.2 :*ix\x01")
        self.server.send(b":Alice!u@h PRIVMSG tester :\x01PING bad\rbounce\x01")
        self.server.send(b"PING :afterbadctcp")
        self.assertEqual(self.server.line(), b"PONG :afterbadctcp")
        stdout = self.finish()
        self.assertIn(b"CTCP PING from Alice", stdout)
        self.assertIn(b"CTCP VERSION from Alice", stdout)

    def test_join_quit_and_other_channel_events_show_the_real_nick(self):
        self.welcome()
        self.command("/join #linux")
        self.assertEqual(self.server.line(), b"JOIN #linux")
        self.server.send(b":tester!u@h JOIN :#linux")
        self.assertEqual(self.server.line(), b"MODE #linux")
        self.server.send(b":Alice!u@h JOIN :#linux")
        self.server.send(b":Alice!u@h NICK :Alicia")
        self.server.send(b":Bob!u@h PART #linux :Later")
        self.server.send(b":Max!u@h QUIT :Max SendQ exceeded")
        self.server.send(b"PING :events-synced")
        self.assertEqual(self.server.line(), b"PONG :events-synced")
        output = self.finish()
        self.assertIn(b"*** Alice joined #linux", output)
        self.assertIn(b"*** Alice is now known as Alicia", output)
        self.assertIn(b"*** Bob left #linux: Later", output)
        self.assertIn(b"*** Max quit: Max SendQ exceeded", output)
        self.assertIn(b"*** tester joined #linux", output)

    def test_ping_measures_only_its_matching_server_or_ctcp_reply(self):
        self.welcome()

        def server_probe(command):
            self.command(command)
            line = self.server.line()
            match = re.fullmatch(rb"PING :(tinyirc-[0-9]+-[0-9]+)", line)
            self.assertIsNotNone(match, line)
            return match.group(1)

        def peer_probe(name):
            self.command("/ping " + name)
            line = self.server.line()
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
        self.assertEqual(len({first, second, third, alice, bob}), 5)
        self.command("/ping Alice extra")
        self.command("/ping #linux")
        self.server.expect_no_line()
        self.server.send(b":irc PONG irc :bogus")
        self.server.send(b":Mallory!u@h PONG irc :" + third)
        self.server.send(b":irc PONG irc :" + alice)  # A PONG is not Alice's RTT.
        self.server.send(b":Mallory!u@h NOTICE tester :\x01PING " + alice + b"\x01")
        self.server.send(b":Alice!u@h NOTICE someone-else :\x01PING " + alice + b"\x01")
        self.server.send(b":Bob!u@h NOTICE tester :\x01PING " + alice + b"\x01")
        self.server.send(b":bOb!u@h NOTICE tester :\x01PING " + bob + b"\x01")
        self.server.send(b":aLiCe!u@h NOTICE tester :\x01PING " + alice + b"\x01")
        self.server.send(b":irc PONG irc :" + third)
        self.server.send(b":irc PONG :" + first)
        self.server.send(b":irc PONG irc :" + second)
        self.server.send(b":irc PONG irc :" + second)  # Duplicate is unsolicited.
        self.server.send(b"PING :all-replies-seen")
        self.assertEqual(self.server.line(), b"PONG :all-replies-seen")
        output = self.finish()
        self.assertEqual(len(re.findall(rb"\*\*\* Server PING 127\.0\.0\.1: [0-9]+ ms", output)), 3)
        self.assertEqual(len(re.findall(rb"\*\*\* CTCP PING (?:Alice|Bob): [0-9]+ ms", output)), 2)
        self.assertIn(b"Usage: /ping", output)
        self.assertIn(b"*** PONG irc " + third, output)
        self.assertNotIn(b"*** CTCP PING Mallory:", output)

    def test_ping_user_without_ctcp_reply_has_no_fabricated_latency(self):
        self.welcome()
        self.command("/ping NoReply")
        line = self.server.line()
        self.assertTrue(line.startswith(b"PRIVMSG NoReply :\x01PING "), line)
        token = line.split(b"PING ", 1)[1][:-1]
        self.server.send(b":irc PONG irc :" + token)
        self.server.send(b"PING :no-ctcp-reply")
        self.assertEqual(self.server.line(), b"PONG :no-ctcp-reply")
        output = self.finish()
        self.assertIn(b"*** CTCP PING sent to NoReply", output)
        self.assertNotRegex(output, rb"\*\*\* CTCP PING NoReply: [0-9]+ ms")

    def test_irc_hispano_nick_password_is_sent_without_local_status_echo(self):
        self.welcome()
        for invalid in (b"/nick :dummy", b"/nick 2Bad:dummy",
                        b"/nick Nuevo:", b"/nick Nuevo:dummy extra",
                        b"/nick Nuevo:dummy\rINJECTED"):
            self.command(invalid)
        self.server.expect_no_line()
        self.command("/nick Nuevo:dummy:with-colon")
        self.assertEqual(self.server.line(), b"NICK Nuevo:dummy:with-colon")
        self.server.send(b":tester!u@h JOIN :#before")
        self.assertEqual(self.server.line(), b"MODE #before")
        self.server.send(b":tester!u@h NICK :Nuevo")
        self.server.send(b":Nuevo!u@h JOIN :#after")
        self.assertEqual(self.server.line(), b"MODE #after")
        output = self.finish()
        self.assertIn(b"Usage: /nick NICK[:PASSWORD]", output)
        self.assertIn(b"Warning: nickname password sent unencrypted", output)
        self.assertIn(b"Nick change requested: Nuevo", output)
        self.assertIn(b"*** tester is now known as Nuevo", output)
        self.assertNotIn(b"dummy", output)  # No *additional* local status echo.

    def test_nick_password_is_not_saved_while_disconnected(self):
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        result = subprocess.run(
            [str(BINARY), "tester", "127.0.0.1", str(port), "-dumb"],
            input=b"/nick Offline:dummy-offline\n/quit\n", capture_output=True,
            timeout=5,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(b"Not connected; nickname password not stored", result.stdout)
        self.assertNotIn(b"dummy-offline", result.stdout)
        self.assertNotIn(b"Nick saved for reconnect: Offline", result.stdout)

    def test_433_does_not_block_and_470_remains_server_information(self):
        self.server.send(b":irc 433 * tester :Nickname already in use")
        self.command("/nick tester2")
        self.assertEqual(self.server.line(), b"NICK tester2")
        self.server.send(b":tester!u@h NICK :tester2")
        self.command("/nick tester2:")  # Empty password is invalid.
        self.server.expect_no_line()
        self.command("/msg NickServ IDENTIFY TEST_ONLY_NOT_A_REAL_PASSWORD")
        self.assertEqual(self.server.line(),
                         b"PRIVMSG NickServ :IDENTIFY TEST_ONLY_NOT_A_REAL_PASSWORD")
        self.server.send(b":irc 470 tester #from #to :Forwarding is server information")
        self.server.expect_no_line()
        stdout = self.finish()
        self.assertIn(b"433 * tester Nickname already in use", stdout)
        self.assertIn(b"470 tester #from #to", stdout)
        self.assertIn(b"IDENTIFY TEST_ONLY_NOT_A_REAL_PASSWORD", stdout)
        self.assertIn(b"Usage: /nick", stdout)

    def test_bad_input_bad_server_line_and_terminal_escape_are_bounded(self):
        self.welcome()
        self.command("/join Bob")
        self.command("/msg Bob " + "a" * 500)
        self.server.expect_no_line()
        self.command("/msg Bob okay")
        self.assertEqual(self.server.line(), b"PRIVMSG Bob :okay")
        self.command("x" * 700)
        self.server.expect_no_line()
        self.server.send(b":irc PRIVMSG tester :" + b"x" * 600)
        self.server.send(b"PING :afteroverflow")
        self.assertEqual(self.server.line(), b"PONG :afteroverflow")
        self.server.send(b":Bad!u@h PRIVMSG tester :\x1b[2Jsafe\x9b2J\x03" + b"08,01text")
        self.server.send(":Friend!u@h PRIVMSG tester :Español áéí".encode())
        self.server.send(b"PING :afterutf8")
        self.assertEqual(self.server.line(), b"PONG :afterutf8")
        stdout = self.finish()
        self.assertIn(b"IRC line too long", stdout)
        self.assertIn(b"Oversized/binary input discarded", stdout)
        self.assertIn(b"Server line too long", stdout)
        self.assertIn(b"safe", stdout)
        self.assertIn("Español áéí".encode(), stdout)
        self.assertNotIn(b"\x1b[2J", stdout)
        self.assertNotIn(b"\x9b2J", stdout)

    def test_mode_remove_absent_flag_kick_and_malformed_messages(self):
        self.welcome()
        self.command("/join #room")
        self.assertEqual(self.server.line(), b"JOIN #room")
        self.server.send(b":tester!u@h JOIN #room")
        self.assertEqual(self.server.line(), b"MODE #room")
        for line in (b":", b"PING", b":bad!u@h PRIVMSG #room",
                     b"@tag=value :irc NOTICE tester :tagged notice",
                     b":irc 324 tester #room +nt",
                     b":op!u@h MODE #room -i+ms",
                     b":op!u@h KILL somebody :not us",
                     b":op!u@h KICK #room tester :bye"):
            self.server.send(line)
        self.server.send(b"PING :stillalive")
        self.assertEqual(self.server.line(), b"PONG :stillalive")
        self.command("message after kick")
        self.server.expect_no_line()
        stdout = self.finish()
        self.assertIn(b"op kicked tester from #room: bye", stdout)
        self.assertIn(b"No current target", stdout)
        self.assertIn(b"tagged notice", stdout)

    def test_server_context_and_explicit_switch_preserve_targets(self):
        self.welcome()
        self.command("/join #room")
        self.assertEqual(self.server.line(), b"JOIN #room")
        self.server.send(b":tester!u@h JOIN #room")
        self.assertEqual(self.server.line(), b"MODE #room")
        self.command("/join Alice")
        self.command("/switch *")
        self.command("not sent from server")
        self.server.expect_no_line()
        self.command("/whois tester")
        self.assertEqual(self.server.line(), b"WHOIS tester")
        self.command("/part")  # No target is selected; do not close either one.
        self.server.expect_no_line()
        self.command("/switch Alice")
        self.command("hello Alice")
        self.assertEqual(self.server.line(), b"PRIVMSG Alice :hello Alice")
        self.command("/switch #room")
        self.command("hello room")
        self.assertEqual(self.server.line(), b"PRIVMSG #room :hello room")
        self.command("/switch *")
        self.command("/switch")  # Server -> first open target (#room or Alice).
        self.command("after cycling")
        line = self.server.line()
        self.assertIn(line, (b"PRIVMSG #room :after cycling",
                             b"PRIVMSG Alice :after cycling"))
        stdout = self.finish()
        self.assertIn(b"Current target: server", stdout)
        self.assertIn(b"No current target", stdout)
        self.assertIn(b"Usage: /part", stdout)

    def test_reconnect_rejoins_only_confirmed_channel(self):
        self.welcome()
        self.command("/join #room")
        self.assertEqual(self.server.line(), b"JOIN #room")
        self.server.send(b":tester!u@h JOIN #room")
        self.assertEqual(self.server.line(), b"MODE #room")
        self.command("/ping")
        old_server_token = self.server.line().split(b" :", 1)[1]
        self.command("/ping Alice")
        old_peer_token = self.server.line().split(b"PING ", 1)[1][:-1]
        self.server.conn.sendall(b":oldserver NOTICE tester :unfinished fragment")
        self.server.conn.close()
        self.server.conn = None
        self.server.accept(timeout=4)
        self.assertEqual(self.server.line(), b"NICK tester")
        self.assertTrue(self.server.line().startswith(b"USER "))
        self.server.send(b":irc 001 tester :Welcome back")
        self.assertEqual(self.server.line(), b"JOIN #room")
        self.server.send(b":irc PONG irc :" + old_server_token)
        self.server.send(b":Alice!u@h NOTICE tester :\x01PING " + old_peer_token + b"\x01")
        self.server.send(b"PING :freshstream")
        self.assertEqual(self.server.line(), b"PONG :freshstream")
        output = self.finish()
        self.assertNotIn(b"unfinished fragment", output)
        self.assertNotRegex(output, rb"\*\*\* Server PING .*: [0-9]+ ms")
        self.assertNotRegex(output, rb"\*\*\* CTCP PING Alice: [0-9]+ ms")


class TerminalTests(unittest.TestCase):
    def test_esc_history_editing_and_tty_restoration(self):
        server = FakeServer()
        master, slave = pty.openpty()
        before = termios.tcgetattr(slave)
        recording = bytearray()
        done = threading.Event()
        flags = fcntl.fcntl(master, fcntl.F_GETFL)
        fcntl.fcntl(master, fcntl.F_SETFL, flags | os.O_NONBLOCK)

        def drain():
            while not done.is_set():
                r, _, _ = select.select([master], [], [], 0.02)
                if r:
                    try:
                        recording.extend(os.read(master, 65536))
                    except (OSError, BlockingIOError):
                        pass

        process = None
        thread = threading.Thread(target=drain, daemon=True)
        thread.start()
        try:
            process = subprocess.Popen(
                [str(BINARY), "tester", "127.0.0.1", str(server.port)],
                stdin=slave, stdout=slave, stderr=subprocess.PIPE,
            )
            server.accept()
            self.assertEqual(server.line(), b"NICK tester")
            self.assertTrue(server.line().startswith(b"USER "))
            server.send(b":irc 001 tester :Welcome")
            os.write(master, b"/join Alice\r/join Bob\r")
            deadline = time.monotonic() + 3
            while b"Now talking to Bob" not in recording and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertIn(b"Now talking to Bob", recording)
            os.write(master, b"\x1b")
            time.sleep(0.20)
            os.write(master, b"abc\x1b[DZ\r")
            self.assertEqual(server.line(), b"PRIVMSG Alice :abZc")
            os.write(master, b"\x10\r")
            self.assertEqual(server.line(), b"PRIVMSG Alice :abZc")
            os.write(master, b"/part\r")
            deadline = time.monotonic() + 3
            while b"Closed: Alice" not in recording and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertIn(b"Closed: Alice", recording)
            os.write(master, b"\x1b")  # Bob -> server (the only other context).
            deadline = time.monotonic() + 3
            while b"Current target: server" not in recording and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertIn(b"Current target: server", recording)
            os.write(master, b"/whois tester\r")
            self.assertEqual(server.line(), b"WHOIS tester")
            os.write(master, b"no channel selected\r")
            server.expect_no_line()
            os.write(master, b"\x1b")  # Server -> Bob, no target closed.
            time.sleep(0.20)
            os.write(master, b"okay\r")
            self.assertEqual(server.line(), b"PRIVMSG Bob :okay")
            os.write(master, b"\x03")
            self.assertEqual(process.wait(timeout=3), 128 + 2)
            self.assertEqual(termios.tcgetattr(slave), before)
        finally:
            if process and process.poll() is None:
                process.kill()
                process.wait(timeout=3)
            done.set()
            thread.join(timeout=2)
            if process and process.stderr:
                process.stderr.close()
            os.close(master)
            os.close(slave)
            server.close()

    def test_nick_password_is_unmasked_in_prompt_and_history_by_choice(self):
        server = FakeServer()
        master, slave = pty.openpty()
        before = termios.tcgetattr(slave)
        process = None
        secret_command = b"/nick Nuevo:dummy-unmasked"

        def read_until(fragment):
            seen = b""
            deadline = time.monotonic() + 3
            while fragment not in seen and time.monotonic() < deadline:
                if select.select([master], [], [], .1)[0]:
                    seen += os.read(master, 65536)
            self.assertIn(fragment, seen)

        try:
            process = subprocess.Popen(
                [str(BINARY), "tester", "127.0.0.1", str(server.port)],
                stdin=slave, stdout=slave, stderr=subprocess.PIPE,
            )
            server.accept()
            self.assertEqual(server.line(), b"NICK tester")
            self.assertTrue(server.line().startswith(b"USER "))
            os.write(master, secret_command)
            read_until(secret_command)  # The compact prompt deliberately has no masking.
            os.write(master, b"\r")
            self.assertEqual(server.line(), b"NICK Nuevo:dummy-unmasked")
            while select.select([master], [], [], .05)[0]:
                os.read(master, 65536)
            os.write(master, b"\x10")  # Ctrl-P recalls the unprotected history entry.
            read_until(secret_command)
            os.write(master, b"\x03")
            self.assertEqual(process.wait(timeout=3), 128 + 2)
            self.assertEqual(termios.tcgetattr(slave), before)
        finally:
            if process and process.poll() is None:
                process.kill()
                process.wait(timeout=3)
            if process and process.stderr:
                process.stderr.close()
            os.close(master)
            os.close(slave)
            server.close()


if __name__ == "__main__":
    unittest.main()
