from src.logsentinel.parser import parse_line, load_events

def test_parse_line_accepts_valid_ipv6():
    line = (
        "Sep 08 18:00:00 server sshd[1234]: "
        "Failed password for root from 2001:db8::42 port 22 ssh2"
    )

    event = parse_line(line)

    assert event is not None
    assert event.source_ip == "2001:db8::42"
    assert event.username == "root"
    assert event.success is False

def test_parse_line_rejects_invalid_ipv4():
    line = (
        "Sep 08 18:00:00 server sshd[1234]: "
        "Failed password for root from 999.999.999.999 port 22 ssh2"
    )

    event = parse_line(line)

    assert event is None

def test_parse_line_rejects_invalid_timestamp():
    line = (
        "Sep 08 25:99:00 server sshd[1234]: "
        "Failed password for root from 192.168.1.10 port 22 ssh2"
    )

    event = parse_line(line)

    assert event is None

def test_parse_line_accepts_invalid_user_format():
    line = (
        "Sep 08 18:00:00 server sshd[1234]: "
        "Failed password for invalid user admin "
        "from 192.168.1.10 port 22 ssh2"
    )

    event = parse_line(line)

    assert event is not None
    assert event.username == "admin"
    assert event.source_ip == "192.168.1.10"
    assert event.success is False

def test_load_events_empty_file(tmp_path):
    log_file = tmp_path / "empty.log"
    log_file.write_text("")

    events = load_events(log_file)

    assert events == []


def test_load_events_skips_malformed_lines(tmp_path):
    log_file = tmp_path / "mixed.log"

    log_file.write_text(
        "Sep 08 18:00:00 server sshd[1234]: "
        "Failed password for root from 192.168.1.10 port 22 ssh2\n"
        "THIS IS NOT A VALID LOG\n"
        "Sep 08 18:00:05 server sshd[1234]: "
        "Failed password for admin from 192.168.1.10 port 22 ssh2\n"
    )

    events = load_events(log_file)

    assert len(events) == 2
    assert events[0].username == "root"
    assert events[1].username == "admin"

def test_parse_line_assigns_reference_year():
    line = (
        "Sep 08 18:00:00 server sshd[1234]: "
        "Failed password for root from 192.168.1.10 port 22 ssh2"
    )

    event = parse_line(line)

    assert event is not None
    assert event.timestamp.year == 2024
