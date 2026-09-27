from src.logsentinel.parser import parse_line


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
