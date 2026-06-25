from sentineldeck.cli import main


def test_cli_rejects_invalid_domain(capsys):
    assert main(["scan", "bad target"]) == 2
    captured = capsys.readouterr()
    assert "Invalid domain" in captured.err


def test_cli_version_command(capsys):
    assert main(["version"]) == 0
    assert "SentinelDeck" in capsys.readouterr().out


def test_cli_checks_command_lists_surfaces(capsys):
    assert main(["checks"]) == 0
    out = capsys.readouterr().out
    assert "DNS" in out and "HTTP" in out


def test_cli_explain_known_finding_tailors_the_fix(capsys):
    assert main(["explain", "dmarc-missing", "--domain", "acme.test"]) == 0
    assert "_dmarc.acme.test" in capsys.readouterr().out


def test_cli_explain_unknown_finding_errors(capsys):
    assert main(["explain", "totally-unknown-id"]) == 1
    assert "no copy-paste fix" in capsys.readouterr().err
