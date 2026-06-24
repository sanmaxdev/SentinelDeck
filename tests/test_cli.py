from sentineldeck.cli import main


def test_cli_rejects_invalid_domain(capsys):
    assert main(["scan", "bad target"]) == 2
    captured = capsys.readouterr()
    assert "Invalid domain" in captured.err
