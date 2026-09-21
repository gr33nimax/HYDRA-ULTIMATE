from hydra.ui._menus import users_links


def test_manual_artifact_output_has_no_qr_renderer(capsys):
    artifact = users_links._ClientArtifact("x", "X", "", "", "client-config", ("tg://proxy?x",))
    users_links._render_inline_artifact(artifact)
    output = capsys.readouterr().out
    assert "client-config" in output
    assert "tg://proxy?x" in output
    assert not hasattr(users_links, "_render_qr")


def test_manual_artifact_hides_redundant_mtproto_json_wrapper(capsys):
    link = "tg://proxy?server=example.com&port=443&secret=ee123"
    config = '{"link": "' + link + '", "protocol": "mtproto_zig"}'
    artifact = users_links._ClientArtifact("mtproto_zig", "MTProto Zig", "", "", config, (link,))

    users_links._render_inline_artifact(artifact)

    output = capsys.readouterr().out
    assert link in output
    assert '"protocol": "mtproto_zig"' not in output
    assert '"link":' not in output


def test_manual_artifact_keeps_nonredundant_json_config(capsys):
    link = "tg://proxy?x"
    config = '{"link": "tg://proxy?x", "protocol": "x", "setting": true}'

    users_links._render_inline_artifact(users_links._ClientArtifact("x", "X", "", "", config, (link,)))

    assert config in capsys.readouterr().out
