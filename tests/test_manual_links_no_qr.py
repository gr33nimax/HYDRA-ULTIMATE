from hydra.ui._menus import users_links


def test_manual_artifact_output_has_no_qr_renderer(capsys):
    artifact = users_links._ClientArtifact("x", "X", "", "", "client-config", ("tg://proxy?x",))
    users_links._render_inline_artifact(artifact)
    output = capsys.readouterr().out
    assert "client-config" in output
    assert "tg://proxy?x" in output
    assert not hasattr(users_links, "_render_qr")
