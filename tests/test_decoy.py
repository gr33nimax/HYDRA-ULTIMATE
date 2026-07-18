from unittest.mock import patch

from hydra.core.decoy import DECOY_DIRS, ensure_decoy_site


def test_hysteria2_has_its_own_status_decoy(tmp_path):
    site_dir = tmp_path / "hysteria2"
    with patch.dict(DECOY_DIRS, {"hysteria2": site_dir}):
        assert ensure_decoy_site("hysteria2") == site_dir

    index = (site_dir / "index.html").read_text(encoding="utf-8")
    assert "Northstar Cloud Status" in index
    assert "All systems operational" in index
    assert (site_dir / "css" / "style.css").is_file()
    assert (site_dir / "status.json").is_file()
