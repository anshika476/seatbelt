"""render_png's optional dependency is reported, not raised."""

from __future__ import annotations

import bench.render_png as render_png


def test_missing_pillow_prints_one_clear_line(monkeypatch, capsys) -> None:
    monkeypatch.setattr(render_png, "Image", None)

    code = render_png.main([])

    captured = capsys.readouterr()
    lines = captured.err.strip().splitlines()
    assert code == 2
    assert captured.out == ""
    assert len(lines) == 1, lines
    assert "Pillow" in lines[0]
    assert '[report]' in lines[0]
    assert "Traceback" not in captured.err


def test_render_png_works_when_pillow_is_installed(tmp_path, capsys) -> None:
    """The published image path still runs end to end on the committed data."""
    import pytest

    pytest.importorskip("PIL", reason="optional report extra not installed")

    out = tmp_path / "results.png"
    code = render_png.main(["--results", "docs/results", "--out", str(out)])

    assert code == 0
    assert out.exists()
    assert out.stat().st_size > 1024