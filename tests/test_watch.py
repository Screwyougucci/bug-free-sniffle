import json

from darthscanner import cli
from darthscanner.watch import run_watch


def test_watch_announces_new_findings_and_persists_state(tmp_path, monkeypatch, capsys):
    finding = {"finding_id": "abc123", "title": "Debug detail exposed", "severity": "medium",
               "url": "https://owned.example/", "confidence": "high",
               "confidence_score": 85, "evidence": "debug header observed"}

    def fake_main(argv):
        output = argv[argv.index("--output") + 1]
        with open(output, "w", encoding="utf-8") as handle:
            json.dump({"findings": [finding]}, handle)
        return 0

    monkeypatch.setattr(cli, "main", fake_main)
    result = run_watch(target="https://owned.example/", scope="scope.json", acknowledged=True,
                       interval=60, output=str(tmp_path / "watch.json"),
                       state_path=str(tmp_path / "state.json"), max_cycles=1)
    assert result == 0
    assert "[NEW SECURITY FINDING]" in capsys.readouterr().out
    state = json.loads((tmp_path / "state.json").read_text())
    assert state["seen_finding_ids"] == ["abc123"]
    assert state["findings"][0]["lifecycle_status"] == "active"
    assert state["findings"][0]["occurrences"] == 1
    report = json.loads((tmp_path / "watch.json").read_text())
    assert report["unique_findings"] == 1
    assert report["active_findings"] == 1


def test_watch_cycle_limit_is_per_invocation(tmp_path, monkeypatch):
    def fake_main(argv):
        with open(argv[argv.index("--output") + 1], "w", encoding="utf-8") as handle:
            json.dump({"findings": []}, handle)
        return 0
    monkeypatch.setattr(cli, "main", fake_main)
    state = tmp_path / "state.json"
    state.write_text(json.dumps({"target": "https://owned.example/", "cycles": 12,
                                 "seen_finding_ids": [], "findings": []}))
    run_watch(target="https://owned.example/", scope="scope.json", acknowledged=True,
              interval=60, output=str(tmp_path / "watch.json"),
              state_path=str(state), max_cycles=1)
    assert json.loads(state.read_text())["cycles"] == 13


def test_watch_refuses_state_for_different_target(tmp_path):
    state = tmp_path / "state.json"
    state.write_text(json.dumps({"target": "https://other.example/"}))
    try:
        run_watch(target="https://owned.example/", scope="scope.json", acknowledged=True,
                  interval=60, output=str(tmp_path / "watch.json"),
                  state_path=str(state), max_cycles=1)
    except ValueError as exc:
        assert "different target" in str(exc)
    else:
        raise AssertionError("expected target mismatch")


def test_watch_tracks_resolved_and_reappeared_findings(tmp_path, monkeypatch, capsys):
    cycle_reports = [
        {"findings": [{"finding_id": "stable-1", "title": "Header issue", "severity": "low"}]},
        {"findings": []},
        {"findings": [{"finding_id": "stable-1", "title": "Header issue", "severity": "low"}]},
    ]

    def fake_main(argv):
        output = argv[argv.index("--output") + 1]
        with open(output, "w", encoding="utf-8") as handle:
            json.dump(cycle_reports.pop(0), handle)
        return 0

    monkeypatch.setattr(cli, "main", fake_main)
    state = tmp_path / "state.json"
    output = tmp_path / "watch.json"
    run_watch(target="https://owned.example/", scope="scope.json", acknowledged=True,
              interval=60, output=str(output), state_path=str(state), max_cycles=3)
    saved = json.loads(state.read_text())
    finding = saved["findings"][0]
    assert finding["lifecycle_status"] == "active"
    assert finding["occurrences"] == 2
    assert finding["first_seen_cycle"] == 1
    assert finding["last_seen_cycle"] == 3
    assert any(row["status"] == "ok" for row in saved["history"])
    assert "[REAPPEARED FINDING]" in capsys.readouterr().out


def test_watch_keeps_history_bounded(tmp_path, monkeypatch):
    def fake_main(argv):
        with open(argv[argv.index("--output") + 1], "w", encoding="utf-8") as handle:
            json.dump({"findings": []}, handle)
        return 0

    monkeypatch.setattr(cli, "main", fake_main)
    state = tmp_path / "state.json"
    state.write_text(json.dumps({"target": "https://owned.example/", "cycles": 500,
                                 "seen_finding_ids": [], "findings": [],
                                 "history": [{"cycle": i} for i in range(500)]}))
    run_watch(target="https://owned.example/", scope="scope.json", acknowledged=True,
              interval=60, output=str(tmp_path / "watch.json"),
              state_path=str(state), max_cycles=1)
    assert len(json.loads(state.read_text())["history"]) == 500
