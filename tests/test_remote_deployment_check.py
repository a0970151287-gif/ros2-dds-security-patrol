"""部署版本比對：存在性不是證據。

2026-10-07 的跨主機鏈跑到第 8 項才炸，因為樹莓派上帶的是 09-24 的
`response_backend.py`，而 `revoke_source` 是 09-25 加的。佈建前我盤點過那台
機器——而那次盤點問的是「檔案在不在」，三個相關模組**都在**。

這一組測試的重點不是「比對會不會動」，而是**只看存在性的版本會不會被咬住**。
最後一個測試就是那個變異：把判準換成存在性，一致與落後兩種情況都回報一致。
"""

from __future__ import annotations

import hashlib
import importlib.util
import pathlib
import sys

import pytest

_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

_TOOL = _ROOT / "工具腳本" / "check_remote_deployment.py"


def _mod():
    spec = importlib.util.spec_from_file_location("check_remote_deployment", _TOOL)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    # @dataclass 會查 sys.modules[cls.__module__]，動態載入時不註冊就會
    # 在定義 Finding 的當下炸成 'NoneType' object has no attribute '__dict__'。
    sys.modules["check_remote_deployment"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def repo(tmp_path):
    (tmp_path / "firewall_lab").mkdir()
    (tmp_path / "firewall_lab" / "response_backend.py").write_text(
        "def revoke_source(): ...\n", encoding="utf-8"
    )
    (tmp_path / "firewall_lab" / "decision.py").write_text("POLICY = 1\n", encoding="utf-8")
    return tmp_path


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _runner_for(mapping: dict[str, str | None], root: str = "/remote"):
    """產生一個假的 sha256sum 輸出；值為 None 代表遠端沒有那個檔案。"""
    def runner(command: str) -> str:
        lines = []
        for rel, content in mapping.items():
            if content is None:
                continue
            lines.append(f"{_sha(content)}  {root}/{rel}")
        return "\n".join(lines) + ("\n" if lines else "")
    return runner


PATHS = ["firewall_lab/response_backend.py", "firewall_lab/decision.py"]


def test_identical_deployment_is_a_match(repo):
    m = _mod()
    runner = _runner_for({
        "firewall_lab/response_backend.py": "def revoke_source(): ...\n",
        "firewall_lab/decision.py": "POLICY = 1\n",
    })
    found = m.compare(repo, PATHS, "/remote", runner=runner)
    assert [f.verdict for f in found] == ["match", "match"]
    assert all(f.ok for f in found)


def test_an_older_remote_copy_is_a_mismatch_not_a_match(repo):
    """2026-10-07 的實際情況：檔案在，但少了 revoke_source。"""
    m = _mod()
    runner = _runner_for({
        "firewall_lab/response_backend.py": "# 09-24 的版本,沒有 revoke_source\n",
        "firewall_lab/decision.py": "POLICY = 1\n",
    })
    found = m.compare(repo, PATHS, "/remote", runner=runner)
    by = {f.path: f for f in found}
    assert by["firewall_lab/response_backend.py"].verdict == "mismatch"
    assert by["firewall_lab/decision.py"].verdict == "match"


def test_missing_on_remote_is_reported_separately_from_mismatch(repo):
    """兩者的修法不同：缺檔要傳過去，版本不同要同步——不可以折疊成同一種。"""
    m = _mod()
    runner = _runner_for({
        "firewall_lab/response_backend.py": None,
        "firewall_lab/decision.py": "POLICY = 1\n",
    })
    found = m.compare(repo, PATHS, "/remote", runner=runner)
    by = {f.path: f for f in found}
    assert by["firewall_lab/response_backend.py"].verdict == "missing"
    assert by["firewall_lab/response_backend.py"].remote_sha is None


def test_a_failing_runner_must_not_look_like_agreement(repo):
    """連不上時最危險的輸出是「一致」。"""
    m = _mod()

    def exploding_runner(command: str) -> str:
        raise SystemExit("⛔ 遠端命令失敗")

    with pytest.raises(SystemExit):
        m.compare(repo, PATHS, "/remote", runner=exploding_runner)


def test_empty_remote_output_is_missing_not_match(repo):
    """ssh 成功但什麼都沒印（例如 root 權限不足）仍然不是一致。"""
    m = _mod()
    found = m.compare(repo, PATHS, "/remote", runner=lambda cmd: "")
    assert [f.verdict for f in found] == ["missing", "missing"]


def test_a_file_absent_locally_is_refused(repo):
    """本機沒有的檔案拿去比對遠端沒有意義,而且會讓結果看起來乾淨。"""
    m = _mod()
    with pytest.raises(SystemExit):
        m.compare(repo, ["firewall_lab/not_here.py"], "/remote",
                  runner=_runner_for({}))


def test_a_path_escaping_the_repo_is_refused(repo):
    m = _mod()
    with pytest.raises(SystemExit):
        m.compare(repo, ["../outside.py"], "/remote", runner=_runner_for({}))


def test_remote_paths_are_quoted(repo):
    """遠端根目錄或檔名含空白時不可以把命令拆開。"""
    m = _mod()
    seen = {}

    def capture(command: str) -> str:
        seen["cmd"] = command
        return ""

    m.remote_digests(["firewall_lab/decision.py"], "/home/a b/sros2", runner=capture)
    assert "'/home/a b/sros2/firewall_lab/decision.py'" in seen["cmd"]


def test_existence_only_would_have_missed_the_2026_10_07_bug(repo):
    """變異：把判準換成存在性,落後的副本就會被回報成一致。

    這正是佈建前那次盤點做的事,而它讓一條鏈跑到第 8 項才失敗。
    """
    m = _mod()
    stale = {
        "firewall_lab/response_backend.py": "# 09-24 的版本,沒有 revoke_source\n",
        "firewall_lab/decision.py": "POLICY = 1\n",
    }
    fresh = {
        "firewall_lab/response_backend.py": "def revoke_source(): ...\n",
        "firewall_lab/decision.py": "POLICY = 1\n",
    }

    def existence_only(mapping):
        remote = m.remote_digests(PATHS, "/remote", runner=_runner_for(mapping))
        return all(v is not None for v in remote.values())

    # 存在性檢查對兩者都說「可以」——它分不出來
    assert existence_only(stale) is True
    assert existence_only(fresh) is True

    # 而摘要比對分得出來
    stale_found = m.compare(repo, PATHS, "/remote", runner=_runner_for(stale))
    fresh_found = m.compare(repo, PATHS, "/remote", runner=_runner_for(fresh))
    assert any(not f.ok for f in stale_found)
    assert all(f.ok for f in fresh_found)


def test_the_runner_decodes_utf8_explicitly():
    """遠端回傳的是 UTF-8 檔名;用平台預設編碼解碼會讓中文路徑誤報缺席。

    2026-10-07 實測過這個失效:firewall_lab/*.py（ASCII）全部正確,
    工具腳本/*.py（中文）五個全部被回報成「遠端沒有這個檔案」,
    而它們正是那條鏈剛剛用過的檔案。

    這一條讀原始碼而不是跑 subprocess,因為 fake runner 永遠不會經過解碼那一層
    ——那正是當初那組測試全綠卻沒抓到這個 bug 的原因。
    """
    src = _TOOL.read_text(encoding="utf-8")
    assert 'encoding="utf-8"' in src, "default_runner 必須明寫 encoding"
    assert "capture_output=True, text=True" not in src, (
        "text=True 單獨使用會用平台預設編碼,在 Windows 上是 cp950／cp1252"
    )
