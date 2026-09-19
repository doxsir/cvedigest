# тесты на парсер и фильтр severity. сеть тут не трогаем вообще
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from main import parse_args, SEV

def test_plain():
    assert parse_args(["pip"]) == ("pip", None, 10, False, False, False)

def test_with_flags():
    assert parse_args(["pip", "--min", "high", "--limit", "5"]) == ("pip", "HIGH", 5, False, False, False)

def test_flags_only():
    # раньше вот тут всё ломалось, флаги после флага съедались
    assert parse_args(["--digest", "weekly", "--min", "high"]) == (None, "HIGH", 10, True, False, False)

def test_eco_after_flags():
    assert parse_args(["--digest", "weekly", "npm"]) == ("npm", None, 10, True, False, False)

def test_unknown_flag():
    assert parse_args(["pip", "--wat"]) == ("pip", None, 10, False, False, False)

def test_kev_flag():
    assert parse_args(["--kev", "npm"]) == ("npm", None, 10, False, True, False)
    assert parse_args(["--digest", "weekly", "--kev"]) == (None, None, 10, True, True, False)

def test_json_flag():
    assert parse_args(["--json", "pip", "--min", "critical"]) == ("pip", "CRITICAL", 10, False, False, True)

def test_sev_filter():
    items = [{"severity": "high"}, {"severity": "low"}, {"severity": "critical"}]
    out = [i["severity"] for i in items if SEV.get(i["severity"], 0) >= SEV["high"]]
    assert out == ["high", "critical"]
