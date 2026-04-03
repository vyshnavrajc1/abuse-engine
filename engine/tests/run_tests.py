"""
Minimal test runner — no pytest dependency.
Run: python3 tests/run_tests.py
"""
import sys, traceback, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from datetime import datetime, timedelta
from engine.agents.auth_agent import AuthAgent
from engine.agents.temporal_agent import TemporalAgent
from engine.agents.volume_agent import VolumeAgent
from engine.coordinator.meta_agent import MetaAgentOrchestrator
from engine.memory.shared_memory import SharedMemory
from engine.tools.registry import ToolRegistry
from evaluation.evaluator import Evaluator
from schemas.models import EvidenceEntry, FusionVerdict, LogRecord, ThreatType

PASS = "\033[92m✓\033[0m"
FAIL = "\033[91m✗\033[0m"
results = []

def test(name, fn):
    t0 = time.time()
    try:
        fn()
        ms = (time.time()-t0)*1000
        print(f"  {PASS} {name}  ({ms:.0f}ms)")
        results.append(("PASS", name))
    except Exception as e:
        ms = (time.time()-t0)*1000
        print(f"  {FAIL} {name}  ({ms:.0f}ms)")
        traceback.print_exc()
        results.append(("FAIL", name))

def rec(ip="1.2.3.4", status=200, endpoint="/port_80",
        offset=0, label="BENIGN", cat="Benign", attack=False):
    return LogRecord(
        timestamp=datetime(2017,7,6,10,0,0)+timedelta(seconds=offset),
        ip=ip, method="GET", endpoint=endpoint, status=status,
        response_size=500, latency=10.0, user_agent="Mozilla/5.0",
        label=label, attack_category=cat, is_attack=attack,
        session_id=f"{ip}_s", endpoint_template=endpoint,
    )

def fresh():
    mem = SharedMemory(window_seconds=60)
    tools = ToolRegistry(mem)
    return mem, tools

# ── SharedMemory ────────────────────────────────────────────────────────────
print("\n[SharedMemory]")

def t_stm_push():
    mem,_ = fresh()
    mem.stm.push("ip:1.2.3.4", rec())
    w = mem.stm.get_window("ip:1.2.3.4")
    assert len(w)==1 and w[0].ip=="1.2.3.4"
test("STM push & retrieve", t_stm_push)

def t_stm_evict():
    mem = SharedMemory(window_seconds=1)
    mem.stm.push("ip:x", rec(offset=0))
    w = mem.stm.get_window("ip:x", reference_time=datetime(2017,7,6,10,0,5))
    assert len(w)==0
test("STM eviction", t_stm_evict)

def t_ltm_baseline():
    mem,_ = fresh()
    mem.ltm.record_rate("/port_80", 100.0)
    mem.ltm.record_rate("/port_80", 200.0)
    assert abs(mem.ltm.get_baseline_rate("/port_80") - 150.0) < 0.01
test("LTM baseline rate", t_ltm_baseline)

def t_board_post_read():
    mem,_ = fresh()
    mem.board.post(EvidenceEntry(posted_by="A", key="dos:x", value=1, confidence=0.9))
    r = mem.board.read(key_filter="dos")
    assert len(r)==1 and r[0].posted_by=="A"
test("EvidenceBoard post & read", t_board_post_read)

def t_board_confidence_filter():
    mem,_ = fresh()
    mem.board.post(EvidenceEntry(posted_by="A", key="t", value=1, confidence=0.3))
    mem.board.post(EvidenceEntry(posted_by="B", key="t", value=2, confidence=0.8))
    high = mem.board.read(min_confidence=0.7)
    assert len(high)==1 and high[0].posted_by=="B"
test("EvidenceBoard confidence filter", t_board_confidence_filter)

# ── ToolRegistry ─────────────────────────────────────────────────────────────
print("\n[ToolRegistry]")

def t_zscore_sig():
    _,tools = fresh()
    r = tools.call("run_statistical_test", values=[100.0]*10+[500.0], test="zscore")
    assert r["significant"] and r["z"]>3.0
test("Z-score significant spike", t_zscore_sig)

def t_zscore_not_sig():
    _,tools = fresh()
    r = tools.call("run_statistical_test", values=[100.,101.,99.,100.5,98.,102.], test="zscore")
    assert not r["significant"]
test("Z-score normal traffic", t_zscore_not_sig)

def t_entropy():
    _,tools = fresh()
    uni = tools.call("compute_entropy", values=["a","b","c","d"])
    skw = tools.call("compute_entropy", values=["a","a","a","b"])
    assert uni > skw
test("Entropy: uniform > skewed", t_entropy)

def t_periodic_bot():
    _,tools = fresh()
    ts = [float(i*100) for i in range(20)]
    r = tools.call("detect_periodicity", timestamps_ms=ts)
    assert r["periodic"] and r["bot_confidence"]>0.8
test("Periodicity: perfect bot", t_periodic_bot)

def t_post_read_evidence():
    _,tools = fresh()
    tools.call("post_to_evidence_board", posted_by="T", key="geo:1.1.1.1",
               value={"datacenter":True}, confidence=0.9)
    entries = tools.call("read_evidence_board", key_filter="geo:")
    assert len(entries)==1 and entries[0]["value"]["datacenter"]
test("post_to_evidence_board + read", t_post_read_evidence)

# ── VolumeAgent ──────────────────────────────────────────────────────────────
print("\n[VolumeAgent]")

def t_vol_clean():
    mem,tools = fresh()
    records = [rec(offset=i) for i in range(10)]
    f = VolumeAgent(mem,tools).run(records)
    assert f.confidence_score < 0.5
test("Clean traffic — no threat", t_vol_clean)

def t_vol_dos():
    mem,tools = fresh()
    records = [rec(ip="2.2.2.2", offset=i, label="DoS", cat="DoS", attack=True)
               for i in range(200)]
    f = VolumeAgent(mem,tools).run(records)
    assert f.threat_detected and f.threat_type==ThreatType.DOS
    assert f.confidence_score >= 0.8
test("200-req spike → DoS detected", t_vol_dos)

def t_vol_trace():
    mem,tools = fresh()
    f = VolumeAgent(mem,tools).run([rec(offset=i) for i in range(5)])
    assert any("OBSERVE" in t for t in f.reasoning_trace)
test("Reasoning trace populated", t_vol_trace)

def t_vol_baseline_update():
    mem,tools = fresh()
    agent = VolumeAgent(mem,tools)
    agent.run([rec(endpoint="/port_80", offset=i) for i in range(20)])
    assert mem.ltm.get_baseline_rate("/port_80") is not None
test("LTM baseline updated after run", t_vol_baseline_update)

# ── TemporalAgent ─────────────────────────────────────────────────────────────
print("\n[TemporalAgent]")

def t_temp_periodic_bot():
    mem,tools = fresh()
    records = [rec(ip="3.3.3.3", offset=i, label="Bot", cat="Botnet", attack=True)
               for i in range(20)]
    f = TemporalAgent(mem,tools).run(records)
    assert f.threat_detected and f.threat_type==ThreatType.BOT_ACTIVITY
test("Periodic 1-s traffic → bot detected", t_temp_periodic_bot)

def t_temp_sparse():
    mem,tools = fresh()
    records = [rec(offset=i*60) for i in range(3)]
    f = TemporalAgent(mem,tools).run(records)
    assert f.confidence_score < 0.5
test("Sparse traffic — no threat", t_temp_sparse)

def t_temp_off_hours():
    mem,tools = fresh()
    records = [
        LogRecord(timestamp=datetime(2017,7,6,3,i%60,0), ip="5.5.5.5",
                  method="GET", endpoint="/port_443", status=200,
                  label="BENIGN", attack_category="Benign", is_attack=False)
        for i in range(20)
    ]
    f = TemporalAgent(mem,tools).run(records)
    assert any("off_hours" in ind for ind in f.indicators)
test("3am requests → off_hours indicator", t_temp_off_hours)

def t_temp_reads_dos_evidence():
    mem,tools = fresh()
    mem.board.post(EvidenceEntry(posted_by="VolumeAgent", key="dos:high_volume",
                                 value=150, confidence=0.85, tags=["dos"]))
    records = [rec(ip="4.4.4.4", offset=i) for i in range(20)]
    f = TemporalAgent(mem,tools).run(records)
    # ORIENT should lift baseline confidence
    assert any("DoS evidence" in t for t in f.reasoning_trace)
test("Reads DoS evidence from board (ORIENT)", t_temp_reads_dos_evidence)

# ── AuthAgent ─────────────────────────────────────────────────────────────────
print("\n[AuthAgent]")

def t_auth_brute():
    mem,tools = fresh()
    records = [rec(ip="6.6.6.6", status=401, label="Brute Force",
                   cat="Brute Force", attack=True) for _ in range(15)]
    f = AuthAgent(mem,tools).run(records)
    assert f.threat_detected
    assert f.threat_type in (ThreatType.BRUTE_FORCE, ThreatType.CREDENTIAL_STUFFING)
test("15 consecutive 401s → brute force", t_auth_brute)

def t_auth_stuffing():
    mem,tools = fresh()
    # 194 failures + 6 successes from same IP = 3% success (classic stuffing signature)
    records = (
        [rec(ip="7.7.7.7", status=401, attack=True, cat="Brute Force") for _ in range(194)] +
        [rec(ip="7.7.7.7", status=200, attack=True, cat="Brute Force") for _ in range(6)]
    )
    f = AuthAgent(mem,tools).run(records)
    assert f.threat_detected and f.confidence_score >= 0.7
test("3% success rate → credential stuffing", t_auth_stuffing)

def t_auth_clean():
    mem,tools = fresh()
    records = [rec(status=200) for _ in range(20)]
    f = AuthAgent(mem,tools).run(records)
    assert f.confidence_score < 0.4
test("All 200s → no auth threat", t_auth_clean)

def t_auth_ltm_update():
    mem,tools = fresh()
    records = [rec(ip="8.8.8.8", status=401, attack=True, cat="Brute Force")
               for _ in range(10)]
    AuthAgent(mem,tools).run(records)
    assert mem.ltm.get_baseline_auth_failures("8.8.8.8") > 0
test("LTM auth failures updated", t_auth_ltm_update)

# ── MetaAgentOrchestrator ─────────────────────────────────────────────────────
print("\n[MetaAgentOrchestrator]")

def t_meta_clean():
    import random; rng = random.Random(99)
    offsets = [0]
    for _ in range(7):
        offsets.append(offsets[-1] + int(rng.expovariate(0.03)))
    records = [rec(offset=o) for o in offsets]
    v = MetaAgentOrchestrator(SharedMemory()).run(records)
    assert isinstance(v, FusionVerdict)
    # Irregular human traffic: no agent should reach HIGH-confidence threat
    assert not any(f.confidence.value == "HIGH" and f.threat_detected for f in v.agent_findings)
test("Clean irregular batch → no HIGH-conf threat", t_meta_clean)

def t_meta_dos():
    orch = MetaAgentOrchestrator(SharedMemory())
    records = [rec(ip="2.2.2.2", offset=i, attack=True, cat="DoS") for i in range(200)]
    v = orch.run(records)
    assert v.is_attack
    assert v.threat_type in (ThreatType.DOS, ThreatType.SCRAPING, ThreatType.BOT_ACTIVITY)
test("200-req DoS batch → attack detected", t_meta_dos)

def t_meta_compound():
    orch = MetaAgentOrchestrator(SharedMemory())
    # Periodic high-volume = compound Bot+DoS → Scraping
    records = [rec(ip="3.3.3.3", offset=i, attack=True, cat="DoS") for i in range(150)]
    v = orch.run(records)
    assert v.is_attack and v.confidence_score >= 0.5
test("Periodic high-volume → compound signal", t_meta_compound)

def t_meta_brute():
    orch = MetaAgentOrchestrator(SharedMemory())
    records = [rec(ip="9.9.9.9", status=401, attack=True, cat="Brute Force")
               for _ in range(20)]
    v = orch.run(records)
    assert v.is_attack
test("Brute-force batch → attack detected", t_meta_brute)

def t_meta_explanation():
    orch = MetaAgentOrchestrator(SharedMemory())
    v = orch.run([rec() for _ in range(10)])
    assert v.explanation and len(v.explanation) > 10
test("Verdict has explanation string", t_meta_explanation)

def t_meta_three_findings():
    orch = MetaAgentOrchestrator(SharedMemory())
    v = orch.run([rec() for _ in range(10)])
    assert len(v.agent_findings) == 3
test("Verdict has 3 agent findings", t_meta_three_findings)

def t_meta_contributing_agents():
    orch = MetaAgentOrchestrator(SharedMemory())
    records = [rec(ip="2.2.2.2", offset=i, attack=True, cat="DoS") for i in range(200)]
    v = orch.run(records)
    assert len(v.contributing_agents) >= 1
test("contributing_agents populated on attack", t_meta_contributing_agents)

# ── Evaluator ─────────────────────────────────────────────────────────────────
print("\n[Evaluator]")

def t_eval_ranges():
    orch = MetaAgentOrchestrator(SharedMemory())
    ev = Evaluator()
    for _ in range(3):
        batch = [rec() for _ in range(10)]
        v = orch.run(batch)
        for r in batch:
            ev.add(v, r.is_attack, r.attack_category)
    res = ev.compute()
    assert 0 <= res.precision <= 1
    assert 0 <= res.recall    <= 1
    assert 0 <= res.f1        <= 1
    assert 0 <= res.accuracy  <= 1
test("Metrics in [0,1] range", t_eval_ranges)

def t_eval_summary():
    orch = MetaAgentOrchestrator(SharedMemory())
    ev = Evaluator()
    batch = [rec() for _ in range(10)]
    v = orch.run(batch)
    for r in batch:
        ev.add(v, r.is_attack, r.attack_category)
    s = ev.compute().summary()
    assert "Precision" in s and "Recall" in s and "F1" in s
test("Summary string contains key metrics", t_eval_summary)

def t_eval_attack_batch():
    orch = MetaAgentOrchestrator(SharedMemory())
    ev = Evaluator()
    batch = [rec(ip="2.2.2.2", offset=i, attack=True, cat="DoS") for i in range(200)]
    v = orch.run(batch)
    for r in batch:
        ev.add(v, r.is_attack, r.attack_category)
    res = ev.compute()
    assert res.true_attacks == 200
test("true_attacks counted correctly", t_eval_attack_batch)

# ── Summary ──────────────────────────────────────────────────────────────────
passed = sum(1 for r,_ in results if r=="PASS")
failed = sum(1 for r,_ in results if r=="FAIL")
total  = len(results)

print(f"\n{'='*55}")
print(f"  Results: {passed}/{total} passed", end="")
if failed:
    print(f"  |  {failed} failed:")
    for r,name in results:
        if r=="FAIL":
            print(f"    ✗ {name}")
else:
    print("  — all green ✓")
print(f"{'='*55}\n")

sys.exit(0 if failed==0 else 1)
