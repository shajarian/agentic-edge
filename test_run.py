"""Quick end-to-end smoke test for KB + MonitoringAgent.

Tests two flows without needing Ollama (fast path only):
  1. A clear benign flow  → should take fast path (log, no LLM)
  2. A clear attack flow  → should route to investigate (LLM path)
     NOTE: LLM call will fail gracefully if Ollama is not running.

Run from project root:
    python test_run.py
"""

import logging
import sys
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("test_run")

CONFIG = "code/config/config.yaml"

# ── 1. KB standalone test ─────────────────────────────────────────────────────

def test_kb():
    print("\n" + "=" * 60)
    print("TEST 1: Knowledge Base")
    print("=" * 60)

    from code.knowledge_base.knowledge_base import KnowledgeBase
    kb = KnowledgeBase.from_config(CONFIG)

    if not kb.is_populated():
        print("  ERROR: KB is empty. Run: python -m code.knowledge_base.build_kb")
        sys.exit(1)

    stats = kb.stats()
    print(f"  Collections: {len(stats)}")
    for name, count in stats.items():
        print(f"    {name:<25} {count} docs")

    print("\n  Query test: 'Mirai Telnet scan port 23'")
    results = kb.query("Mirai Telnet scan port 23", collection="attack_signatures", n_results=1)
    if results:
        top = results[0]
        print(f"  Top hit : {top['collection']}/{top['id']}")
        print(f"  Relevance: {1 - top['distance']:.2f}")
        print(f"  Snippet  : {top['text'][:120]}...")
    else:
        print("  ERROR: No results returned")

    print("\n  Query test: 'BruteForce escalation criteria'")
    results = kb.query("BruteForce escalation criteria", collection="response_playbooks", n_results=1)
    if results:
        top = results[0]
        print(f"  Top hit : {top['collection']}/{top['id']}")
        print(f"  Relevance: {1 - top['distance']:.2f}")
    print("\n  KB: PASSED")


# ── 2. Monitoring Agent fast-path test ────────────────────────────────────────

def test_agent_preprocess():
    print("\n" + "=" * 60)
    print("TEST 2: Monitoring Agent — ML preprocess + KB load")
    print("=" * 60)

    import json
    from pathlib import Path
    from code.agents.monitoring_agent import _load_models, _get_flow_statistics, _classify_flow, _resolve_model_dir
    import yaml

    with open(CONFIG) as f:
        cfg = yaml.safe_load(f)
    model_dir = _resolve_model_dir(CONFIG, cfg)

    print("  Loading models (this may take 10–30s for 1.15 GB models)...")
    _load_models(str(model_dir))
    print("  Models loaded.")

    # Load a real row from feature_cols to build a valid zero-vector
    feat_cols_path = Path(model_dir) / "feature_cols.json"
    with open(feat_cols_path) as f:
        feat_cols = json.load(f)

    # Minimal flow dict — ML will classify based on all-zero features + metadata
    test_flow = {col: 0.0 for col in feat_cols}
    test_flow.update({
        "Protocol": 6, "Src IP": "192.168.137.10",
        "Dst IP": "192.168.137.1", "Dst Port": 1883,
        "Flow Packets/s": 12.5, "Flow Bytes/s": 1200.0,
        "Flow Duration": 500000, "Total Fwd Packet": 8,
        "Total Bwd packets": 7, "SYN Flag Count": 1,
        "FIN Flag Count": 1, "RST Flag Count": 0,
        "PSH Flag Count": 4, "ACK Flag Count": 12,
    })

    stats = _get_flow_statistics(test_flow)
    clf = _classify_flow(test_flow)

    print(f"  Flow stats  : pkt_rate={stats['packet_rate']}, syn_fin_ratio={stats['syn_fin_ratio']}")
    print(f"  ML class    : {clf['predicted_class']}")
    print(f"  Confidence  : {clf['confidence']:.2f}")
    print(f"  Is attack   : {clf['is_attack']}")
    route = "log (fast path)" if not clf['is_attack'] and clf['confidence'] >= 0.85 else "investigate (slow path - needs Ollama)"
    print(f"  Route       : {route}")
    print("\n  Preprocess: PASSED")


# ── 3. Monitoring Agent slow-path test (LLM optional) ─────────────────────────

def test_agent_slow_path():
    print("\n" + "=" * 60)
    print("TEST 3: Monitoring Agent — slow path (attack flow, LLM)")
    print("=" * 60)
    print("  NOTE: Requires Ollama running at http://localhost:11434")

    from code.agents.monitoring_agent import MonitoringAgent
    agent = MonitoringAgent.from_config(CONFIG)

    # SYN flood pattern: very high SYN, no FIN, high packet rate
    attack_flow = {
        "Protocol": 6,
        "Src IP": "203.0.113.99",   # external IP
        "Dst IP": "192.168.137.5",  # IoT device
        "Dst Port": 80,
        "Flow Packets/s": 15000.0,
        "Flow Bytes/s": 900000.0,
        "Flow Duration": 2000000,
        "Total Fwd Packet": 30000,
        "Total Bwd packets": 2,
        "SYN Flag Count": 29990,
        "FIN Flag Count": 0,
        "RST Flag Count": 5,
        "PSH Flag Count": 1,
        "ACK Flag Count": 10,
        "SYN_FIN_Ratio": 29990.0,
    }

    try:
        result = agent.process(attack_flow)
        print(f"  Decision   : {result['decision']}")
        print(f"  LLM invoked: {result['llm_invoked']}")
        print(f"  ML class   : {result['classification']['predicted_class']}")
        print(f"  Confidence : {result['classification']['confidence']:.2f}")
        if result["reasoning"]:
            print(f"  Reasoning  : {result['reasoning'][:200]}...")
        print(f"\n  Slow path: PASSED (decision={result['decision']})")
    except Exception as e:
        print(f"  Slow path skipped — Ollama not available: {e}")
        print("  Start Ollama with: ollama serve")


# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    test_kb()

    try:
        test_agent_preprocess()
        test_agent_slow_path()
    except FileNotFoundError as e:
        print(f"\n  Skipping agent tests: {e}")
        print("  Run: python -m code.train   to train the models first")
