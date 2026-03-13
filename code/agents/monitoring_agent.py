"""Monitoring Agent: First stage of IoT incident response pipeline.

Hybrid ML+LLM architecture for network flow analysis at edge gateways.
Routes high-confidence benign flows through fast path (ML only, ~10ms) and 
suspicious flows through slow path (LLM reasoning with tools, ~1-3s).

Architecture:
    Flow → preprocess (stats + ML) → route
        ├─→ log (benign, conf ≥ 0.85)          [70-85% traffic, no LLM] 
        └─→ investigate (LLM + tools) → decide  [15-30% traffic, LLM invoked]

ML Models (from train.py):
    - Binary classifier: 97.28% accuracy (attack vs benign gate)
    - Multi-class: 91.15% weighted F1 (attack type ID)
    - Size: 1.15 GB (edge consideration)

LLM Tools (grounded to prevent hallucination):
    - check_flow_baseline: Hardcoded protocol rate thresholds 
    - get_recent_events_for_ip: Query EventStore for IP reputation
    - escalate_to_incident_manager: Structured handoff with reasoning

Example:
    agent = MonitoringAgent.from_config("code/config/config.yaml")
    result = agent.process(flow_dict)
    if result["decision"] == "escalate":
        handle_incident(result)
"""

import json
import logging
from pathlib import Path
from typing import Any, Optional, TypedDict

import numpy as np
from langchain_core.tools import tool
from langchain_ollama import ChatOllama
from langgraph.prebuilt import create_react_agent
from langgraph.graph import StateGraph, START, END

logger = logging.getLogger(__name__)


# Module state: Models loaded once at startup (1.15 GB).
# Thread-safe for predict(); EventStore needs locks if multi-threaded.
_models: dict = {}  # {"rf_multi": RF, "rf_binary": RF, "feat_cols": list}
_benign_confidence_threshold: float = 0.85
_event_store: Any = None  # Shared EventStore for multi-agent context
_knowledge_base: Any = None  # ChromaDB knowledge base (optional, loaded at startup)


def _resolve_model_dir(config_path: str, cfg: dict[str, Any]) -> Path:
    """Resolve model directory from config, defaulting to <root>/results/models.
    
    Resolves against project root (not CWD) for reliable path handling.
    """
    cfg_file = Path(config_path).resolve()
    project_root = cfg_file.parents[2] if len(cfg_file.parents) >= 3 else cfg_file.parent

    configured = (cfg.get("paths", {}) or {}).get("models")
    if configured:
        path = Path(configured)
        return path if path.is_absolute() else (project_root / path)

    return project_root / "results" / "models"


def _load_models(model_dir: str):
    """Load ML artifacts into module-level state (singleton, called once at startup).
    
    Required files (1.15 GB total from train.py):
        - rf_multiclass.joblib: 8-class attack classifier (F1=0.91)
        - rf_binary.joblib: Binary attack gate (acc=97.28%)
        - feature_cols.json: 77 feature names in exact order

    Raises:
        FileNotFoundError: If artifacts missing (run: python -m code.train)
    """
    import joblib
    d = Path(model_dir)
    
    required = [d / "rf_multiclass.joblib", d / "rf_binary.joblib", d / "feature_cols.json"]
    missing = [str(p) for p in required if not p.exists()]
    if missing:
        raise FileNotFoundError(f"Missing models: {', '.join(missing)}. Run: python -m code.train")

    _models["rf_multi"] = joblib.load(d / "rf_multiclass.joblib")
    _models["rf_binary"] = joblib.load(d / "rf_binary.joblib")
    with open(d / "feature_cols.json") as f:
        _models["feat_cols"] = json.load(f)
    
    logger.info(f"Loaded {len(_models['feat_cols'])} features from {model_dir}")


# ═════════════════════════════════════════════════════════════════════════
# Pre-processing (pure Python, no LLM, ~10ms latency)
# ═════════════════════════════════════════════════════════════════════════

def _get_flow_statistics(flow: dict) -> dict:
    """Extract human-readable stats from CICFlowMeter features for LLM context.
    
    Transforms 80+ raw features into 6 interpretable metrics.
    Handles NaN/Inf values and division-by-zero edge cases.
    
    Key ratios for attack detection:
        - syn_fin_ratio: High → SYN flood (attacker never closes connections)
        - fwd_bwd_ratio: Asymmetric → potential attack pattern
        - packet_rate/byte_rate: Extreme values → DoS/DDoS
    """
    def _get(key, default=0.0):
        """Safely extract numeric value, replacing NaN/Inf with 0."""
        val = flow.get(key, default)
        try:
            v = float(val)
            return 0.0 if (np.isnan(v) or np.isinf(v)) else v
        except (TypeError, ValueError):
            return default

    syn = _get("SYN Flag Count")
    fin = _get("FIN Flag Count")
    fwd = _get("Total Fwd Packet")
    bwd = _get("Total Bwd packets")

    return {
        "packet_rate": round(_get("Flow Packets/s"), 4),
        "byte_rate": round(_get("Flow Bytes/s"), 4),
        "syn_fin_ratio": round(syn / (fin + 1), 4),  # +1 prevents div-by-zero
        "flow_duration_ms": round(_get("Flow Duration") / 1000.0, 4),
        "fwd_bwd_ratio": round(fwd / (bwd + 1), 4),
        "flag_summary": {
            "SYN": int(syn), "FIN": int(fin),
            "RST": int(_get("RST Flag Count")),
            "PSH": int(_get("PSH Flag Count")),
            "ACK": int(_get("ACK Flag Count")),
        },
    }


def _classify_flow(flow: dict) -> dict:
    """Run RandomForest classifiers (binary + multi-class) on flow.
    
    Two-model approach:
        1. Binary (rf_binary): Attack vs benign → routing decision
        2. Multi-class (rf_multi): Attack type → context for LLM
    
    Feature engineering: Computes SYN_FIN_Ratio at inference time
    (high ratio = SYN flood signature).
    
    Returns dict with:
        - predicted_class: Most likely attack type (str)
        - confidence: Max class probability 0-1 (float)
        - is_attack: Binary gate result (bool)
        - top_3_probabilities: Ranked alternatives
    
    Note: ML weaknesses (BruteForce F1=0.36, Web-Based F1=0.62) 
    compensated by LLM tool-use.
    """
    if not _models:
        raise RuntimeError("Models not loaded — call MonitoringAgent.from_config() first")

    feat_cols = _models["feat_cols"]
    rf_multi = _models["rf_multi"]
    rf_binary = _models["rf_binary"]

    # Build feature vector in exact order
    row = [float(flow.get(col, 0.0)) for col in feat_cols]
    
    # Re-compute engineered feature if present
    if "SYN_FIN_Ratio" in feat_cols:
        syn = float(flow.get("SYN Flag Count", 0))
        fin = float(flow.get("FIN Flag Count", 0))
        row[feat_cols.index("SYN_FIN_Ratio")] = syn / (fin + 1)

    X = np.array(row).reshape(1, -1)
    pred_class = rf_multi.predict(X)[0]
    proba = rf_multi.predict_proba(X)[0]
    confidence = float(np.max(proba))
    top3_idx = np.argsort(proba)[::-1][:3]
    is_attack = int(rf_binary.predict(X)[0]) == 1

    return {
        "predicted_class": pred_class,
        "confidence": round(confidence, 4),
        "is_attack": is_attack,
        "top_3_probabilities": [
            {"class": rf_multi.classes_[i], "probability": round(float(proba[i]), 4)}
            for i in top3_idx
        ],
    }


# ═════════════════════════════════════════════════════════════════════════
# LangGraph State
# ═════════════════════════════════════════════════════════════════════════

class MonitoringState(TypedDict):
    """State object passed through LangGraph nodes."""
    flow: dict            # Raw CICFlowMeter features (input)
    stats: dict           # Human-readable metrics from _get_flow_statistics()
    classification: dict  # ML predictions from _classify_flow()
    decision: str         # Final decision: "log" | "escalate"
    reasoning: str        # LLM explanation (empty if fast path)
    llm_invoked: bool     # Performance tracking flag


# ═════════════════════════════════════════════════════════════════════════
# LLM Tools (grounded to prevent hallucination)
# ═════════════════════════════════════════════════════════════════════════

@tool
def check_flow_baseline(protocol: int, packet_rate: float, byte_rate: float) -> str:
    """Compare flow rates against hardcoded per-protocol baselines for benign traffic.
    
    Baselines (empirically derived):
        TCP:  500 pkt/s, 500 KB/s
        UDP:  1000 pkt/s, 1 MB/s
        ICMP: 50 pkt/s, 50 KB/s
    
    Args:
        protocol: IANA protocol number (6=TCP, 17=UDP, 1=ICMP)
        packet_rate: Observed packets per second
        byte_rate: Observed bytes per second

    Returns:
        JSON with observed/baseline ratios and exceeds_baseline flag
    """
    BASELINES = {
        6:  {"name": "TCP",  "max_pkt_rate": 500,   "max_byte_rate": 500_000},
        17: {"name": "UDP",  "max_pkt_rate": 1_000, "max_byte_rate": 1_000_000},
        1:  {"name": "ICMP", "max_pkt_rate": 50,    "max_byte_rate": 50_000},
    }
    
    baseline = BASELINES.get(protocol, {"name": "UNKNOWN", "max_pkt_rate": 500, "max_byte_rate": 500_000})
    pkt_ratio = round(packet_rate / baseline["max_pkt_rate"], 2)
    byte_ratio = round(byte_rate / baseline["max_byte_rate"], 2)

    return json.dumps({
        "protocol": baseline["name"],
        "baseline_max_pkt_rate": baseline["max_pkt_rate"],
        "baseline_max_byte_rate": baseline["max_byte_rate"],
        "observed_pkt_rate": round(packet_rate, 2),
        "observed_byte_rate": round(byte_rate, 2),
        "pkt_rate_ratio": pkt_ratio,
        "byte_rate_ratio": byte_ratio,
        "exceeds_baseline": pkt_ratio > 1.0 or byte_ratio > 1.0,
        "summary": f"{baseline['name']} flow is {pkt_ratio:.1f}x normal packet rate, {byte_ratio:.1f}x byte rate",
    })


@tool
def escalate_to_incident_manager(
    predicted_class: str,
    confidence: float,
    reason: str,
    source_ip: str = "",
    destination_ip: str = "",
) -> str:
    """Escalate flow to Incident Manager agent for investigation and mitigation.
    
    Creates structured incident brief with attack type, confidence, reasoning,
    and IP addresses for policy enforcement.
    
    Side effects:
        - Logs escalation to console (operator visibility)
        - Records alert in EventStore (IP reputation tracking)
    
    Args:
        predicted_class: Attack type from ML (e.g., 'DDoS', 'Mirai')
        confidence: ML confidence score 0-1
        reason: One-sentence escalation rationale
        source_ip: Attacker/victim IP (optional)
        destination_ip: Target IP (optional)

    Returns:
        JSON with status='escalated' and incident brief
    """
    brief = {
        "status": "escalated",
        "predicted_class": predicted_class,
        "confidence": confidence,
        "reason": reason,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
    }
    
    logger.info(
        f"ESCALATION: {predicted_class} (conf={confidence:.2f}) "
        f"src={source_ip or '?'} dst={destination_ip or '?'} — {reason}"
    )

    # Persist to EventStore for IP reputation and Incident Manager
    if _event_store is not None:
        _event_store.record_alert(
            source_ip=source_ip,
            destination_ip=destination_ip,
            description=f"[MonitoringAgent] {predicted_class} — {reason}",
            severity="high" if confidence >= 0.75 else "medium",
            predicted_class=predicted_class,
            confidence=confidence,
        )

    return json.dumps(brief)


@tool
def get_recent_events_for_ip(ip_address: str, limit: int = 10) -> str:
    """Query EventStore for recent security events involving specified IP.

    Use cases:
        - Repeat offender detection (multiple prior alerts → escalate)
        - False positive reduction (clean history + low conf → don't escalate)
        - Pattern recognition (attack type switching → sophisticated adversary)

    Data source: In-memory EventStore (last 1000 events, circular buffer).
    Events recorded by this agent on escalation and by Incident Manager on mitigation.

    Args:
        ip_address: Source or destination IP to look up
        limit: Max events to return (default 10)

    Returns:
        JSON with ip_address, total count, and list of event objects
    """
    if _event_store is None:
        return json.dumps({"events": [], "total": 0, "note": "Event store not initialized"})

    events = _event_store.events_for_ip(ip_address, n=limit)
    serialized = [
        {
            "timestamp": e.timestamp,
            "event_type": e.event_type,
            "source_ip": e.source_ip,
            "destination_ip": e.destination_ip,
            "severity": e.severity,
            "description": e.description,
            "metadata": e.metadata,
        }
        for e in events
    ]

    return json.dumps({
        "ip_address": ip_address,
        "total": len(serialized),
        "events": serialized,
    })


@tool
def search_knowledge_base(query: str, collection: str = "all", top_k: int = 2) -> str:
    """Search the ChromaDB knowledge base for relevant IoT security context.

    Use this tool when you need semantic context that tools and flow statistics
    alone cannot provide — e.g., understanding what a specific attack class looks
    like, what response action to take, how to interpret a feature value, or
    what a policy rule says.

    Collections available:
        attack_signatures  — Flow-level signatures for 8 attack classes
                             (Benign, DDoS, DoS, Mirai, BruteForce, Recon, Spoofing, Web-Based)
        device_context     — Subnet topology and device criticality
                             (192.168.137.0/24 = IoT devices, external IPs = attackers)
        security_policies  — Active policy rules
                             (BLOCK_TELNET, RATE_LIMIT_HIGH_PPS, RATE_LIMIT_HIGH_BPS)
        response_playbooks — Per-attack escalation criteria and recommended actions
        feature_glossary   — CICFlowMeter feature interpretations
                             (SYN_FIN_Ratio, packet_rate, flow_duration, TCP flags)
        all                — Search across all collections (default)

    Args:
        query:      Natural language question or description of what you're looking for.
                    Examples: "Mirai Telnet port scan signature",
                              "should I escalate BruteForce with low confidence",
                              "what does high SYN_FIN_Ratio mean"
        collection: Collection to search. Use "all" when unsure (default).
        top_k:      Number of results to return per collection (default 2).

    Returns:
        Formatted string with top matching KB passages and relevance scores.
        Returns "Knowledge base not available." if KB is not initialised.
    """
    if _knowledge_base is None:
        return "Knowledge base not available. Proceed with tool-based reasoning only."

    try:
        result = _knowledge_base.query_formatted(
            query_text=query,
            collection=collection,
            n_results=top_k,
        )
        return result
    except Exception as exc:
        logger.warning("Knowledge base query failed: %s", exc)
        return f"Knowledge base query failed: {exc}"


# ═════════════════════════════════════════════════════════════════════════
# LangGraph Nodes
# ═════════════════════════════════════════════════════════════════════════

def preprocess_node(state: MonitoringState) -> dict:
    """Pre-processing: Extract stats and run ML classifiers (always executes, no LLM)."""
    flow = state["flow"]
    return {
        "stats": _get_flow_statistics(flow),
        "classification": _classify_flow(flow),
    }


def route(state: MonitoringState) -> str:
    """Routing function: Decide fast path (log) vs slow path (investigate).
    
    Decision logic:
        IF benign AND confidence ≥ threshold (0.85) → "log" (fast path, no LLM)
        ELSE → "investigate" (slow path, LLM reasoning)
    
    Threshold tuning trade-off:
        Higher (0.9+): More LLM calls = better accuracy, higher cost
        Lower (0.7-0.8): Fewer LLM calls = lower cost, risk missing attacks
    """
    clf = state["classification"]
    if not clf["is_attack"] and clf["confidence"] >= _benign_confidence_threshold:
        return "log"
    return "investigate"


def log_node(state: MonitoringState) -> dict:
    """Fast path terminal: Log benign flow and exit (no LLM, < 1ms).
    
    Handles 70-85% of traffic, reducing edge CPU load by 80%+ and 
    latency from ~2s (LLM) to ~10ms (ML only).
    """
    logger.debug(
        f"Benign flow logged (confidence={state['classification']['confidence']:.2f}, "
        f"class={state['classification']['predicted_class']})"
    )
    return {"decision": "log", "reasoning": "", "llm_invoked": False}


def make_investigate_node(llm_config: dict):
    """Factory: Build LLM investigation node with ReAct pattern.
    
    ReAct loop: LLM reasons about evidence, calls tools, reasons further, decides.
    
    System prompt establishes:
        - Agent persona: Security analyst on IoT edge gateway
        - Task: Investigate and decide whether to escalate
        - Available tools (3) and decision criteria
        - Output format: escalate_to_incident_manager call OR "Decision: log"
    
    Returns:
        investigate_node function (MonitoringState → dict)
    """
    llm = ChatOllama(
        model=llm_config.get("model", "llama3.2:3b"),
        base_url=llm_config.get("api_base", "http://localhost:11434"),
        temperature=llm_config.get("temperature", 0.1),  # Low for consistency
        num_predict=llm_config.get("max_tokens", 1024),
    )

    system_prompt = (
        "You are a security analyst agent on an IoT edge gateway. "
        "The ML classifier flagged a flow as suspicious. Investigate and decide whether to escalate.\n\n"
        "Tools available:\n"
        "  - check_flow_baseline: Compare rates against known-good baselines\n"
        "  - get_recent_events_for_ip: Check IP reputation history\n"
        "  - search_knowledge_base: Retrieve attack signatures, policies, playbooks, and feature guidance\n"
        "  - escalate_to_incident_manager: Hand off to next agent\n\n"
        "Reasoning strategy:\n"
        "  1. Check flow baseline for rate anomalies.\n"
        "  2. If ML class is uncertain (confidence < 0.75) or the attack class is BruteForce/Web-Based,\n"
        "     call search_knowledge_base with the ML-predicted class to get signature and playbook context.\n"
        "  3. Check IP history with get_recent_events_for_ip for source and destination.\n"
        "  4. Decide: escalate (call escalate_to_incident_manager) or log ('Decision: log').\n\n"
        "When escalating, provide a concise reason and always include source_ip and destination_ip. "
        "If investigation concludes flow is benign, say 'Decision: log'."
    )

    react_agent = create_react_agent(
        model=llm,
        tools=[
            check_flow_baseline,
            get_recent_events_for_ip,
            search_knowledge_base,
            escalate_to_incident_manager,
        ],
        prompt=system_prompt,
    )

    def _did_escalate(result: dict) -> bool:
        """Parse LLM transcript to infer escalation decision (heuristic approach)."""
        messages = result.get("messages", [])
        text = "\n".join(str(getattr(m, "content", m)) for m in messages[-6:]).lower()

        if "decision: log" in text or "do not escalate" in text:
            return False
        if '"status": "escalated"' in text or '"status":"escalated"' in text:
            return True
        if "escalated" in text:
            return True
        return False

    def investigate_node(state: MonitoringState) -> dict:
        """Slow path: LLM investigates with tools (~1-3s latency)."""
        clf = state["classification"]
        stats = state["stats"]
        flow = state["flow"]

        user_message = (
            f"Suspicious flow detected.\n"
            f"ML Classification: {json.dumps(clf, indent=2)}\n"
            f"Flow Statistics: {json.dumps(stats, indent=2)}\n"
            f"Protocol: {flow.get('Protocol', 'unknown')}\n"
            f"Source IP: {flow.get('Src IP', 'unknown')}\n"
            f"Destination IP: {flow.get('Dst IP', 'unknown')}\n"
            f"Destination Port: {flow.get('Dst Port', 'unknown')}\n\n"
            f"Investigate and decide whether to escalate."
        )

        result = react_agent.invoke({"messages": [("user", user_message)]})
        last_msg = result["messages"][-1].content
        escalated = _did_escalate(result)

        return {
            "decision": "escalate" if escalated else "log",
            "reasoning": last_msg,
            "llm_invoked": True,
        }

    return investigate_node


# ═════════════════════════════════════════════════════════════════════════
# MonitoringAgent Class
# ═════════════════════════════════════════════════════════════════════════

class MonitoringAgent:
    """Autonomous monitoring agent for IoT network flow analysis.
    
    Combines ML classification with LLM reasoning for attack detection
    with self-explaining decisions. Optimized for edge deployment.
    
    Usage:
        agent = MonitoringAgent.from_config("code/config/config.yaml")
        result = agent.process(flow_dict)
        if result["decision"] == "escalate":
            handle_incident(result)
    
    Thread safety: Stateless agent, but EventStore needs locks if multi-threaded.
    """

    def __init__(self, graph):
        """Private constructor - use from_config() factory method."""
        self._graph = graph

    @classmethod
    def from_config(cls, config_path: str) -> "MonitoringAgent":
        """Initialize agent from YAML config (loads models, sets up LLM, builds graph).
        
        Initialization sequence:
            1. Load config.yaml
            2. Set module-level threshold
            3. Initialize EventStore (shared context)
            4. Load ML models (1.15 GB artifacts)
            5. Build LangGraph state machine
        
        Raises:
            FileNotFoundError: If config or model artifacts missing
            ConnectionError: If Ollama server not running
        """
        import yaml
        global _benign_confidence_threshold, _event_store, _knowledge_base
        from code.context_repository.event_store import EventStore

        with open(config_path) as f:
            cfg = yaml.safe_load(f)

        # Set fast path threshold
        monitoring_cfg = cfg.get("monitoring", {}) or {}
        _benign_confidence_threshold = float(
            monitoring_cfg.get("benign_confidence_threshold", 0.85)
        )

        # Initialize shared EventStore
        context_cfg = cfg.get("context", {}) or {}
        max_events = int(context_cfg.get("max_recent_events", 1000))
        _event_store = EventStore(max_events=max_events)
        logger.info(f"EventStore initialized (capacity={max_events})")

        # Initialize Knowledge Base (optional — agent works without it)
        kb_cfg = (cfg.get("knowledge_base") or {})
        if kb_cfg.get("enabled", True):
            try:
                from code.knowledge_base.knowledge_base import KnowledgeBase
                _knowledge_base = KnowledgeBase.from_config(config_path)
                if not _knowledge_base.is_populated():
                    logger.warning(
                        "Knowledge base is empty. Run: python -m code.knowledge_base.build_kb"
                    )
                else:
                    stats = _knowledge_base.stats()
                    total = sum(stats.values())
                    logger.info(f"KnowledgeBase loaded ({total} documents across {len(stats)} collections)")
            except Exception as exc:
                logger.warning(f"KnowledgeBase unavailable (install chromadb): {exc}")
                _knowledge_base = None
        else:
            logger.info("KnowledgeBase disabled in config.")
            _knowledge_base = None

        # Load ML models
        model_dir = _resolve_model_dir(config_path, cfg)
        _load_models(str(model_dir))

        # Build LangGraph
        llm_cfg = cfg.get("llm", {})
        graph = cls._build_graph(llm_cfg)

        instance = cls(graph)
        instance.event_store = _event_store  # Expose for testing
        instance.knowledge_base = _knowledge_base  # Expose for testing
        return instance

    @staticmethod
    def _build_graph(llm_config: dict):
        """Construct LangGraph state machine.
        
        Topology: START → preprocess → route → {log, investigate} → END
        """
        investigate_node = make_investigate_node(llm_config)

        builder = StateGraph(MonitoringState)
        builder.add_node("preprocess", preprocess_node)
        builder.add_node("log", log_node)
        builder.add_node("investigate", investigate_node)

        builder.add_edge(START, "preprocess")
        builder.add_conditional_edges("preprocess", route, {
            "log": "log",
            "investigate": "investigate",
        })
        builder.add_edge("log", END)
        builder.add_edge("investigate", END)

        return builder.compile()

    def process(self, flow: dict) -> MonitoringState:
        """Process single CICFlowMeter flow record.
        
        Execution: preprocess (~10ms) → route → log (~1ms) OR investigate (~1-3s)
        
        Args:
            flow: Dict with CICFlowMeter features (80+ keys including all 77 from feature_cols.json)

        Returns:
            MonitoringState with decision ("log"/"escalate"), reasoning, and metrics
        """
        initial_state: MonitoringState = {
            "flow": flow,
            "stats": {},
            "classification": {},
            "decision": "",
            "reasoning": "",
            "llm_invoked": False,
        }
        return self._graph.invoke(initial_state)
