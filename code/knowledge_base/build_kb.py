"""Build / rebuild the ChromaDB knowledge base.

Run once before starting the monitoring agent:

    python -m code.knowledge_base.build_kb

Or with a custom config:

    python -m code.knowledge_base.build_kb --config code/config/config.yaml

The script ingests all five document collections:
    - attack_signatures   (8 docs)
    - device_context      (6 docs)
    - security_policies   (5 docs)
    - response_playbooks  (8 docs)
    - feature_glossary    (8 docs)

Total: ~35 documents. Build time < 30s on CPU (embedding via sentence-transformers).
Re-running is safe — documents are upserted (not duplicated).
"""

import argparse
import logging
import sys
import time
from pathlib import Path

# Allow running as `python -m code.knowledge_base.build_kb` from project root
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from code.knowledge_base.knowledge_base import KnowledgeBase
from code.knowledge_base.documents.attack_signatures import ATTACK_SIGNATURES
from code.knowledge_base.documents.device_context import DEVICE_CONTEXT
from code.knowledge_base.documents.security_policies import SECURITY_POLICIES
from code.knowledge_base.documents.response_playbooks import RESPONSE_PLAYBOOKS
from code.knowledge_base.documents.feature_glossary import FEATURE_GLOSSARY

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)


COLLECTIONS: dict[str, list[dict]] = {
    "attack_signatures": ATTACK_SIGNATURES,
    "device_context": DEVICE_CONTEXT,
    "security_policies": SECURITY_POLICIES,
    "response_playbooks": RESPONSE_PLAYBOOKS,
    "feature_glossary": FEATURE_GLOSSARY,
}


def build(config_path: str, force_rebuild: bool = False) -> None:
    """Build the knowledge base from all document collections.

    Args:
        config_path:   Path to config.yaml (used to resolve persist_dir).
        force_rebuild: If True, clears each collection before ingesting.
                       If False, upserts (safe to run multiple times).
    """
    logger.info("Initialising KnowledgeBase from config: %s", config_path)
    kb = KnowledgeBase.from_config(config_path)

    if not force_rebuild and kb.is_populated():
        logger.info("Knowledge base already populated. Use --rebuild to force re-ingestion.")
        _print_stats(kb)
        return

    total_docs = 0
    t0 = time.time()

    for collection_name, documents in COLLECTIONS.items():
        if force_rebuild:
            logger.info("Clearing collection '%s'...", collection_name)
            kb.clear_collection(collection_name)

        logger.info(
            "Ingesting %d documents into '%s'...", len(documents), collection_name
        )
        n = kb.ingest(collection_name, documents)
        total_docs += n

    elapsed = time.time() - t0
    logger.info(
        "Build complete: %d documents ingested across %d collections in %.1fs",
        total_docs,
        len(COLLECTIONS),
        elapsed,
    )
    _print_stats(kb)
    _run_smoke_test(kb)


def _print_stats(kb: KnowledgeBase) -> None:
    """Print document counts per collection."""
    print("\nKnowledge Base Stats:")
    print("-" * 35)
    total = 0
    for name, count in kb.stats().items():
        print(f"  {name:<25} {count:>4} docs")
        total += count
    print(f"  {'TOTAL':<25} {total:>4} docs")
    print("-" * 35)


def _run_smoke_test(kb: KnowledgeBase) -> None:
    """Run a few example queries to verify the KB is working."""
    test_queries = [
        ("SYN flood high packet rate attack", "attack_signatures"),
        ("Mirai botnet Telnet port 23", "attack_signatures"),
        ("IoT device subnet criticality", "device_context"),
        ("block telnet policy violation", "security_policies"),
        ("brute force SSH escalation", "response_playbooks"),
        ("SYN_FIN_Ratio interpretation", "feature_glossary"),
    ]

    print("\nSmoke Test Queries:")
    print("=" * 60)
    for query_text, expected_collection in test_queries:
        results = kb.query(query_text, collection=expected_collection, n_results=1)
        if results:
            top = results[0]
            relevance = round(1 - top["distance"], 2)
            print(f"  Query: '{query_text}'")
            print(f"  Top hit: [{top['collection']}/{top['id']}] relevance={relevance}")
        else:
            print(f"  Query: '{query_text}' → NO RESULTS (check embedding model)")
        print()


def main():
    parser = argparse.ArgumentParser(
        description="Build the ChromaDB knowledge base for agentic-edge."
    )
    parser.add_argument(
        "--config",
        default="code/config/config.yaml",
        help="Path to config.yaml (default: code/config/config.yaml)",
    )
    parser.add_argument(
        "--rebuild",
        action="store_true",
        help="Force rebuild: clear all collections before ingesting.",
    )
    args = parser.parse_args()

    config_path = Path(args.config)
    if not config_path.exists():
        logger.error("Config not found: %s", config_path)
        sys.exit(1)

    build(str(config_path), force_rebuild=args.rebuild)


if __name__ == "__main__":
    main()
