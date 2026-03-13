"""Knowledge Base — ChromaDB-backed semantic retrieval for IoT security context.

Collections:
    attack_signatures  — Flow-level signatures for 8 attack classes
    device_context     — Subnet topology and device criticality
    security_policies  — Active policy rules in natural language
    response_playbooks — Per-attack escalation and mitigation guides
    feature_glossary   — CICFlowMeter feature security interpretations

Usage:
    # Build once (run build_kb.py)
    # Then in agent:
    kb = KnowledgeBase.from_config("code/config/config.yaml")
    results = kb.query("SYN flood high packet rate", collection="attack_signatures")
"""

import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

COLLECTION_NAMES = [
    "attack_signatures",
    "device_context",
    "security_policies",
    "response_playbooks",
    "feature_glossary",
]


class KnowledgeBase:
    """ChromaDB-backed semantic knowledge base for IoT security reasoning.

    Uses a locally persisted ChromaDB store (no external server required).
    Documents are embedded with ChromaDB's default embedding function
    (all-MiniLM-L6-v2 via sentence-transformers) — runs fully on-device,
    consistent with the edge deployment model.

    Thread safety: ChromaDB PersistentClient is thread-safe for reads.
    Writes during build_kb.py are single-threaded.
    """

    def __init__(self, persist_dir: str):
        """Initialise client and open (or create) all collections.

        Args:
            persist_dir: Path to the ChromaDB persistence directory.
                         Created automatically if it does not exist.
        """
        import chromadb

        Path(persist_dir).mkdir(parents=True, exist_ok=True)
        self._client = chromadb.PersistentClient(path=persist_dir)
        self._collections: dict = {}
        for name in COLLECTION_NAMES:
            self._collections[name] = self._client.get_or_create_collection(
                name=name,
                metadata={"hnsw:space": "cosine"},  # cosine similarity for text
            )
        logger.info(
            "KnowledgeBase ready at '%s' (%d collections)", persist_dir, len(self._collections)
        )

    # ── Factory ──────────────────────────────────────────────────────────────

    @classmethod
    def from_config(cls, config_path: str) -> "KnowledgeBase":
        """Create KnowledgeBase from YAML config (reads knowledge_base.persist_dir).

        Falls back to <project_root>/results/knowledge_base if not configured.
        """
        import yaml

        cfg_file = Path(config_path).resolve()
        project_root = cfg_file.parents[2] if len(cfg_file.parents) >= 3 else cfg_file.parent

        with open(config_path) as f:
            cfg = yaml.safe_load(f)

        kb_cfg = (cfg.get("knowledge_base") or {})
        configured = kb_cfg.get("persist_dir")
        if configured:
            persist_dir = Path(configured)
            if not persist_dir.is_absolute():
                persist_dir = project_root / persist_dir
        else:
            persist_dir = project_root / "results" / "knowledge_base"

        return cls(str(persist_dir))

    # ── Write ─────────────────────────────────────────────────────────────────

    def ingest(self, collection_name: str, documents: list[dict]) -> int:
        """Add documents to a collection.

        Each document dict must have:
            id (str):       Unique document identifier
            text (str):     Content to embed and retrieve
            metadata (dict): Filterable key-value metadata (optional)

        Upserts: existing docs with same id are replaced.

        Args:
            collection_name: One of COLLECTION_NAMES.
            documents:       List of {id, text, metadata} dicts.

        Returns:
            Number of documents ingested.

        Raises:
            KeyError: If collection_name is not recognised.
        """
        if collection_name not in self._collections:
            raise KeyError(
                f"Unknown collection '{collection_name}'. "
                f"Valid: {COLLECTION_NAMES}"
            )

        col = self._collections[collection_name]
        ids = [doc["id"] for doc in documents]
        texts = [doc["text"] for doc in documents]
        metadatas = [doc.get("metadata", {}) for doc in documents]

        col.upsert(ids=ids, documents=texts, metadatas=metadatas)
        logger.info("Ingested %d documents into '%s'", len(documents), collection_name)
        return len(documents)

    def clear_collection(self, collection_name: str) -> None:
        """Delete and recreate a collection (wipes all documents)."""
        self._client.delete_collection(collection_name)
        self._collections[collection_name] = self._client.get_or_create_collection(
            name=collection_name,
            metadata={"hnsw:space": "cosine"},
        )
        logger.info("Cleared collection '%s'", collection_name)

    # ── Read ──────────────────────────────────────────────────────────────────

    def query(
        self,
        query_text: str,
        collection: str = "all",
        n_results: int = 3,
        where: Optional[dict] = None,
    ) -> list[dict]:
        """Semantic search over one or all collections.

        Args:
            query_text: Natural language query (e.g., "high SYN flood packet rate").
            collection: Collection name or "all" to search across all collections.
            n_results:  Max documents to return per collection.
            where:      Optional ChromaDB metadata filter dict.

        Returns:
            List of result dicts sorted by relevance:
            [{"collection": str, "id": str, "text": str,
              "metadata": dict, "distance": float}, ...]
        """
        collections_to_search = (
            list(self._collections.values())
            if collection == "all"
            else [self._collections[collection]]
        )

        all_results: list[dict] = []

        for col in collections_to_search:
            # Skip empty collections
            if col.count() == 0:
                continue

            kwargs: dict = {
                "query_texts": [query_text],
                "n_results": min(n_results, col.count()),
                "include": ["documents", "metadatas", "distances"],
            }
            if where:
                kwargs["where"] = where

            try:
                res = col.query(**kwargs)
            except Exception as exc:
                logger.warning("Query failed on collection '%s': %s", col.name, exc)
                continue

            for doc_text, metadata, distance in zip(
                res["documents"][0],
                res["metadatas"][0],
                res["distances"][0],
            ):
                all_results.append(
                    {
                        "collection": col.name,
                        "id": res["ids"][0][res["documents"][0].index(doc_text)],
                        "text": doc_text,
                        "metadata": metadata,
                        "distance": round(float(distance), 4),
                    }
                )

        # Sort by cosine distance ascending (lower = more similar)
        all_results.sort(key=lambda x: x["distance"])
        return all_results

    def query_formatted(
        self,
        query_text: str,
        collection: str = "all",
        n_results: int = 3,
    ) -> str:
        """Semantic search returning a compact string ready for the LLM context window.

        Returns top-k results formatted as:
            [collection/id] text_snippet (distance=0.12)
        """
        results = self.query(query_text, collection=collection, n_results=n_results)
        if not results:
            return "No relevant knowledge base entries found."

        lines = []
        for r in results:
            # Truncate text to 500 chars to stay within LLM context budget
            snippet = r["text"][:500] + ("..." if len(r["text"]) > 500 else "")
            lines.append(
                f"[{r['collection']}/{r['id']}] (relevance={1 - r['distance']:.2f})\n{snippet}"
            )
        return "\n\n---\n\n".join(lines)

    # ── Stats ─────────────────────────────────────────────────────────────────

    def stats(self) -> dict:
        """Return document counts per collection."""
        return {name: col.count() for name, col in self._collections.items()}

    def is_populated(self) -> bool:
        """Return True if all collections have at least one document."""
        return all(col.count() > 0 for col in self._collections.values())
