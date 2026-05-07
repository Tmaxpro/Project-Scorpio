"""OWASP API Top 10 RAG — ChromaDB-backed semantic retrieval.

Indexes markdown documents by OWASP category and returns the most relevant
text chunks for a given query. Used by the Coordinator and Agents to inject
category-specific knowledge into their system prompts.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path

import chromadb
from chromadb.utils.embedding_functions import SentenceTransformerEmbeddingFunction

logger = logging.getLogger(__name__)

_CATEGORY_RE = re.compile(r"##\s+(API\d+)", re.IGNORECASE)


class OWASPRag:
    """Semantic retrieval over the OWASP API Top 10 knowledge base.

    Usage::

        rag = OWASPRag("./data/chroma", "all-MiniLM-L6-v2")
        rag.index_documents("./data/owasp/")
        chunks = rag.query("API1", "horizontal privilege escalation techniques")
    """

    _COLLECTION_NAME = "owasp_api_top10"
    _MAX_CHUNK_CHARS = 500

    def __init__(self, persist_dir: str, embedding_model: str = "all-MiniLM-L6-v2") -> None:
        self._persist_dir = persist_dir
        self._embedding_model_name = embedding_model
        self._ef = SentenceTransformerEmbeddingFunction(model_name=embedding_model)
        self._client: chromadb.ClientAPI | None = None
        self._collection = None

    # ── Public API ──────────────────────────────────────────────────────── #

    def index_documents(self, docs_dir: str) -> None:
        """Chunk and index all .md files in *docs_dir* into ChromaDB.

        Chunking strategy: split on ``##`` headers (one chunk per section),
        then sub-split sections longer than 500 characters by paragraph.
        Chunks are upserted so repeated calls are idempotent.
        """
        self._ensure_collection()
        docs_path = Path(docs_dir)
        if not docs_path.exists():
            logger.warning("docs_dir does not exist: %s", docs_dir)
            return

        total = 0
        for md_file in sorted(docs_path.glob("*.md")):
            text = md_file.read_text(encoding="utf-8")
            chunks = self._chunk_markdown(text)
            if not chunks:
                continue

            ids, documents, metadatas = [], [], []
            for idx, (category, chunk_text) in enumerate(chunks):
                ids.append(f"{md_file.stem}_{category}_{idx:04d}")
                documents.append(chunk_text)
                metadatas.append({"category": category, "source": md_file.name})

            self._collection.upsert(ids=ids, documents=documents, metadatas=metadatas)
            total += len(ids)
            logger.info("Indexed %d chunks from %s", len(ids), md_file.name)

        logger.info("OWASPRag: total %d chunks indexed from %s", total, docs_dir)

    def query(self, owasp_category: str, query: str, top_k: int = 5) -> list[str]:
        """Return up to *top_k* relevant text chunks for *owasp_category*.

        Filters by category metadata before semantic ranking so results are
        always scoped to the requested OWASP category.
        """
        self._ensure_collection()

        where_filter: dict = {"category": owasp_category}

        try:
            # Cap n_results to actual matching document count to avoid ChromaDB error
            existing = self._collection.get(where=where_filter, include=[])
            available = len(existing["ids"])
        except Exception as exc:  # noqa: BLE001
            logger.warning("Could not count documents for %s: %s", owasp_category, exc)
            available = 0

        if available == 0:
            logger.warning(
                "No indexed documents for category %s — run index_documents() first.",
                owasp_category,
            )
            return []

        n = min(top_k, available)
        try:
            results = self._collection.query(
                query_texts=[query],
                n_results=n,
                where=where_filter,
            )
            return results["documents"][0] if results.get("documents") else []
        except Exception as exc:  # noqa: BLE001
            logger.error("ChromaDB query failed: %s", exc)
            return []

    def is_indexed(self, owasp_category: str | None = None) -> bool:
        """Return True if the collection has any documents (or any for *owasp_category*)."""
        self._ensure_collection()
        try:
            if owasp_category:
                result = self._collection.get(
                    where={"category": owasp_category}, include=[]
                )
                return len(result["ids"]) > 0
            return self._collection.count() > 0
        except Exception:  # noqa: BLE001
            return False

    # ── Internal ──────────────────────────────────────────────────────────── #

    def _ensure_collection(self) -> None:
        if self._client is not None:
            return
        Path(self._persist_dir).mkdir(parents=True, exist_ok=True)
        self._client = chromadb.PersistentClient(path=self._persist_dir)
        self._collection = self._client.get_or_create_collection(
            name=self._COLLECTION_NAME,
            embedding_function=self._ef,
            metadata={"hnsw:space": "cosine"},
        )

    def _chunk_markdown(self, content: str) -> list[tuple[str, str]]:
        """Split markdown by ``##`` section headers, yield (category, chunk) pairs.

        Sections longer than _MAX_CHUNK_CHARS are further split by paragraph.
        """
        chunks: list[tuple[str, str]] = []
        current_category = "general"
        current_lines: list[str] = []

        for line in content.splitlines():
            if line.startswith("## "):
                # Flush previous section
                if current_lines:
                    section_text = "\n".join(current_lines).strip()
                    for chunk in self._split_section(section_text):
                        chunks.append((current_category, chunk))
                # Start new section
                m = _CATEGORY_RE.search(line)
                current_category = m.group(1).upper() if m else "general"
                current_lines = [line]
            else:
                current_lines.append(line)

        # Flush final section
        if current_lines:
            section_text = "\n".join(current_lines).strip()
            for chunk in self._split_section(section_text):
                chunks.append((current_category, chunk))

        return chunks

    def _split_section(self, text: str) -> list[str]:
        """Split *text* into chunks of at most _MAX_CHUNK_CHARS characters."""
        text = text.strip()
        if not text:
            return []
        if len(text) <= self._MAX_CHUNK_CHARS:
            return [text]

        # Split by blank-line-separated paragraphs
        paragraphs = [p.strip() for p in re.split(r"\n\s*\n", text) if p.strip()]
        chunks: list[str] = []
        current = ""

        for para in paragraphs:
            if not current:
                current = para[: self._MAX_CHUNK_CHARS] if len(para) > self._MAX_CHUNK_CHARS else para
            elif len(current) + 2 + len(para) <= self._MAX_CHUNK_CHARS:
                current += "\n\n" + para
            else:
                chunks.append(current)
                current = para[: self._MAX_CHUNK_CHARS] if len(para) > self._MAX_CHUNK_CHARS else para

        if current:
            chunks.append(current)

        return [c for c in chunks if c]
