"""Unit tests for core/rag — chunking logic and NucleiIndex.

OWASPRag live embedding tests are skipped unless sentence-transformers and
chromadb are available with the required model downloaded.
"""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from core.rag.nuclei_index import OWASP_TAG_MAP, NucleiIndex
from core.rag.owasp_rag import OWASPRag

OWASP_MD = Path(__file__).parent.parent.parent / "data" / "owasp" / "api_top10.md"


# ── OWASPRag chunking (pure Python — no embeddings) ───────────────────────── #

class TestMarkdownChunking:
    @pytest.fixture()
    def rag(self) -> OWASPRag:
        return OWASPRag.__new__(OWASPRag)  # bypass __init__ to skip ChromaDB init

    def test_chunk_extracts_all_10_categories(self, rag: OWASPRag):
        text = OWASP_MD.read_text()
        chunks = rag._chunk_markdown(text)
        categories = {cat for cat, _ in chunks}
        for api_cat in [f"API{i}" for i in range(1, 11)]:
            assert api_cat in categories, f"Category {api_cat} not found in chunks"

    def test_no_chunk_exceeds_max_chars(self, rag: OWASPRag):
        text = OWASP_MD.read_text()
        chunks = rag._chunk_markdown(text)
        oversized = [(cat, len(chunk)) for cat, chunk in chunks if len(chunk) > 500]
        assert not oversized, f"Chunks exceeding 500 chars: {oversized[:3]}"

    def test_chunk_count_is_reasonable(self, rag: OWASPRag):
        text = OWASP_MD.read_text()
        chunks = rag._chunk_markdown(text)
        # 10 categories × at least 2 chunks each = 20 minimum
        assert len(chunks) >= 20, f"Only {len(chunks)} chunks — content may be too sparse"

    def test_each_chunk_is_non_empty(self, rag: OWASPRag):
        text = OWASP_MD.read_text()
        chunks = rag._chunk_markdown(text)
        assert all(chunk_text.strip() for _, chunk_text in chunks)

    def test_categories_match_owasp_tag_map(self, rag: OWASPRag):
        text = OWASP_MD.read_text()
        chunks = rag._chunk_markdown(text)
        categories = {cat for cat, _ in chunks if cat != "general"}
        known = set(OWASP_TAG_MAP.keys())
        unknown = categories - known
        assert not unknown, f"Unexpected categories in chunks: {unknown}"

    def test_split_section_short_text_unchanged(self, rag: OWASPRag):
        text = "Short text under 500 chars."
        result = rag._split_section(text)
        assert result == [text]

    def test_split_section_empty_returns_empty(self, rag: OWASPRag):
        assert rag._split_section("") == []
        assert rag._split_section("   \n  ") == []

    def test_split_section_long_text_split(self, rag: OWASPRag):
        # Build a text longer than 500 chars with clear paragraph breaks
        para = "A" * 200
        text = f"{para}\n\n{para}\n\n{para}"
        result = rag._split_section(text)
        assert len(result) > 1
        for chunk in result:
            assert len(chunk) <= 500

    def test_chunk_api1_content_mentions_bola(self, rag: OWASPRag):
        text = OWASP_MD.read_text()
        chunks = rag._chunk_markdown(text)
        api1_text = " ".join(chunk for cat, chunk in chunks if cat == "API1").lower()
        assert "bola" in api1_text or "authorization" in api1_text

    def test_chunk_api8_content_mentions_injection(self, rag: OWASPRag):
        text = OWASP_MD.read_text()
        chunks = rag._chunk_markdown(text)
        api8_text = " ".join(chunk for cat, chunk in chunks if cat == "API8").lower()
        assert "injection" in api8_text or "sql" in api8_text


# ── NucleiIndex — empty directory ─────────────────────────────────────────── #

class TestNucleiIndexEmpty:
    def test_empty_dir_returns_empty_payloads(self, tmp_path: Path):
        idx = NucleiIndex(str(tmp_path))
        idx.index()
        assert idx.get_payloads("API1") == []

    def test_empty_dir_returns_empty_matchers(self, tmp_path: Path):
        idx = NucleiIndex(str(tmp_path))
        idx.index()
        assert idx.get_matchers("API8") == []

    def test_missing_dir_does_not_raise(self, tmp_path: Path):
        idx = NucleiIndex(str(tmp_path / "does_not_exist"))
        idx.index()  # must not raise
        assert idx.get_payloads("API1") == []

    def test_categories_with_data_empty_when_no_templates(self, tmp_path: Path):
        idx = NucleiIndex(str(tmp_path))
        idx.index()
        assert idx.categories_with_data() == []


# ── NucleiIndex — real template parsing ────────────────────────────────────── #

def _write_template(directory: Path, filename: str, content: dict) -> Path:
    p = directory / filename
    p.write_text(yaml.dump(content))
    return p


class TestNucleiIndexParsing:
    @pytest.fixture()
    def templates_dir(self, tmp_path: Path) -> Path:
        # JWT auth-bypass template
        _write_template(
            tmp_path,
            "jwt-none.yaml",
            {
                "id": "jwt-none-algorithm",
                "info": {
                    "name": "JWT None Algorithm",
                    "tags": "jwt,auth-bypass,broken-auth",
                    "severity": "high",
                },
                "http": [
                    {
                        "method": "GET",
                        "path": ["{{BaseURL}}/api/v1/users"],
                        "payloads": {
                            "token": [
                                "eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ.",
                                "eyJhbGciOiJub25lIn0.eyJyb2xlIjoiYWRtaW4ifQ.",
                            ]
                        },
                        "matchers": [
                            {"type": "status", "status": [200]},
                            {"type": "word", "words": ['"admin"'], "part": "body"},
                        ],
                    }
                ],
            },
        )
        # BOLA / IDOR template
        _write_template(
            tmp_path,
            "bola-idor.yaml",
            {
                "id": "bola-id-enumeration",
                "info": {
                    "name": "BOLA ID Enumeration",
                    "tags": "bola,idor,broken-access-control",
                    "severity": "high",
                },
                "requests": [
                    {
                        "method": "GET",
                        "path": ["{{BaseURL}}/api/v1/users/{{id}}"],
                        "payloads": {"id": ["1", "2", "3", "100", "999"]},
                        "matchers": [{"type": "status", "status": [200]}],
                    }
                ],
            },
        )
        # SQLi template using 'requests' key
        _write_template(
            tmp_path,
            "sqli-basic.yaml",
            {
                "id": "sql-injection-basic",
                "info": {
                    "name": "Basic SQL Injection",
                    "tags": "sqli,injection",
                    "severity": "critical",
                },
                "http": [
                    {
                        "method": "GET",
                        "path": ["{{BaseURL}}/api/v1/items?id={{sqli}}"],
                        "payloads": {
                            "sqli": [
                                "' OR '1'='1",
                                "'; DROP TABLE users;--",
                                "1 OR 1=1",
                            ]
                        },
                        "matchers": [
                            {
                                "type": "word",
                                "words": ["SQL syntax", "ORA-", "mysql_fetch"],
                                "part": "body",
                            }
                        ],
                    }
                ],
            },
        )
        return tmp_path

    def test_jwt_payloads_mapped_to_api2(self, templates_dir: Path):
        idx = NucleiIndex(str(templates_dir))
        idx.index()
        payloads = idx.get_payloads("API2")
        assert len(payloads) >= 2
        # Payloads are raw base64 JWT strings — check for the known fixture values
        assert any("eyJhbGciOiJub25lIn0" in p for p in payloads)

    def test_bola_payloads_mapped_to_api1(self, templates_dir: Path):
        idx = NucleiIndex(str(templates_dir))
        idx.index()
        payloads = idx.get_payloads("API1")
        assert "1" in payloads
        assert "999" in payloads

    def test_sqli_payloads_mapped_to_api8(self, templates_dir: Path):
        idx = NucleiIndex(str(templates_dir))
        idx.index()
        payloads = idx.get_payloads("API8")
        assert any("OR" in p for p in payloads)
        assert any("DROP" in p for p in payloads)

    def test_matchers_extracted(self, templates_dir: Path):
        idx = NucleiIndex(str(templates_dir))
        idx.index()
        matchers = idx.get_matchers("API2")
        assert len(matchers) >= 1
        matcher_types = {m.get("type") for m in matchers}
        assert "status" in matcher_types or "word" in matcher_types

    def test_api8_matchers_contain_sql_errors(self, templates_dir: Path):
        idx = NucleiIndex(str(templates_dir))
        idx.index()
        matchers = idx.get_matchers("API8")
        all_words = []
        for m in matchers:
            all_words.extend(m.get("words", []))
        assert any("SQL" in w or "ORA" in w for w in all_words)

    def test_categories_with_data_after_indexing(self, templates_dir: Path):
        idx = NucleiIndex(str(templates_dir))
        idx.index()
        cats = idx.categories_with_data()
        assert "API1" in cats
        assert "API2" in cats
        assert "API8" in cats

    def test_payloads_deduplicated(self, tmp_path: Path):
        # Two templates with the same payload for the same category
        for i in (1, 2):
            _write_template(
                tmp_path,
                f"jwt-dup-{i}.yaml",
                {
                    "id": f"jwt-dup-{i}",
                    "info": {"name": f"Dup {i}", "tags": "jwt,auth-bypass"},
                    "http": [{"payloads": {"t": ["SAME_PAYLOAD"]}, "matchers": []}],
                },
            )
        idx = NucleiIndex(str(tmp_path))
        idx.index()
        payloads = idx.get_payloads("API2")
        assert payloads.count("SAME_PAYLOAD") == 1

    def test_index_is_lazy(self, templates_dir: Path):
        idx = NucleiIndex(str(templates_dir))
        assert not idx._indexed
        idx.get_payloads("API1")  # triggers lazy indexing
        assert idx._indexed

    def test_invalid_yaml_skipped_gracefully(self, tmp_path: Path):
        (tmp_path / "bad.yaml").write_text("{invalid: [yaml: content")
        _write_template(
            tmp_path,
            "good.yaml",
            {
                "id": "good",
                "info": {"name": "Good", "tags": "jwt,auth-bypass"},
                "http": [{"payloads": {"t": ["valid"]}, "matchers": []}],
            },
        )
        idx = NucleiIndex(str(tmp_path))
        idx.index()
        # Should still index the good template
        assert "valid" in idx.get_payloads("API2")

    def test_template_without_tags_skipped(self, tmp_path: Path):
        _write_template(
            tmp_path,
            "no-tags.yaml",
            {"id": "no-tags", "info": {"name": "No tags"}, "http": []},
        )
        idx = NucleiIndex(str(tmp_path))
        idx.index()
        assert idx.categories_with_data() == []

    def test_get_payloads_returns_copy(self, templates_dir: Path):
        idx = NucleiIndex(str(templates_dir))
        idx.index()
        p1 = idx.get_payloads("API2")
        p1.append("MUTATED")
        p2 = idx.get_payloads("API2")
        assert "MUTATED" not in p2


# ── Live OWASPRag integration test (skipped unless env is ready) ──────────── #

def _chromadb_and_st_available() -> bool:
    try:
        import chromadb  # noqa: F401
        import sentence_transformers  # noqa: F401
        return True
    except ImportError:
        return False


@pytest.mark.skipif(
    not _chromadb_and_st_available(),
    reason="chromadb or sentence-transformers not installed",
)
def test_live_rag_index_and_query(tmp_path: Path):
    """Index the real OWASP doc and confirm API1 query returns relevant chunks."""
    rag = OWASPRag(persist_dir=str(tmp_path / "chroma"), embedding_model="all-MiniLM-L6-v2")
    rag.index_documents(str(OWASP_MD.parent))

    results = rag.query("API1", "BOLA horizontal privilege escalation object ID", top_k=3)
    assert len(results) >= 1
    combined = " ".join(results).lower()
    assert any(kw in combined for kw in ("bola", "authorization", "object", "id"))
