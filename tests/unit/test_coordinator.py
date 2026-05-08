"""Unit tests for coordinator, dispatcher, and all agents.  All LLM and RAG
calls are mocked so no Ollama or ChromaDB instance is needed.
"""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from core.agents.auth_agent import AuthAgent
from core.agents.base_agent import AgentDecision, BaseAgent
from core.agents.bola_agent import BOLAAgent
from core.agents.injection_agent import InjectionAgent
from core.agents.mass_assign_agent import MassAssignAgent
from core.agents.rate_limit_agent import RateLimitAgent
from core.coordinator.coordinator import Coordinator
from core.coordinator.dispatcher import Dispatcher
from core.coordinator.task_builder import Task, TaskBuilder
from core.parser.enricher import EnrichedEndpoint
from core.parser.openapi_parser import EndpointInfo


# ── Shared fixtures ───────────────────────────────────────────────────────── #

def _make_llm(return_value=None) -> MagicMock:
    llm = MagicMock()
    llm.reason = AsyncMock(return_value=return_value or {})
    return llm


def _make_rag(chunks: list[str] | None = None) -> MagicMock:
    rag = MagicMock()
    rag.query = MagicMock(return_value=chunks or ["OWASP context chunk"])
    return rag


def _ep(
    path: str = "/items/{item_id}",
    method: str = "GET",
    security: list[str] | None = None,
    owasp_candidates: list[str] | None = None,
    risk_hints: list[str] | None = None,
    body_schema: dict | None = None,
    priority: int = 2,
) -> EnrichedEndpoint:
    return EnrichedEndpoint(
        path=path,
        method=method,
        params=[{"name": "item_id", "in": "path", "type": "integer", "required": True}],
        body_schema=body_schema,
        response_schemas={},
        security=security or ["bearerAuth"],
        tags=[],
        summary="test endpoint",
        risk_hints=risk_hints or ["has_resource_id_param", "auth_required"],
        owasp_candidates=owasp_candidates or ["API1", "API4"],
        suggested_priority=priority,
    )


def _task(
    task_id: str = "T-001",
    category: str = "API1",
    path: str = "/items/{item_id}",
    method: str = "GET",
    strategy: str = "horizontal_id_enumeration",
    priority: int = 1,
) -> Task:
    return Task(
        task_id=task_id,
        vuln_category=category,
        owasp_ref=f"{category}:2023",
        target_endpoint=path,
        method=method,
        strategy=strategy,
        rag_context_tags=[],
        priority=priority,
    )


# ── TaskBuilder ───────────────────────────────────────────────────────────── #

class TestTaskBuilder:
    def test_build_spec_summary_non_empty(self):
        eps = [_ep(), _ep(path="/admin/users", method="POST")]
        summary = TaskBuilder.build_spec_summary(eps)
        assert isinstance(summary, str)
        assert len(summary) > 0
        assert "/items/{item_id}" in summary
        assert "/admin/users" in summary

    def test_build_spec_summary_empty_endpoints(self):
        summary = TaskBuilder.build_spec_summary([])
        assert "No endpoints" in summary

    def test_from_llm_dict_valid(self):
        data = {
            "task_id": "T-001",
            "vuln_category": "API1",
            "owasp_ref": "API1:2023 — BOLA",
            "target_endpoint": "/users/{id}",
            "method": "GET",
            "strategy": "horizontal enumeration",
            "rag_context_tags": ["bola", "idor"],
            "priority": 1,
        }
        task = TaskBuilder.from_llm_dict(data, 1)
        assert task is not None
        assert task.task_id == "T-001"
        assert task.vuln_category == "API1"
        assert task.method == "GET"
        assert task.priority == 1

    def test_from_llm_dict_method_uppercased(self):
        data = {
            "vuln_category": "API8",
            "target_endpoint": "/search",
            "method": "post",
            "strategy": "sqli",
        }
        task = TaskBuilder.from_llm_dict(data, 5)
        assert task is not None
        assert task.method == "POST"

    def test_from_llm_dict_missing_required_returns_none(self):
        assert TaskBuilder.from_llm_dict({"vuln_category": "API1"}, 1) is None
        assert TaskBuilder.from_llm_dict({"method": "GET"}, 1) is None

    def test_from_llm_dict_invalid_category_returns_none(self):
        data = {
            "vuln_category": "INVALID",
            "target_endpoint": "/x",
            "method": "GET",
            "strategy": "test",
        }
        assert TaskBuilder.from_llm_dict(data, 1) is None

    def test_from_llm_dict_invalid_method_returns_none(self):
        data = {
            "vuln_category": "API1",
            "target_endpoint": "/x",
            "method": "TELEPORT",
            "strategy": "test",
        }
        assert TaskBuilder.from_llm_dict(data, 1) is None

    def test_from_llm_dict_bad_priority_defaults_to_2(self):
        data = {
            "vuln_category": "API4",
            "target_endpoint": "/x",
            "method": "GET",
            "strategy": "test",
            "priority": 99,
        }
        task = TaskBuilder.from_llm_dict(data, 1)
        assert task is not None
        assert task.priority == 2

    def test_from_llm_dict_autogenerates_task_id(self):
        data = {
            "vuln_category": "API4",
            "target_endpoint": "/x",
            "method": "GET",
            "strategy": "test",
        }
        task = TaskBuilder.from_llm_dict(data, 42)
        assert task is not None
        assert task.task_id == "T-042"

    def test_from_endpoint_and_category(self):
        ep = _ep(path="/users/{id}", method="PUT", priority=1)
        task = TaskBuilder.from_endpoint_and_category(ep, "API6", 3)
        assert task.task_id == "T-003"
        assert task.vuln_category == "API6"
        assert task.target_endpoint == "/users/{id}"
        assert task.method == "PUT"
        assert task.priority == 1

    def test_from_endpoint_and_category_has_strategy(self):
        ep = _ep()
        task = TaskBuilder.from_endpoint_and_category(ep, "API1", 1)
        assert len(task.strategy) > 0

    def test_from_endpoint_and_category_has_rag_tags(self):
        ep = _ep()
        task = TaskBuilder.from_endpoint_and_category(ep, "API2", 1)
        assert isinstance(task.rag_context_tags, list)


# ── Coordinator ───────────────────────────────────────────────────────────── #

class TestCoordinator:
    @pytest.fixture()
    def coordinator(self) -> Coordinator:
        return Coordinator(llm=_make_llm(), rag=_make_rag())

    async def test_plan_returns_tasks_on_valid_llm_response(self):
        llm_output = [
            {
                "task_id": "T-001",
                "vuln_category": "API1",
                "owasp_ref": "API1:2023 — BOLA",
                "target_endpoint": "/items/{item_id}",
                "method": "GET",
                "strategy": "horizontal enumeration",
                "rag_context_tags": ["bola"],
                "priority": 1,
            },
            {
                "task_id": "T-002",
                "vuln_category": "API4",
                "owasp_ref": "API4:2023",
                "target_endpoint": "/items/{item_id}",
                "method": "GET",
                "strategy": "rate limit check",
                "rag_context_tags": [],
                "priority": 3,
            },
        ]
        c = Coordinator(llm=_make_llm(llm_output), rag=_make_rag())
        tasks = await c.plan([_ep()], context="test", owasp_filter=["API1", "API4"])
        assert len(tasks) == 2
        assert tasks[0].task_id == "T-001"
        assert tasks[1].vuln_category == "API4"

    async def test_plan_accepts_dict_wrapped_tasks(self):
        llm_output = {
            "tasks": [
                {
                    "task_id": "T-001",
                    "vuln_category": "API1",
                    "owasp_ref": "API1:2023",
                    "target_endpoint": "/items/{item_id}",
                    "method": "GET",
                    "strategy": "enum",
                    "rag_context_tags": [],
                    "priority": 1,
                }
            ]
        }
        c = Coordinator(llm=_make_llm(llm_output), rag=_make_rag())
        tasks = await c.plan([_ep()], context="", owasp_filter=["API1"])
        assert len(tasks) == 1

    async def test_plan_fallback_on_error_response(self):
        c = Coordinator(llm=_make_llm({"error": "all failed"}), rag=_make_rag())
        tasks = await c.plan([_ep()], context="", owasp_filter=["API1", "API4"])
        assert len(tasks) > 0
        assert all(isinstance(t, Task) for t in tasks)

    async def test_plan_fallback_on_invalid_json(self):
        c = Coordinator(llm=_make_llm("not a list or dict"), rag=_make_rag())
        tasks = await c.plan([_ep()], context="", owasp_filter=["API1", "API4"])
        assert len(tasks) > 0

    async def test_plan_filters_out_of_scope_categories(self):
        llm_output = [
            {
                "task_id": "T-001",
                "vuln_category": "API8",  # not in filter
                "owasp_ref": "API8:2023",
                "target_endpoint": "/x",
                "method": "GET",
                "strategy": "injection",
                "rag_context_tags": [],
                "priority": 1,
            },
        ]
        c = Coordinator(llm=_make_llm(llm_output), rag=_make_rag())
        tasks = await c.plan([_ep()], context="", owasp_filter=["API1", "API4"])
        # API8 is not in filter → should fall back to rule-based (or empty → fallback)
        assert all(t.vuln_category in ("API1", "API4") for t in tasks)

    async def test_plan_empty_filter_uses_all_categories(self):
        c = Coordinator(llm=_make_llm({"error": "fail"}), rag=_make_rag())
        ep = _ep(owasp_candidates=["API1", "API2", "API4"])
        tasks = await c.plan([ep], context="", owasp_filter=[])
        # With empty filter, all categories should be valid
        assert len(tasks) > 0

    def test_rule_based_fallback_one_task_per_pair(self):
        c = Coordinator(llm=_make_llm(), rag=_make_rag())
        ep1 = _ep(path="/a", owasp_candidates=["API1", "API4"])
        ep2 = _ep(path="/b", owasp_candidates=["API6"])
        tasks = c._rule_based_fallback([ep1, ep2], ["API1", "API4", "API6"])
        pairs = {(t.target_endpoint, t.vuln_category) for t in tasks}
        assert ("/a", "API1") in pairs
        assert ("/a", "API4") in pairs
        assert ("/b", "API6") in pairs

    def test_rule_based_fallback_respects_owasp_filter(self):
        c = Coordinator(llm=_make_llm(), rag=_make_rag())
        ep = _ep(owasp_candidates=["API1", "API4", "API6"])
        tasks = c._rule_based_fallback([ep], ["API1"])
        assert all(t.vuln_category == "API1" for t in tasks)

    def test_rule_based_fallback_sequential_ids(self):
        c = Coordinator(llm=_make_llm(), rag=_make_rag())
        ep = _ep(owasp_candidates=["API1", "API4"])
        tasks = c._rule_based_fallback([ep], ["API1", "API4"])
        ids = [t.task_id for t in tasks]
        assert ids == ["T-001", "T-002"]


# ── BaseAgent ─────────────────────────────────────────────────────────────── #

class TestBaseAgent:
    @pytest.fixture()
    def agent(self) -> BaseAgent:
        agent = BaseAgent(llm=_make_llm(), rag=_make_rag())
        agent.OWASP_CATEGORY = "API1"
        return agent

    async def test_analyze_returns_decision_on_valid_llm_response(self, agent: BaseAgent):
        llm_payload = {
            "task_id": "T-001",
            "chosen_strategies": ["horizontal_enum"],
            "payload_config": {"id_range": 10},
            "use_exploit_module": "bola_exploit",
            "reasoning": "test reasoning",
        }
        agent._llm.reason = AsyncMock(return_value=llm_payload)
        decision = await agent.analyze(_task(), _ep())
        assert decision.task_id == "T-001"
        assert "horizontal_enum" in decision.chosen_strategies
        assert decision.use_exploit_module == "bola_exploit"

    async def test_analyze_falls_back_on_error(self, agent: BaseAgent):
        agent._llm.reason = AsyncMock(return_value={"error": "failed"})
        agent.get_default_decision = MagicMock(
            return_value=AgentDecision(
                task_id="T-001",
                chosen_strategies=["fallback"],
                payload_config={},
                use_exploit_module=None,
                reasoning="default",
            )
        )
        decision = await agent.analyze(_task(), _ep())
        agent.get_default_decision.assert_called_once()
        assert "fallback" in decision.chosen_strategies

    async def test_analyze_falls_back_on_missing_strategies(self, agent: BaseAgent):
        agent._llm.reason = AsyncMock(
            return_value={"task_id": "T-001", "chosen_strategies": [], "payload_config": {}}
        )
        decision = await agent.analyze(_task(strategy="my_strategy"), _ep())
        # Empty strategies list → falls back to task.strategy
        assert "my_strategy" in decision.chosen_strategies

    def test_build_system_prompt_contains_category(self, agent: BaseAgent):
        prompt = agent.build_system_prompt(_task(), _ep())
        assert "API1" in prompt

    def test_build_system_prompt_contains_endpoint(self, agent: BaseAgent):
        prompt = agent.build_system_prompt(_task(path="/users/{id}"), _ep(path="/users/{id}"))
        assert "/users/{id}" in prompt

    def test_build_system_prompt_contains_rag_context(self):
        agent = BaseAgent(
            llm=_make_llm(),
            rag=_make_rag(chunks=["SPECIFIC_RAG_CHUNK"]),
        )
        agent.OWASP_CATEGORY = "API1"
        prompt = agent.build_system_prompt(_task(), _ep())
        assert "SPECIFIC_RAG_CHUNK" in prompt


# ── Agent subclasses — default decisions ─────────────────────────────────── #

class TestAgentDefaults:
    def _make(self, AgentClass):
        return AgentClass(llm=_make_llm(), rag=_make_rag())

    def test_bola_default_strategies(self):
        decision = self._make(BOLAAgent).get_default_decision(_task())
        assert "horizontal_id_enumeration" in decision.chosen_strategies
        assert decision.use_exploit_module == "bola_exploit"

    def test_bola_default_has_id_range(self):
        decision = self._make(BOLAAgent).get_default_decision(_task())
        assert "id_range" in decision.payload_config

    def test_auth_api2_default_strategies(self):
        decision = self._make(AuthAgent).get_default_decision(_task(category="API2"))
        assert "jwt_none_algorithm" in decision.chosen_strategies
        assert decision.use_exploit_module == "jwt_exploit"

    def test_auth_api5_default_strategies(self):
        decision = self._make(AuthAgent).get_default_decision(_task(category="API5"))
        assert "admin_endpoint_access" in decision.chosen_strategies
        assert decision.use_exploit_module is None

    def test_auth_api5_vs_api2_different_strategies(self):
        agent = self._make(AuthAgent)
        d2 = agent.get_default_decision(_task(category="API2"))
        d5 = agent.get_default_decision(_task(category="API5"))
        assert d2.chosen_strategies != d5.chosen_strategies

    def test_mass_assign_default_inject_fields(self):
        decision = self._make(MassAssignAgent).get_default_decision(_task(category="API6"))
        assert "role" in decision.payload_config.get("inject_fields", [])
        assert "isAdmin" in decision.payload_config.get("inject_fields", [])
        assert decision.use_exploit_module == "mass_assign_exploit"

    def test_injection_default_strategies(self):
        decision = self._make(InjectionAgent).get_default_decision(_task(category="API8"))
        strats = decision.chosen_strategies
        assert "sqli" in strats
        assert "ssti" in strats

    def test_rate_limit_default_request_count(self):
        decision = self._make(RateLimitAgent).get_default_decision(_task(category="API4"))
        assert decision.payload_config.get("request_count") == 50
        assert "rate_limit_absence_check" in decision.chosen_strategies

    def test_all_defaults_have_task_id(self):
        classes = [BOLAAgent, AuthAgent, MassAssignAgent, InjectionAgent, RateLimitAgent]
        for AgentClass in classes:
            agent = self._make(AgentClass)
            decision = agent.get_default_decision(_task(task_id="T-XYZ"))
            assert decision.task_id == "T-XYZ", f"{AgentClass.__name__} lost task_id"

    def test_all_defaults_have_non_empty_strategies(self):
        classes = [BOLAAgent, AuthAgent, MassAssignAgent, InjectionAgent, RateLimitAgent]
        for AgentClass in classes:
            agent = self._make(AgentClass)
            decision = agent.get_default_decision(_task())
            assert decision.chosen_strategies, f"{AgentClass.__name__} has empty strategies"


# ── Dispatcher ────────────────────────────────────────────────────────────── #

class TestDispatcher:
    def _make_agent(self, decision: AgentDecision) -> BaseAgent:
        agent = MagicMock(spec=BaseAgent)
        agent.analyze = AsyncMock(return_value=decision)
        agent.get_default_decision = MagicMock(return_value=decision)
        return agent

    async def test_dispatch_routes_to_correct_agent(self):
        bola_decision = AgentDecision("T-001", ["enum"], {}, "bola_exploit", "ok")
        auth_decision = AgentDecision("T-002", ["jwt"], {}, "jwt_exploit", "ok")
        agents = {
            "API1": self._make_agent(bola_decision),
            "API2": self._make_agent(auth_decision),
        }
        dispatcher = Dispatcher(agents, max_concurrent=3)
        ep = _ep(path="/items/{item_id}")
        tasks = [
            _task("T-001", "API1", "/items/{item_id}"),
            _task("T-002", "API2", "/items/{item_id}"),
        ]
        results = await dispatcher.dispatch(tasks, [ep])
        assert len(results) == 2
        assert results[0].task_id == "T-001"
        assert results[1].use_exploit_module == "jwt_exploit"

    async def test_dispatch_uses_default_agent_for_unknown_category(self):
        fallback = AgentDecision("T-001", ["generic"], {}, None, "fallback")
        agents = {"default": self._make_agent(fallback)}
        dispatcher = Dispatcher(agents)
        results = await dispatcher.dispatch(
            [_task("T-001", "API9")], [_ep()]
        )
        assert results[0].reasoning == "fallback"

    async def test_dispatch_passthrough_when_no_agent(self):
        dispatcher = Dispatcher({})  # no agents at all
        results = await dispatcher.dispatch([_task("T-001", "API1")], [_ep()])
        assert len(results) == 1
        assert "no agent" in results[0].reasoning.lower()

    async def test_dispatch_uses_default_decision_when_endpoint_missing(self):
        bola_agent = self._make_agent(
            AgentDecision("T-001", ["default_used"], {}, None, "default")
        )
        agents = {"API1": bola_agent}
        dispatcher = Dispatcher(agents)
        # Pass empty endpoint list so lookup fails
        results = await dispatcher.dispatch(
            [_task("T-001", "API1", "/nonexistent")], []
        )
        bola_agent.get_default_decision.assert_called_once()
        assert results[0].chosen_strategies == ["default_used"]

    async def test_dispatch_respects_concurrency_limit(self):
        call_times: list[float] = []
        import time

        async def slow_analyze(task, endpoint):
            call_times.append(time.monotonic())
            await asyncio.sleep(0.05)
            return AgentDecision(task.task_id, ["s"], {}, None, "ok")

        agent = MagicMock(spec=BaseAgent)
        agent.analyze = slow_analyze
        agent.get_default_decision = MagicMock(
            return_value=AgentDecision("x", ["s"], {}, None, "ok")
        )
        agents = {"API1": agent}
        dispatcher = Dispatcher(agents, max_concurrent=2)
        tasks = [_task(f"T-{i:03d}", "API1") for i in range(4)]
        ep = _ep()
        await dispatcher.dispatch(tasks, [ep])
        # All 4 tasks should eventually complete
        assert len(call_times) == 4

    async def test_dispatch_returns_all_results(self):
        decisions = [
            AgentDecision(f"T-{i:03d}", ["s"], {}, None, "ok")
            for i in range(5)
        ]
        tasks = [_task(f"T-{i:03d}", "API1") for i in range(5)]

        call_idx = 0

        async def sequential_analyze(task, endpoint):
            nonlocal call_idx
            d = decisions[call_idx]
            call_idx += 1
            return d

        agent = MagicMock(spec=BaseAgent)
        agent.analyze = sequential_analyze
        agent.get_default_decision = MagicMock()

        dispatcher = Dispatcher({"API1": agent}, max_concurrent=5)
        results = await dispatcher.dispatch(tasks, [_ep()])
        assert len(results) == 5
