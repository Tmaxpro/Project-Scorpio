# ARIA — Pipeline de traitement des données

Ce document décrit le flux complet d'une demande de scan : depuis la soumission par l'interface
jusqu'à la génération du rapport final.

---

## Vue d'ensemble

```
Utilisateur → Router → ScanRunner → Parser → Enricher → Coordinator → Agents
                                                                          ↓
               DB ← Reporter ← Validator ← HTTP Client ← Payload Factory
```

Chaque étape reçoit des données typées de l'étape précédente et les transforme. Aucune étape
ne communique directement avec une autre en dehors de cette chaîne linéaire.

---

## Étape 1 — Réception de la requête

**Fichier :** `app/routers/scan.py`

L'utilisateur soumet un `POST /api/scan` contenant un `ScanRequest` :

```python
ScanRequest:
  spec: str                    # OpenAPI YAML complet
  target_url: str              # Base URL de l'API cible
  auth_token: str              # Credential principal (bearer / apikey / basic)
  auth_type: str               # "bearer" | "apikey" | "basic" | "none"
  credentials: Credentials     # username + password (pour auto-login)
  user2_credentials: Credentials  # Compte victime (tests BOLA cross-user)
  owasp_filter: list[str]      # Sous-ensemble de [API1..API10] à tester
  max_payloads_per_endpoint: int
  scan_mode: str               # "fast" | "balanced" | "thorough"
  context: str                 # Contexte libre (ex. "c'est une API de paiement")
```

Le router :
1. Crée un `ScanSession` (UUID, `status=pending`)
2. Persiste immédiatement en base SQLite via `save_scan()`
3. Lance `_run_scan()` en tâche d'arrière-plan (FastAPI `BackgroundTasks`)
4. Retourne `{ scan_id, message }` au client

---

## Étape 2 — Orchestration globale

**Fichier :** `app/scan_runner.py`

`ScanRunner.run()` est le chef d'orchestre. Il enchaîne toutes les étapes ci-dessous dans
l'ordre, en émettant des événements SSE à chaque progression :

```
0.05  Parsing + Enrichissement
0.20  Chargement de la base de connaissances (RAG)
0.30  Planification des tâches (Coordinator + LLM)
0.39  Auto-login (principal + user2 si besoin)
0.40–0.95  Exécution des tâches en parallèle
1.00  Génération du rapport
```

Chaque mise à jour de progression appelle `event_cb("progress", {...})`, ce qui déclenche
une sauvegarde en base et un événement SSE vers le frontend.

---

## Étape 3 — Parsing OpenAPI

**Fichier :** `core/parser/openapi_parser.py`

**Entrée :** `spec: str` (YAML brut)  
**Sortie :** `list[EndpointInfo]`

Le parser :
- Charge le YAML et résout récursivement tous les `$ref`
- Extrait chaque opération (`GET /users/{id}`, etc.)
- Construit un `EndpointInfo` par opération :

```python
EndpointInfo:
  path: str               # "/api/v1/users/{id}"
  method: str             # "GET"
  params: list[dict]      # [{name, in: path|query, type, required}]
  body_schema: dict       # JSON Schema résolu (ou None)
  response_schemas: dict  # {status_code: schema}
  security: list[str]     # noms des security schemes requis
  tags: list[str]
  summary: str
```

---

## Étape 4 — Enrichissement des endpoints

**Fichier :** `core/parser/enricher.py`

**Entrée :** `list[EndpointInfo]`  
**Sortie :** `list[EnrichedEndpoint]`

L'enrichisseur applique des heuristiques **déterministes** (sans LLM) pour détecter des
signaux de risque :

| Risk hint | Détection |
|-----------|-----------|
| `has_resource_id_param` | Le chemin contient `{id}`, `{userId}`, etc. |
| `auth_required` | Au moins un security scheme est listé |
| `returns_sensitive_data` | Le body de réponse contient `password`, `token`, `email`, `ssn` |
| `admin_endpoint` | Le chemin contient `/admin` ou le résumé dit "admin" |
| `accepts_user_controlled_body` | POST/PUT/PATCH avec un body schema |
| `sequential_id` | Paramètre `id` de type integer |

À partir des hints détectés, l'enrichisseur assigne des **candidats OWASP** :

```
has_resource_id_param + auth_required     → API1
returns_sensitive_data                    → API3
admin_endpoint                            → API5
accepts_user_controlled_body              → API6
tout endpoint avec body ou params string  → API8
```

Un `suggested_priority` (1=haute, 3=faible) est calculé selon le nombre de hints.

---

## Étape 5 — Base de connaissances OWASP (RAG)

**Fichier :** `core/rag/owasp_rag.py`

**Entrée :** `(owasp_category: str, query_text: str, top_k: int)`  
**Sortie :** `list[str]` (chunks de texte pertinents)

Le RAG utilise ChromaDB avec des embeddings `all-MiniLM-L6-v2`. Les documents OWASP API Top 10
sont pré-indexés par section. Les chunks récupérés sont injectés dans les prompts du coordinator
et des agents pour contextualiser les décisions d'attaque.

---

## Étape 6 — Planification des tâches

**Fichier :** `core/coordinator/coordinator.py` + `task_builder.py`

**Entrée :** `list[EnrichedEndpoint]` + contexte utilisateur + filtre OWASP  
**Sortie :** `list[Task]`

Le coordinator :
1. Construit un résumé tabulaire de la spec (endpoint, méthode, security, candidats OWASP)
2. Interroge le RAG (2 chunks par catégorie) pour enrichir le prompt
3. Appelle `LLMClient.reason()` → le modèle `Foundation-Sec-8B-Reasoning` génère un plan JSON
4. Parse et valide les tâches retournées
5. Si le LLM échoue ou retourne trop peu, bascule sur un plan **rule-based** déterministe
6. Complète le plan avec des tâches rule-based pour les paires endpoint/catégorie manquées

Une `Task` est la granularité de travail : un endpoint × une catégorie de vulnérabilité :

```python
Task:
  task_id: str              # "T-001"
  vuln_category: str        # "API1"
  owasp_ref: str            # "API1:2023 — BOLA"
  target_endpoint: str      # "/api/v1/users/{id}"
  method: str               # "GET"
  strategy: str             # "horizontal_id_enumeration"
  priority: int             # 1=haute, 2=moyenne, 3=faible
```

---

## Étape 7 — Analyse par les agents

**Fichiers :** `core/agents/` (`base_agent.py`, `bola_agent.py`, `auth_agent.py`, etc.)

**Entrée :** `Task` + `EnrichedEndpoint`  
**Sortie :** `AgentDecision`

Chaque catégorie OWASP a son agent spécialisé :

| Catégorie | Agent | Strategies par défaut | Module exploit |
|-----------|-------|----------------------|----------------|
| API1 | BOLAAgent | horizontal_id_enumeration, uuid_substitution | bola_exploit |
| API2 | AuthAgent | jwt_none_algorithm, jwt_weak_secret_bruteforce, missing_auth_header | jwt_exploit |
| API3 | PropertyAuthAgent | sensitive_field_exposure | — |
| API4 | RateLimitAgent | rate_limit_absence_check (si applicable) | — |
| API5 | AuthAgent | admin_endpoint_access, http_method_enumeration | — |
| API6 | MassAssignAgent | privilege_field_injection, role_escalation | mass_assign_exploit |
| API8 | InjectionAgent | sqli, nosqli, ssti, xss | — |

**Logique de décision :**

```
if scan_mode == "fast"         → get_default_decision() (aucun LLM)
elif LLM.reason() réussit      → AgentDecision depuis la réponse JSON
else                           → get_default_decision() (fallback)
```

Un `AgentDecision` précise :
- `chosen_strategies` : liste des attaques à exécuter
- `payload_config` : paramètres spécifiques (nombre de requêtes, secrets à tester, etc.)
- `use_exploit_module` : nom du module spécialisé à utiliser (ou `None`)
- `reasoning` : explication lisible

---

## Étape 8 — Génération des payloads

**Fichier :** `core/payload_factory/factory.py` + `exploit_modules/`

**Entrée :** `Task` + `AgentDecision` + `EnrichedEndpoint`  
**Sortie :** `list[PayloadRequest]` (plafonné à `max_payloads_per_endpoint`)

### Modules exploit (prioritaires)

| Module | Ce qu'il génère |
|--------|----------------|
| `jwt_exploit` | JWT alg=none, JWT secret faible (24 candidats), JWT expiré, forge depuis le vrai token |
| `bola_exploit` | Variantes d'ID cross-user (1..N, UUID aléatoires, ID connus du user2) |
| `mass_assign_exploit` | Un payload par champ privilégié (`role`, `is_admin`, `balance`, …) + un combiné |

### Strategies génériques (fallback)

- `sqli` / `nosqli` / `ssti` / `xss` : injection dans les params path, query ou le body
- `rate_limit_absence_check` : N requêtes identiques (baseline)
- `admin_endpoint_access` : avec / sans headers de rôle (`X-Role: admin`)
- `http_method_enumeration` : tous les verbes HTTP

### Résolution des paramètres de chemin

Les `{param}` dans les chemins sont résolus en trois priorités :
1. `known_values` fournis par le runner (ex. `username` depuis les credentials)
2. `_PARAM_TEST_VALUES` statiques par nom de param
3. Valeur numérique par défaut (`1`, `2`, …)

Cela garantit que `/users/{id}` devient `/users/1` et non `/users/{id}`.

Un `PayloadRequest` est un objet HTTP complet :

```python
PayloadRequest:
  task_id, method, path         # ex. "GET", "/api/v1/users/2"
  headers: dict                  # inclut X-ARIA-* (signaux internes)
  body: dict | None
  query_params: dict
  strategy: str
  label: str                     # ex. "jwt_none_algorithm", "mass_assign:role='admin'"
```

---

## Étape 9 — Exécution HTTP

**Fichier :** `core/http_engine/client.py` + `core/auth/injector.py`

**Entrée :** `list[PayloadRequest]`  
**Sortie :** `list[ScanResult]`

### Injection d'authentification

`AuthInjector.inject()` traite chaque requête dans cet ordre :

1. Retire les headers internes `X-ARIA-*`
2. Si `X-ARIA-Skip-Auth=true` → aucun credential
3. Si le payload a déjà un `Authorization` (ex. JWT forgé) → le garde tel quel
4. Si `X-ARIA-Other-User=true` → utilise `other_user_token` (compte victime BOLA)
5. Sinon → injecte la session principale (Bearer / API key / Basic)

### Exécution

- `httpx.AsyncClient` avec timeout configurable
- Concurrence bornée par `asyncio.Semaphore(max_concurrent_http_slots)` (config YAML)
- Les requêtes Ollama sont sérialisées (une seule inférence à la fois)

Un `ScanResult` capture tout ce dont le validateur a besoin :

```python
ScanResult:
  task_id, request          # requête originale
  status_code: int
  response_headers: dict
  response_body: str        # premiers 4096 caractères
  response_time_ms: float
  error: str | None
```

---

## Étape 10 — Validation des résultats

**Fichier :** `core/validator/rule_validator.py` + `core/validator/severity_scorer.py`

**Entrée :** `ScanResult`  
**Sortie :** `ValidationResult`

### Règles déterministes

| Règle | Catégorie | Déclenchement |
|-------|-----------|---------------|
| `auth_bypass` | API2 | Aucun header auth + 2xx |
| `bola_object_access` | API1 | strategy=bola_exploit + 2xx |
| `admin_endpoint_exposed` | API5 | label=admin_access + 2xx |
| `mass_assignment_accepted` | API6 | strategy=mass_assign + 2xx + champ injecté reflété dans la réponse |
| `sensitive_data_exposure` | API3 | 2xx + pattern `password`, `token`, `secret` dans le body |
| `injection_error` | API8 | Pattern d'erreur SQL/NoSQL/SSTI dans le body |
| `rate_limit_absent` | API4 | >10 requêtes identiques, aucun 429 reçu |

### Scoring de sévérité contextuel

La sévérité de base est définie par catégorie, puis ajustée selon le contexte :

| Condition | Ajustement |
|-----------|-----------|
| API4 sur endpoint d'auth (`/login`, `/token`) | +1 → high (risque de brute force) |
| API2 auth_bypass sur endpoint authentifié | +1 → critical |
| API3 + `password` exposé | → high |
| API4 sur GET public sans resource ID | -1 → info |

### Résultat

```python
ValidationResult:
  task_id, scan_result
  rule_checks: list[RuleCheckResult]   # une entrée par règle évaluée
  is_vulnerable: bool                   # True si au moins une règle high/medium a déclenché
  confirmed_by_slm: bool               # réservé au validator agent (optionnel)
```

---

## Étape 11 — Génération du rapport

**Fichier :** `core/reporter/report_generator.py`

**Entrée :** `list[ValidationResult]`  
**Sortie :** `ScanReport` + HTML + Markdown

Le reporter :
1. Aplatit les règles déclenchées en `Finding` (endpoint, catégorie, sévérité, evidence)
2. Filtre les faux positifs (`filter_false_positives()`)
3. Déduplique les findings identiques (`deduplicate_findings()`)
4. Construit le `ScanReport` avec métadonnées (durée, nombre de requêtes, etc.)
5. Rend en Markdown (table de résultats + sections détaillées)
6. Rend en HTML (tableau dark-theme + métadonnées)

---

## Étape 12 — Persistance et streaming

**Fichiers :** `app/database.py`, `app/routers/scan.py` (SSE)

### Base de données SQLite

La table `scans` est upsertée **à chaque événement** (toutes les 5-10 secondes en pratique) :

```
scan_id, target_url, scan_name, status, progress, message,
started_at, finished_at, total_tasks, completed_tasks,
results_json, report_html, report_md, events_json, done
```

### Streaming SSE

Le frontend s'abonne à `GET /api/scan/{scan_id}/events`. Le router envoie chaque event
accumulé dans `session._events` dès la connexion, puis pousse les nouveaux en temps réel :

| Event type | Contenu |
|------------|---------|
| `progress` | `{progress: float, message: str, status: str}` |
| `task_started` | `{task_id, endpoint, vuln_category}` |
| `task_completed` | `{task_id, payloads_sent, findings_count}` |
| `finding` | `{task_id, endpoint, vuln_category, severity, evidence}` |
| `llm_call` | `{status, model, task_id}` |
| `scan_completed` | `{scan_id, vulnerable_count, total_tasks, report_md}` |
| `error` | `{message}` |

Le frontend ferme l'`EventSource` dès réception de `scan_completed` ou `error`.

---

## Modes de scan et impact sur le LLM

| Mode | Coordinator LLM | Agent LLM | Impact |
|------|----------------|-----------|--------|
| `fast` | ✓ (1 appel) | ✗ (rule-based) | ~40 appels LLM économisés |
| `balanced` | ✓ | Uniquement priorité haute | Équilibre qualité/vitesse |
| `thorough` | ✓ | ✓ pour toutes les tâches | Couverture maximale |

---

## Modèles LLM utilisés

**Fichier :** `core/llm/client.py`

| Rôle | Modèle | Usage |
|------|--------|-------|
| Raisonnement | `Foundation-Sec-8B-Reasoning` | Coordinator, agents |
| Instruction | `Foundation-Sec-1.1-8B-Instruct` | Validator agent (optionnel) |
| Fallback | `Qwen2.5:7b` | Récupération sur échec JSON |

Tous les appels passent par Ollama (local). Les appels Ollama sont **sérialisés** (un seul
à la fois) pour éviter la contention GPU, alors que les requêtes HTTP cibles sont concurrentes.

Chaque appel est loggé dans `benchmarks/runs/{scan_id}.jsonl` :
```json
{"timestamp": "...", "task_id": "T-003", "model_used": "foundation-sec-8b",
 "tokens_in": 512, "tokens_out": 128, "latency_ms": 1240, "success": true}
```

---

## Résumé des transformations

| Étape | Entrée | Sortie | Cardinalité |
|-------|--------|--------|-------------|
| Router | `ScanRequest` | `ScanSession` | 1:1 |
| Parser | YAML `str` | `list[EndpointInfo]` | 1:N |
| Enricher | `EndpointInfo` | `EnrichedEndpoint` | 1:1 |
| Coordinator | `list[EnrichedEndpoint]` | `list[Task]` | 1:M |
| Agent | `Task` | `AgentDecision` | 1:1 |
| Payload Factory | `AgentDecision` | `list[PayloadRequest]` | 1:M (≤20) |
| HTTP Client | `PayloadRequest` | `ScanResult` | 1:1 |
| Validator | `ScanResult` | `ValidationResult` | 1:1 |
| Reporter | `list[ValidationResult]` | `ScanReport` | 1:1 |
