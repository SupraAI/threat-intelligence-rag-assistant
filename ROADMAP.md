# Implementation Roadmap

The roadmap follows one rule: add one source of complexity at a time and keep a
measurable baseline at every stage.

> **Current checkpoint:** ingestion is implemented, and the lexical, dense, and
> hybrid retrievers are operational. Phases 2 and 3 remain open until they have
> been compared on the fixed, human-reviewed evaluation set from Phase 0.

## Phase 0 — Contract and evaluation set

### Learn

- Difference between a tactic, technique, sub-technique, procedure, and
  detection evidence.
- Difference between retrieval relevance, model reasoning, and calibrated
  confidence.
- How ambiguous and insufficient inputs should be represented.

### Implement

- Finalize typed input and output contracts.
- Create an initial hand-reviewed dataset of behavior descriptions.
- Include clear cases, multi-label cases, ambiguous cases, insufficient cases,
  paraphrases, and out-of-scope cases.
- Define an annotation guide before assigning labels.

### Exit criterion

At least 30 initial cases have expected labels, acceptable alternatives,
evidence requirements, and abstention expectations.

## Phase 1 — ATT&CK ingestion

### Learn

- STIX 2.1 objects and relationships.
- Data normalization, provenance, versioning, and reproducibility.

### Implement

- Download and pin one MITRE ATT&CK Enterprise release.
- Parse techniques, sub-techniques, tactics, platforms, descriptions,
  relationships, detection content, and procedure examples.
- Transform each technique into a normalized internal model.
- Preserve ATT&CK IDs, object IDs, source URLs, and dataset version.
- Add unit tests for parsing, revoked/deprecated content, missing properties,
  and technique/sub-technique relations.

### Exit criterion

The complete selected Enterprise release can be rebuilt deterministically into
validated internal records with no unexplained losses.

## Phase 2 — Lexical retrieval baseline

### Learn

- Tokenization, inverted indexes, BM25, top-k search, and ranking metrics.

### Implement

- Build a lexical index over normalized ATT&CK documents.
- Search from a behavior description without using an LLM.
- Evaluate Recall@k, Precision@k, MRR, and nDCG.
- Store retrieval traces for error analysis.

### Exit criterion

The lexical baseline is reproducible and its most common failure modes are
documented.

## Phase 3 — Dense and hybrid retrieval

### Learn

- Embeddings, cosine similarity, nearest-neighbor search, and semantic drift.
- Why lexical and semantic retrieval make different errors.

### Implement

- Add one embedding model and vector index.
- Compare dense retrieval against the lexical baseline.
- Combine lexical and dense rankings with a documented fusion method.
- Add metadata filters only when evaluation shows they are needed.

### Exit criterion

Hybrid retrieval improves the selected retrieval metrics on the fixed dataset,
or the experiment documents why it does not.

## Phase 4 — Reranking and context construction

### Learn

- Bi-encoder versus cross-encoder trade-offs.
- Context budgets, duplicate evidence, chunking, and lost-in-the-middle effects.

### Implement

- Rerank a small candidate pool.
- Build a deterministic context assembler.
- Attach stable source identifiers to every context element.
- Measure latency and the marginal retrieval improvement.

### Exit criterion

The context given to the generator contains the expected evidence within a
known token budget and preserves source traceability.

## Phase 5 — Grounded generation

### Learn

- Prompt roles, structured generation, hallucination, grounding, and
  abstention.

### Implement

- Select an LLM provider or local model through a replaceable interface.
- Define Pydantic response models.
- Instruct the model to use only the supplied observation and ATT&CK context.
- Require behavior evidence, ATT&CK evidence, citations, uncertainty, and an
  explicit abstention status.
- Validate and log every response without storing secrets.

### Exit criterion

Responses are schema-valid and every factual mapping claim is traceable to the
input or retrieved context.

## Phase 6 — End-to-end evaluation

### Learn

- Multi-label evaluation, human rubrics, ablation studies, calibration, and
  error taxonomies.

### Implement

- Compare lexical, dense, hybrid, reranked, and generated pipelines.
- Measure mapping, citation, grounding, abstention, latency, and cost metrics.
- Classify errors as ingestion, retrieval, ranking, reasoning, citation, or
  annotation problems.
- Add regression tests for every corrected failure mode.

### Exit criterion

One command produces a versioned evaluation report from a fixed dataset and
configuration.

## Phase 7 — API and engineering quality

### Learn

- Clean architecture, dependency inversion, configuration, observability, and
  reproducible deployment.

### Implement

- Expose the pipeline through FastAPI.
- Separate domain, ingestion, retrieval, generation, and evaluation modules.
- Add unit, integration, and API contract tests.
- Add linting, formatting, type checking, structured logs, and request IDs.
- Add Docker and CI only after the local pipeline is stable.

### Exit criterion

The same evaluated pipeline runs through the API with documented setup and
automated checks.

## Phase 8 — Post-MVP extensions

These items stay outside the MVP until evidence shows they are useful:

- graph-aware retrieval over ATT&CK STIX relationships;
- query decomposition or agentic retrieval;
- threat reports and organization-specific knowledge sources;
- ingestion of Zeek, NetFlow, Suricata, or SIEM events;
- deterministic network-feature extraction and temporal aggregation;
- analyst feedback and probability calibration;
- local models, fine-tuning, and deployment optimization.

Each extension must be compared with the previous baseline rather than added
because it is architecturally fashionable.
