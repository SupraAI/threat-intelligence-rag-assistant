# Threat Intelligence RAG Assistant

An educational Retrieval-Augmented Generation (RAG) project that maps a
natural-language behavior description to plausible
[MITRE ATT&CK Enterprise](https://attack.mitre.org/matrices/enterprise/)
techniques and explains every proposed mapping with evidence and inspectable
sources.

> **Current status:** Phase 1 — parsing and normalizing the ATT&CK Enterprise
> knowledge base. Embeddings, retrieval, and LLM generation have not been
> implemented yet.

## Why this project exists

This project is designed as a step-by-step introduction to Generative AI for
someone with a machine-learning and data-science background. Its objective is
not only to produce an assistant, but also to make each component independently
understandable and measurable:

1. knowledge ingestion and normalization;
2. lexical and semantic retrieval;
3. grounded LLM generation;
4. end-to-end evaluation;
5. production-quality packaging and observability.

## MVP

### Input

A natural-language description of an observed behavior.

Example:

> A workstation establishes a short HTTPS connection to the same previously
> unseen domain every 60 seconds and transfers a small, regular amount of data.

### Output

A ranked list of plausible ATT&CK techniques. Each candidate must provide:

- the ATT&CK technique ID and name;
- why the behavior fits the technique;
- which facts from the input support the mapping;
- which ATT&CK facts support the explanation;
- inspectable source references;
- uncertainties and missing information.

The assistant must return `insufficient_evidence` when the behavior does not
support a responsible mapping.

### Initial ATT&CK scope

- Enterprise ATT&CK only;
- active parent techniques only;
- sub-techniques are deliberately excluded from the first iteration;
- tactics, platforms, detection strategies, procedure examples, object
  versions, and source references are retained as technique context;
- revoked and deprecated techniques are excluded.

Sub-techniques will be introduced only after the parent-technique retrieval
baseline has been evaluated.

### Outside the MVP

- raw PCAP, Zeek, NetFlow, Suricata, or live SIEM ingestion;
- automated intrusion detection;
- threat-actor attribution;
- incident-response actions;
- graph or agentic RAG;
- fine-tuning and calibrated attack probabilities.

The assistant proposes evidence-backed ATT&CK mappings. It does not prove that
an intrusion occurred.

## MVP pipeline

```text
Versioned ATT&CK Enterprise STIX bundle
                    |
                    v
        Parse and normalize techniques
                    |
                    v
      Lexical baseline, then embeddings
                    |
                    v
       Retrieve candidate techniques
                    |
                    v
     LLM ranks and explains candidates
                    |
                    v
 Techniques + evidence + sources + uncertainty
```

The source text is preserved after embedding. A vector is only a search
representation and cannot be used as evidence or as a citation.

## Conceptual response contract

```json
{
  "status": "mapped | ambiguous | insufficient_evidence",
  "candidates": [
    {
      "rank": 1,
      "attack_id": "Txxxx",
      "name": "Technique name",
      "explanation": "Why this candidate fits the observation",
      "behavior_evidence": ["Fact copied or derived from the input"],
      "attack_evidence": ["Supporting fact retrieved from ATT&CK"],
      "sources": ["Stable ATT&CK identifier or URL"],
      "uncertainties": ["What remains unknown or ambiguous"]
    }
  ]
}
```

This will become a typed Pydantic contract during the grounded-generation
phase.

## Repository contents

```text
.
|-- data/
|   |-- enterprise-attack (2).json     # Supplied ATT&CK STIX source bundle
|   |-- DATA_VERSION.json              # Dataset provenance and fingerprint
|   `-- processed/
|       `-- enterprise_techniques.json # Generated normalized dataset
|-- src/
|   |-- __init__.py
|   `-- parser/
|       |-- __init__.py
|       `-- mitre_parser.py
|-- tests/
|   `-- test_mitre_parser.py
|-- pyproject.toml
|-- uv.lock
|-- ROADMAP.md
`-- README.md
```

`data/processed/enterprise_techniques.json` is a generated artifact. Run the
parser to create or refresh it.

## Environment setup

The project uses Python 3.12 and
[`uv`](https://docs.astral.sh/uv/) for dependency management.

```bash
uv sync --all-groups
```

Useful checks:

```bash
uv run pytest
uv run ruff check .
```

## Parse the ATT&CK bundle

The default command reads the supplied bundle and writes the normalized parent
techniques to `data/processed/enterprise_techniques.json`:

```bash
uv run python -m src.parser.mitre_parser
```

Explicit paths can also be provided:

```bash
uv run python -m src.parser.mitre_parser \
  --input "data/enterprise-attack (2).json" \
  --output data/processed/enterprise_techniques.json
```

The parser:

1. validates the top-level STIX bundle structure;
2. extracts and orders Enterprise tactics;
3. selects active parent `attack-pattern` objects;
4. excludes sub-techniques, revoked objects, and deprecated objects;
5. joins `uses` relationships as procedure examples;
6. joins `detects` relationships as detection strategies;
7. preserves IDs, timestamps, versions, platforms, references, and provenance;
8. creates deterministic `retrieval_text` for the future search index.

Dataset provenance and the exact SHA-256 fingerprint are documented in
[`data/DATA_VERSION.json`](data/DATA_VERSION.json).

## Evaluation strategy

Retrieval and generated responses are evaluated separately so that an error can
be attributed to ingestion, retrieval, ranking, or LLM reasoning.

### Retrieval

- Recall@k and Precision@k;
- Mean Reciprocal Rank;
- nDCG@k for graded relevance.

### Final technique mapping

- Top-1 accuracy and Hit Rate@k;
- micro and macro precision, recall, and F1 for multi-label cases;
- final ranking MRR or nDCG.

### Explanations and sources

- citation correctness and completeness;
- evidence precision;
- grounded-claim and unsupported-claim rates.

### Abstention and operations

- abstention precision and recall;
- coverage and selective risk;
- latency, token usage, cost, and schema-validation failure rate.

Raw cosine similarity or LLM self-reported confidence will not be presented as
a calibrated probability.

## Definition of MVP completion

The MVP is complete when one reproducible pipeline can:

1. ingest the recorded ATT&CK Enterprise snapshot;
2. retrieve and rank techniques for a behavior description;
3. produce a schema-valid explanation with evidence and sources;
4. abstain on insufficient descriptions;
5. report retrieval, mapping, grounding, and operational metrics on a fixed,
   human-reviewed evaluation set.

See [`ROADMAP.md`](ROADMAP.md) for the staged implementation plan.

## Data notice

This project uses MITRE ATT&CK data. ATT&CK is a registered trademark of The
MITRE Corporation. Refer to the official
[ATT&CK data and tools page](https://attack.mitre.org/resources/attack-data-and-tools/)
and [ATT&CK terms of use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/)
for authoritative data and usage information.
