# Trace JSON schema

The trace document is the **only** interface between the engine and `viz/`.
Renderers never import the search engine, never call it, and cannot influence a
result. Every document is validated on load by `core/trace.py::validate`; a
malformed document raises `TraceError`.

```jsonc
{
  "protocol": "ns",
  "claim": "R3",
  "status": "FALSIFIED",              // VERIFIED | FALSIFIED | UNKNOWN
  "claim_kind": "Niagree",            // Secret | Alive | Weakagree | Niagree | Nisynch
  "bounds": { "max_runs": 4, "max_len": 20 },
  "agents": [
    { "id": "I", "kind": "honest" },
    { "id": "M", "kind": "attacker" }
  ],
  "runs": [
    { "id": 1, "role": "I", "agent": "I", "peer": "M" },
    { "id": 2, "role": "R", "agent": "R", "peer": "I" }
  ],
  "steps": [
    {
      "i": 1,
      "type": "send",                 // send | recv | attacker_forward | attacker_inject
      "run": 1,                       // null for attacker steps
      "from": "I",
      "to": "M",
      "label": "1",
      "msg": "{I,ni#2}pk(M)",
      "attacker_new": ["ni#2"],       // terms learned from this step
      "note": "I sends message 1 to M."
    }
  ],
  "edges": [
    { "from": 1, "to": 4, "kind": "message" }   // 1-based step numbers
  ],
  "violation": "R believes its I partner is I, but the I run(s) of this trace are I talking to M; claim R3 (Niagree) does not hold."
}
```

## Field reference

| field | type | required | meaning |
| --- | --- | --- | --- |
| `protocol` | non-empty string | yes | protocol name from the SPDL file |
| `claim` | non-empty string | yes | claim label, e.g. `R3` |
| `status` | `VERIFIED`/`FALSIFIED`/`UNKNOWN` | yes | outcome for this claim |
| `claim_kind` | one of the five claim kinds | no | which claim was broken |
| `bounds` | object | no | the limits the search ran under |
| `agents[].id` | non-empty string | no | agent name |
| `agents[].kind` | `honest`/`attacker` | no | drives the colour palette |
| `runs[].id` | integer | no | unique run id; `steps[].run` refers to it |
| `runs[].role` | string | no | role name of the run |
| `runs[].agent` | string | no | the agent playing the role |
| `runs[].peer` | string | no | the agent the run believes is its partner |
| `steps[].i` | integer | no | 1-based position; must be exactly `1..n` without gaps |
| `steps[].type` | see above | no | `attacker_*` steps are drawn red and dashed |
| `steps[].run` | integer or `null` | no | the run that performed it (`null` = attacker) |
| `steps[].from`, `steps[].to` | non-empty string | no | endpoints |
| `steps[].label` | string | no | the message label |
| `steps[].msg` | non-empty string | no | the concrete message, rendered |
| `steps[].attacker_new` | array of strings | no | terms the attacker learnt, highlighted yellow |
| `steps[].note` | string | no | one-line natural-language caption |
| `edges[]` | object | no | causal edges; `from` must be `< to` |
| `violation` | string | no | one sentence shown on the final frame |

## Validation rules

`Trace.from_json` rejects a document when:

1. `protocol`, `claim`, `msg`, `status` or an agent `id` is missing or empty;
2. `status` is not one of the three outcomes, or `claim_kind` is not a claim kind;
3. two agents share an id, or two runs share an id;
4. step numbers are not exactly `1..n`;
5. a step has an unknown `type`, references an unknown `run`, or an empty `msg`;
6. an edge points outside `1..n` or is not a forward edge;
7. a field has the wrong JSON type.

## Step types

| type | drawn as | meaning |
| --- | --- | --- |
| `send` | solid arrow, sender colour | an honest run executed `send_N` |
| `recv` | solid arrow, receiver colour | the message came from the run's own peer |
| `attacker_forward` | red dashed arrow from the attacker | the attacker relayed a message it had seen |
| `attacker_inject` | red dashed arrow from the attacker | the attacker built a message from its own knowledge |

## Rendering rules (shared by both back-ends)

* honest agents are blue / green (alternating, stable per run), the attacker red;
* forged or relayed messages are red and dashed;
* a term listed in `attacker_new` is highlighted yellow in the knowledge panel;
* every frame shows the step number and its `note`;
* long terms are abbreviated (both ends kept) — the renderer owns this choice;
* the last frames add `violation`.

## Producing a document

```bash
protoverify verify examples/ns.spdl --trace-dir traces     # writes traces/ns_R3.json
protoverify animate examples/ns.spdl --claim R3 --out a.gif # verify + render
```

The Python API is `Trace.from_file(path)`, `Trace.to_file(path)` and
`Trace.to_json()` / `Trace.from_json(dict)`.