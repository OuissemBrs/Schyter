# Limitations

Read this before you rely on a `VERIFIED`.

## What `VERIFIED` does and does not mean

ProtoVerify reports `VERIFIED` when it **exhausted the bounded search space**
without finding a counterexample. That is a statement about the search, not a
proof about the protocol. Concretely, a `VERIFIED` claim means:

> No trace falsifying this claim was found with at most `--max-runs` role
> instances, at most `--max-len` events in total, at most one run per role, and
> within `--max-states` explored states and `--timeout` seconds.

If a budget runs out first the answer is `UNKNOWN`, together with the reason.
The engine never downgrades `UNKNOWN` to `VERIFIED` and never reports a claim it
did not actually check.

## Explicitly out of scope

* **Unbounded verification.** ProtoVerify does not use pattern refinement, so it
  cannot conclude "no attack exists" the way Scyther can. Every answer is
  relative to the bounds above.
* **Stateful protocols.** No state, state-space or `let` constructs: a role is a
  straight-line sequence of events. Loops, counters and retransmission are out.
* **Algebraic equations.** No Diffie–Hellman, no XOR, no exponentiation, no
  equational theory of any kind. The term algebra is *free*: `a*b` does not
  equal `b*a` because there is no multiplication. A protocol whose security
  argument needs an algebraic identity (e.g. `g^(ab) = g^a · g^b`) cannot be
  checked here.
* **Computational or probabilistic security.** Everything is perfect-cryptography
  and zero-error: an attacker either can build a term or cannot, forever. No
  side channels, no probabilities, no reduction proofs, no computational bounds.
* **Protocol composition.** No mutual recursion, no sub-protocol calls, no
  verification-modular "assume the sub-protocol is secure" reasoning.
* **Key agreement terms.** There is no explicit Diffie–Hellman, so protocols
  written with DH primitives cannot be expressed.
* **Type flaws in the Dolev-Yao sense** (e.g. non-injective encryption
  properties, key confusion) are out of scope; only perfect encryption and
  perfect signatures are modelled.

## Known incompletenesses of the search

These are honest gaps, not bugs:

* **One run per role** (`Bounds.max_runs_per_role = 1`). An attack that needs two
  runs of the *same* role interacting is missed.
* **The claimant's agent is fixed** to the protocol parameter with the same name
  as the role. Attacks that require a *different* agent to play the claimant's
  role are not searched.
* **The honest-run condition.** All claims are evaluated only over traces in
  which the claimant run's agent *and* peer are honest. If the protocol is meant
  to survive talking to the attacker, that is out of scope — write a `Secret`
  claim for it, or use `--compromise` to model a specific bad agent.
* **Only completed traces.** The search terminates when every message event of
  every run has fired. A falsifying trace in which the partner run gets *stuck*
  (never receives its last message) is therefore not produced: an incomplete
  partner run is indistinguishable from an absent one in the final check.
* **Guessing is restricted.** The attacker may invent values for `Agent` and
  `Ticket` variables, and may replay any *atom* it knows (typically a nonce it
  decrypted earlier), but it may not bind a nonce variable to a constructed
  term such as `pk(a)` or `h(x)`. That keeps the search finite and avoids
  nonsense bindings; it can, in principle, miss an attack that needs one.
* **Candidate truncation.** At most 12 candidate values and 128 guess
  combinations per receive event. A knowledge set larger than that may hide the
  value an attack needs.
* **Two-role agent environment.** For a protocol with more than two roles, every
  non-self role parameter of a run resolves to the run's peer (a broadcast
  model).

## How this differs from the tools it resembles

### Scyther

| | Scyther | ProtoVerify |
| --- | --- | --- |
| Unbounded search | yes, via **pattern refinement** (rules over patterns, not concrete terms) | no — bounded concrete exploration |
| Result for a secure protocol | a proof ("no attack within refinement") | "no counterexample within these bounds" |
| Speed | much faster on large protocols; rules collapse infinite behaviour | exhaustive over a small bound, so it scales only to small protocols |
| Attack traces | yes, rendered in the Scyther GUI | yes, as validated JSON rendered by matplotlib/Manim |
| Claim language | `Secret`, `Alive`, `Weakagree`, `Niagree`, `Nisynch` | the same five, same hierarchy |

ProtoVerify is essentially a small, readable teaching implementation of the same
*model*: Dolev–Yao knowledge, role instances, and the four agreement levels. What
it trades away for simplicity is completeness: Scyther generalises each concrete
execution into a rule and iterates, so it terminates on the infinite trace space.
ProtoVerify enumerates concrete traces and must be cut off.

### Tamarin

Tamarin works over the *applied pi-calculus* with equational theories. It can
therefore reason about Diffie–Hellman (`g^(ab)`), subterm and equational
conversions, and non-free term structure. Tamarin also supports unbounded
sessions and stateful protocols. ProtoVerify has **no equational theory at all**
and no unbounded sessions; what it has in return is a 300-line search loop a
reader can follow, and animations that most tools do not produce.

### ProVerif

ProVerif is also symbolic and handles unbounded sessions, but it verifies
*security properties in the shape ProVerif supports* (secrecy, some
authentication properties) rather than a family of quantified agreement claims.
It applies a number of well-understood optimisations — congruence, key-tables,
simplification — to reach conclusions on large, real-world protocols such as
TLS or Tor's handshake. ProtoVerify supports neither the optimisations nor the
protocol classes: it will happily search a small academic protocol exhaustively
and say `UNKNOWN` on anything large, because the budget runs out first.

### Summary

| | Scyther | Tamarin | ProVerif | ProtoVerify |
| --- | --- | --- | --- | --- |
| Unbounded sessions | yes | yes | yes | **no** |
| Equational theory | none (free terms) | yes (DH and more) | yes (DH) | none |
| Stateful protocols | no | yes | yes | no |
| Agreement claims | 4 levels | 3 levels | partial | 4 levels |
| Counterexample traces | yes | yes | no (often) | yes, always replayed and rendered |
| Animation | GUI | no | no | matplotlib + Manim |
| Readable in an afternoon | no | no | no | yes |

## If you need more

* Raise the bounds (`--max-runs`, `--max-len`, `--timeout`) and watch for
  `UNKNOWN`; if the search is being cut off, the answer is simply not known.
* For DH or algebraic protocols, use Tamarin or ProVerif.
* For a real proof of a small protocol, use Scyther.