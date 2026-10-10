# The SPDL subset

ProtoVerify reads a small, deliberately boring protocol description language.
This page is its normative reference.

## File structure

```
declarations*
protocol name(P1, P2, ...) { role+ }
```

Comments are `// to end of line` and `/* block */`.

## Declarations

| Declaration | Meaning |
| --- | --- |
| `usertype Name;` | introduce a user type name |
| `const c: Type;` | a public constant; its type matters for the static checker |
| `hashfunction h;` | declare a one-way hash function usable as `h(x)` |
| `secret s: Type;` | a secret constant (`secret s;` defaults to `Key`); it is **not** public |

`Type` is one of the built-ins (`Nonce`, `Agent`, `Key`, `Data`, `Ticket`,
`Any`) or a name introduced with `usertype`.

### Typing rules

A variable declared with type `T` may only be bound to a term that satisfies
`T`. Each term carries a set of tags:

| term | tags |
| --- | --- |
| `a` (atom: agent name, fresh value, constant) | `agent nonce key data` |
| `pk(a)`, `sk(a)`, `k(a,b)` | `agent key data` |
| tuples, encryptions, signatures, hashes | `nonce data` |
| a variable of type `T` | the tags of `T` |

| declared type | accepts |
| --- | --- |
| `Agent` | `agent`-tagged terms: atoms, public keys, shared keys |
| `Nonce`, `Key`, `Data` | their own tag (`key` terms also satisfy `Data`) |
| `Ticket` (opaque) | **any** term — this is the "ticket"/session-identifier type |
| `Any` | anything |

Because atoms are polymorphic, a nonce and an agent name share the same
constructor; the declared type of the variable is what disambiguates them.

## Protocol header

```
protocol ns(I,R) { ... }
```

The parameters are the **role parameters**: agent names that also name the
roles. Every `role` name must appear in this list (enforced by the static
checker), so the per-run agent environment below is well defined.

## Roles and events

```
role R {
  fresh x: Type;             -- a globally unique value
  var y: Type;               -- a value learned from the network
  send_N(A, B, term);        -- send message N
  recv_N(A, B, term);        -- receive message N
  claim_L(Role, Kind[, arg]);-- a claim
}
```

* `fresh` and `var` declarations must appear **before** their first use; the
  static checker reports `used ... before it is declared` otherwise.
* A `fresh` name may be declared by **one role only** — fresh values are
  globally unique.
* Each message label `N` must be sent exactly once and received exactly once
  across the whole protocol.

### Run model

A **run** is one execution of one role. It is bound to a concrete *agent* (the
role's own parameter) and a concrete *peer* (every other role parameter):

```
agent_env = { P : agent if P == role-name else peer }
```

so in a two-role protocol `ns(I,R)` a run of role `I` with agent `Alice` and
peer `Bob` resolves `I → Alice` and `R → Bob`.

Event semantics inside a run:

* `send_N(A, B, t)` — the run sends `t` **from its own agent to its peer**;
  `A` and `B` are resolved through `agent_env` and are documentation of that.
* `recv_N(A, B, t)` — the run receives `t`. `B` must resolve to the run's own
  agent. `A` resolves to the run's *believed* peer and is **not checked against
  the real sender**: this is exactly what lets the attacker impersonate a peer.
* A fresh declaration creates the unique atom `name#<run id>`, e.g. `ni#1`.
* Variable names are qualified with the run id (`r1::ni`), so several runs of
  the same role never share a variable.

## Terms

| Syntax | Term | Rendering |
| --- | --- | --- |
| `a` | `Atom` | `a` |
| `a,b,c` | `Tuple` | `(a,b,c)` |
| `{m}k` | `SymEnc` | `{m}k(k)` |
| `{m}k(A,B)` | `SymEnc` with a shared key | `{m}k(k(A,B))` |
| `{m}pk(A)` | `AsymEnc` | `{m}pk(A)` |
| `{m}sk(A)` | `Sign` | `{m}sk(A)` |
| `{m}h(x)` | `Hash` | `{m} → h(m)` |
| `pk(A)`, `sk(A)`, `k(A,B)`, `h(x)` | key/hash constructors | as written |
| `{a,b}` | plain `Tuple` when no key operand follows the `}` | `{a,b}` |

`h` may be replaced by any name declared with `hashfunction`.

## Claims

```
claim_L(Role, Secret, term);   -- the attacker must never learn term
claim_L(Role, Alive);          -- the partner must have run
claim_L(Role, Weakagree[, P]); -- the partner ran with us as its partner
claim_L(Role, Niagree[, P]);   -- ... and the data agrees
claim_L(Role, Nisynch[, P]);   -- ... and the messages are identical
```

* `Role` must be the role the claim is written in (a claim states what *its own*
  role guarantees).
* `P` is the partner role; for a two-role protocol it defaults to the unique
  other role, and for more roles it must be given.
* The semantics are specified in [`claims.md`](claims.md).

## Static checks

`protoverify check FILE` reports **every** problem it finds, not just the first:

* a variable used before it is declared, or never declared;
* a `fresh` name declared by two roles;
* a claim naming an undefined claimant or partner role, written in the wrong
  role, or naming itself as partner;
* a message label that is not sent exactly once / received exactly once;
* an undeclared type name;
* a role that is not in the protocol parameter list;
* a role without any message event.

Syntax errors instead come from the parser and point a caret at the offending
column:

```
line 8, col 28: expected ')' after term in message 1
  send_1(I,R, {I,ni}pk(R);
                          ^
```

## Worked example

```
usertype Key;

protocol ns(I,R) {
  role I {
    fresh ni: Nonce;  var nr: Nonce;
    send_1(I,R, {I,ni}pk(R));
    recv_2(R,I, {ni,nr}pk(I));
    send_3(I,R, {nr}pk(R));
    claim_I1(I,Secret,ni);  claim_I2(I,Secret,nr);
    claim_I3(I,Niagree);    claim_I4(I,Nisynch);
  }
  role R {
    var ni: Nonce;  fresh nr: Nonce;
    recv_1(I,R, {I,ni}pk(R));
    send_2(R,I, {ni,nr}pk(I));
    recv_3(I,R, {nr}pk(R));
    claim_R1(R,Secret,ni);  claim_R2(R,Secret,nr);
    claim_R3(R,Niagree);    claim_R4(R,Nisynch);
  }
}
```