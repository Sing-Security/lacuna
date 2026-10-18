# LACUNA - Demand-Driven Semantic Closure Engine

**Milestone 1: diagnosis without repair.**

LACUNA is a *semantic coverage authority* for concolic and symbolic-execution
sessions. Given the report a hybrid engine already produced, it answers one
question:

> Which semantic gap blocked which coverage, and at what trust does the engine
> know it?

It does not synthesize approximations, and it does not repair gaps. It reads
what the engine measured - the stop condition, the gap notes, the flip
ledger, the property-query ledger - and emits a **trust-carrying diagnosis**:
one certificate per claim, each stating what was observed and what that
observation licenses.

The theory is stated at the *report boundary*, not at an instruction set.
Nothing in this crate names a register, a syscall number, a memory layout, or
a vendor vocabulary. Any frontend that emits the
[`concolic-core`](https://crates.io/crates/concolic-core) contract is
diagnosed by the same code and receives the same semantics - the
frontend-invariance principle (paper §2.1).

```toml
[dependencies]
lacuna-core = "0.1"
concolic-core = "0.1"
```

---

## A worked example

A session ran four concrete executions. It verified one flip, proved one
decision unflippable, re-landed on a path it had already seen, hit one call
the host does not model, sealed one digest over attacker bytes, and asked one
property question.

```rust
use concolic_core::{FlipOutcome, FlipRec, Opts, PropertyOutcome, PropertyRec, Report};
use lacuna_core::diagnose;

let report = Report {
    result: Some(0),
    runs: 4,
    flips_verified: 1,
    exhausted: true,
    flips: vec![
        FlipRec { at: 0x401010, input: vec![("in!x".into(), 0x1337)], verified: true,
                  outcome: FlipOutcome::Verified },
        FlipRec { at: 0x401040, input: vec![], verified: false,
                  outcome: FlipOutcome::ProvenUnflippable },
        FlipRec { at: 0x401080, input: vec![("in!x".into(), 0x99)], verified: false,
                  outcome: FlipOutcome::AlreadyExplored },
    ],
    gaps: vec![
        "a call at 0x4010f0 is outside the syscall model, so the lift trapped on it".into(),
        "a value at 0x401100 hashes attacker-derived bytes - sealed to this input".into(),
    ],
    properties: vec![PropertyRec {
        label: "written == 0".into(),
        outcome: PropertyOutcome::Proven,
        violation: None,
        input: vec![],
    }],
    ..Report::default()
};

let diagnosis = diagnose(&report, &Opts::default());
print!("{diagnosis}");
```

The rendered diagnosis is the artifact an operator reads and a downstream
tool consumes:

```text
LACUNA diagnosis (milestone 1: diagnosis without repair)
  runs 4  flips-verified 1  result 0 (0x0)
  stop: Exhausted
  outcomes (3)
    Verified: 1
    ProvenUnflippable: 1
    AlreadyExplored: 1
  property queries (1)
    Proven: 1
  blockers (2)
    [A] UnmodelledSyscall: 1
    [C] SealedDerivation: 1
  certificates (7)
    [1] trust Exact
        claim: the flip frontier emptied inside the budgets: every decision the solver saw was flipped or proven unflippable under its prefix - within the modelled surface, no other input reaches anything new (sealed constants and unmodelled answers were never variable)
        evidence: runs=4 flips_verified=1 result=0 exhausted=true unresolved_attempts=0
    [2] trust Empirical class [A] site 0x4010f0
        claim: the call is outside the host's syscall model and the lift trapped on it: the run ended at the call, so nothing downstream of it was observed, and the model's answer (where one exists) is an approximation, not the runtime's
        evidence: a call at 0x4010f0 is outside the syscall model, so the lift trapped on it
    [3] trust Conditional class [C] site 0x401100
        claim: a digest/address derived from attacker-derived bytes is sealed to the real implementation's value for THIS input: decisions on it are constants to the solver - a re-run with different bytes changes it, but only under some other decision's flip
        evidence: a value at 0x401100 hashes attacker-derived bytes - sealed to this input
    [4] trust Exact site 0x401010
        claim: an input reaching this decision was found and the ENGINE ran it: the site is reachable, and the attempt's input is the machine-checked witness
        evidence: flip attempt at 0x401010 (Verified), input: in!x=0x1337
    [5] trust Exact site 0x401040
        claim: no assignment to the ATTACKER surface flips this decision under its path prefix with non-attacker memory as seeded (the solver completed `Unsat`): under the walker's own path formula, this decision is fixed
        evidence: flip attempt at 0x401040 (ProvenUnflippable), input: seed input
    [6] trust Exact site 0x401080
        claim: the engine's run DID take the opposite side of this decision, but the resulting path was already explored: the model and the run agree, and no new decision path was discovered past this flip
        evidence: flip attempt at 0x401080 (AlreadyExplored), input: in!x=0x99
    [7] trust Exact
        claim: no assignment to the ATTACKER surface on this walked path violates the invariant (the solver completed `Unsat` under the path formula): a local negative, exact with respect to the walker's formula
        evidence: property query `written == 0` (Proven), input: seed input
```

Read one certificate and you know exactly what was established, by what
evidence, and with which caveat. That is the whole product.

---

## The diagnosis

`Diagnosis` carries run counters, the **stop**, the **flip ledger** by
structured outcome, the **property-query ledger** by structured outcome, the
**classified blockers**, and a `Vec<Certificate>`. Every field is public for
machine consumers; `render()` is a deterministic text form for humans.

`Certificate { site, class, trust, claim, evidence }` is the unit of
accountability. Certificate order is a fixed contract - stop, then gaps, then
flips, then properties, each in report order - so offsets are stable across
sessions that differ only in tail length.

### Stop semantics

A stop is only meaningful against the budgets the session ran under, which is
why `diagnose` takes `Opts` as well as the report.

| Stop | Means | Does **not** mean |
|---|---|---|
| `Exhausted` | The report marks the search complete: the frontier emptied with no attempt skipped by a budget and every discovered path walked. When every attempt is also exact, that licenses "every decision the solver saw was flipped or proven unflippable under its prefix". | A coverage claim by itself - the adequacy condition is checked separately (see below). Nor that the *program* has no more behaviors: only the modelled surface. Sealed constants and unmodelled answers were never variable. |
| `BudgetRuns` | The run budget was hit; decisions remain unposed. | Exhaustion. The claim text says "NOT empty" in so many words. |
| `BudgetFlips` | The verified-flip budget was hit; further flips were possible. | Exhaustion. |
| `Undetermined` | The search stopped with neither an emptied frontier nor a reached budget; the report does not mark exhaustion, and any limit it recorded is in the gap ledger. | Anything. Coverage is open, and the diagnosis says so. |

Exhaustion wins over a budget that was also reached, matching the engine's
check-before-attempt discipline: counters never overshoot the budgets they
are read against. The mandatory base run is the one exception at the edge -
it happens even when `max_runs` is 0, so `runs` can be 1 there.

`Exhausted` is a report fact; it is not by itself a coverage claim. Theorem 1's
side condition is that every attempt in the flip ledger reached an *exact*
outcome (`Verified`, `ProvenUnflippable`, `AlreadyExplored`). An `Unconfirmed`,
`SolverUnknown`, `NotPosed` or `RunFailed` attempt leaves the adequacy
condition unmet. The stop certificate therefore says `Exact` only when the
ledger is all-exact, and otherwise says `Unknown` with an explicit "not a
coverage claim"; its evidence records `unresolved_attempts`. Machine consumers
should call `Diagnosis::coverage_licensed()` - the same predicate - rather
than comparing `stop` to `Exhausted` by hand. `BudgetRuns`, `BudgetFlips` and
`Undetermined` are `Exact`, `Exact` and `Unknown` about the stop respectively;
none of them licenses coverage.

Theorem 1's scope clause is also *load-bearing*: even a licensed claim is
about the decisions the solver saw, not about the program's full input domain.
`coverage_licensed()` is a predicate over the **flip** ledger, so it says
nothing about the property ledger: a query that never reached a verdict
(`SolverUnknown`, `NotPosed`, `RunFailed`) leaves the invariant question open
and must be gated separately. It also reads each attempt's structured
`outcome`, not `FlipRec::verified`; the engine contract keeps `verified` true
exactly for `Verified`, and a hand-built report must do the same.

### Blocker taxonomy

Free-text gap notes are classified by a decision list (Proposition 3: total
and single-valued). An unrecognized note is `Unclassified` - preserved
verbatim, counted, never guessed.

| Class | Meaning | Trust |
|---|---|---|
| `UnmodelledSyscall` (A) | A call outside the host's model; the lift trapped and the run ended there. | `Empirical` |
| `LiftCap` (B) | The run ended at a construct the lifted module does not carry - the *module's* extent, not the program's behavior. | `Empirical` |
| `SealedDerivation` (C) | A digest or address derived from attacker-derived bytes is sealed to the real implementation's answer for *this* input. | `Conditional` |
| `UnmodelledAddress` (D) | The walk used a symbolic address outside its bounded window; more solver time cannot change the answer. | `Unknown` |
| `SolverGaveUp` | The solver hit a configured bound before a verdict. | `Unknown` |
| `EngineLimit` | An engine-internal replay limit (divergence, walk budget, host-model limit). | `Unknown` |
| `GuestTrap` | The engine's reference run trapped - the program's own behavior as modelled. The note states the trap; a failed symbolic replay is a separate `EngineLimit` note. | `Empirical` |
| `Unclassified` | No rule matched. Kept verbatim and counted. | `Unknown` |

### The flip ledger

Verification is a predicate on *decisions*, not on operands (Proposition 4):
a reported input is a witness the engine confirmed by re-running it, never a
solver claim.

| `FlipOutcome` | Means | Trust |
|---|---|---|
| `Verified` | The engine re-ran the model and took the opposite side. | `Exact` |
| `ProvenUnflippable` | The flip query completed `Unsat` under the path prefix. | `Exact` |
| `AlreadyExplored` | The flip happened, but the resulting path was already discovered. `verified` is false: nothing new was established. | `Exact` |
| `SolverUnknown` | The solver hit a bound before a verdict. | `Unknown` |
| `NotPosed` | No verification run was spent. | `Unknown` |
| `RunFailed` | The verification run failed at the engine level. | `Empirical` |
| `Unconfirmed` | The model ran but did not take the opposite side - walker and engine disagree. Evidence against the *model*, never for the program (Proposition 5). | `Empirical` |

The two exact universal claims (`ProvenUnflippable`) rest on Theorem 2; the
exact existential claim (`Verified`) rests on Theorem 3. Both are relative to
the solver's semantics - the trusted computing base - and the certificates say
so rather than implying independent proof.

### The property ledger

A branch flip cannot reach a straight-line violation: with no decision in
front of a bad store there is no branch to flip (Theorem 4). The property
ledger asks the end-state question instead, posing `path ∧ ¬invariant` on
each walked path.

| `PropertyOutcome` | Means | Trust |
|---|---|---|
| `Confirmed` | The solver's model was applied and the engine's own run reproduced a violating readback. A machine-checked witness (Theorem 6). | `Exact` |
| `Proven` | `Unsat` under this path's assumptions - no input reaching *this path* violates the invariant. A local negative (Theorem 5), not a program-wide proof. | `Exact` |
| `SolverUnknown` | The solver hit a bound before a verdict. | `Unknown` |
| `NotPosed` | No verification run was spent: the budget was exhausted, an operand has no symbolic form, or the run trapped with no post-state to read. | `Unknown` |
| `RunFailed` | The model was applied and the re-run trapped or failed at the engine level. | `Empirical` |
| `Unreproduced` | The model ran but did not violate; walker and engine disagree. Refutes a hypothesis, not the program (Proposition 6). | `Empirical` |

`Confirmed` is a witness; `Proven` is a local negative. They share a trust
level but not a meaning. `NotPosed` stays `Unknown` on purpose: nothing was
observed, so nothing is claimed (Proposition 7).

### The trust calculus

Trust is a function of the *kind* of claim, not of how good the session felt.

| Trust | Meaning |
|---|---|
| `Exact` | A machine-checked fact about a run that happened (a verified flip, a reproduced violation, a stated stop) or a completed solver verdict. |
| `Conditional` | True of the concrete run, conditional on its input - a sealed value. |
| `Empirical` | Observed engine behavior, not a proof. |
| `Unknown` | The absence of a verdict. |
| `SoundOverApprox` | **Reserved.** Nothing in M1 earns it, and nothing may claim it until the reasoning that justifies it exists. |

Proposition 8 is the upper-bound law: a claim is never more trusted than its
weakest load-bearing evidence. Proposition 9 says certificates do not compose
for free - an `Exact` witness and an `Exact` universal verdict do not add up
to an `Exact` mixed claim without new reasoning.

---

## Determinism

`Diagnosis` is a pure function of `(Report, Opts, Classifier)` (Theorem 7).
Same inputs, same bytes out - there is no clock, no randomness, no hash-map
iteration order in the rendered form. That makes a diagnosis diffable in CI:
you can pin the rendered text as a golden artifact, and a change in it is a
change in semantics rather than in presentation.

`render()` is also the serialization format used by recorded artifacts. If you
need structured data, read the public fields and serialize them yourself;
they are the source of truth, and `render()` reads only them. Report-controlled
strings (gap notes, labels, input names) are interpolated verbatim, including
embedded newlines: it is a golden format for reports from a trusted engine,
not a sanitizer for untrusted ones.

---

## Examples

Five runnable examples, ordered as a tutorial. Each compiles its claims into
assertions, so running one is also running its proofs-of-claim.

```sh
cargo run -p lacuna-core --example 01_exhausted_session
cargo run -p lacuna-core --example 02_stop_honesty
cargo run -p lacuna-core --example 03_frontend_classifier
cargo run -p lacuna-core --example 04_property_ledger
cargo run -p lacuna-core --example 05_coverage_gate
```

| # | Example | What it teaches |
|---|---|---|
| 1 | `01_exhausted_session` | The full artifact: three flip outcomes, two blockers, one property query, seven certificates, and the certificate-order contract. |
| 2 | `02_stop_honesty` | The four stops side by side and the honesty assertions: silence must never read as coverage. |
| 3 | `03_frontend_classifier` | Extending the classifier without teaching the public crate a private vocabulary; unknown → named; `Unknown` → `Conditional`; precedence is order. |
| 4 | `04_property_ledger` | All six property outcomes, their three distinct kinds of claim, and why `NotPosed` stays `Unknown`. |
| 5 | `05_coverage_gate` | Using the diagnosis as a conservative, machine-readable coverage gate - refusing to assume an unclassified gap is *not* a model boundary, refusing to promote an emptied frontier to coverage when an attempt never resolved, and keeping the property ledger's open questions open. |

Example 5 is the intended downstream pattern: a CI gate reads public fields,
never prose, and returns a verdict that cannot be stronger than the evidence.

---

## The classifier is a frontend boundary

`Classifier::generic()` recognizes generic producer phrasings only: a seal
note, a call outside the syscall model, a symbolic address outside the
modelled window, a solver bound, a lift-emitted trap, a guest trap, an
engine-level run failure, and a walker replay limit. It knows no engine's
private vocabulary; a frontend that spells a note differently supplies the
rule for it.

A frontend whose engine spells an additional note differently prepends its own
rule:

```rust
use concolic_core::{Opts, Report};
use lacuna_core::{BlockerClass, Classifier, Rule, diagnose_with};

let classifier = Classifier::generic().prepend(Rule::contains(
    BlockerClass::EngineLimit,
    "my engine's private note",
));

let diagnosis = diagnose_with(&report, &Opts::default(), &classifier);
```

`prepend` is the entire extension mechanism. Rules are tried in order, so
precedence is order, not specificity-by-magic - put specific patterns before
broad ones. A vendor adapter is a thin module outside this crate that owns its
vocabulary; the public crate stays frontend-invariant, and a note nobody
recognizes stays `Unclassified` instead of being guessed into a class.

---

## Paper map

The crate is the executable form of the theory. Section and theorem numbers
refer to *LACUNA: The Demand-Driven Semantic Closure Engine* (rev 2, 17 Oct
2026).

| Crate concept | Paper |
|---|---|
| Frontend invariance / report as interface | §2.1 |
| The diagnosis problem and algorithm | §4, §4.1 |
| Stop table and adequacy of exhaustion | §5.1-5.3, Theorem 1 |
| Blocker taxonomy; classifier totality | §6.1-6.4, Proposition 3 |
| Flip outcome algebra; witness validity | §7.1-7.5, Proposition 4, Theorem 2, Theorem 3, Proposition 5 |
| Property-directed queries | §7.5, §12.3, Theorem 4, Theorem 5, Theorem 6, Proposition 6, Proposition 7 |
| Trust calculus; upper-bound law | §8.1-8.3, Proposition 8, Proposition 9 |
| Deterministic rendering | §9, Theorem 7 |
| `SoundOverApprox` (reserved) | §10, §11 |
| Limitations and trusted computing base | §14 |

---

## Known incompleteness (stated, not hidden)

- **Unmodelled calls the model *answered*** are recorded by some hosts as sink
  records rather than report gaps, so M1 cannot cite them. Harvesting them
  into the report is **M1.1**.
- The classifier reads free-text gaps. Structured gap kinds are **M2**, with
  the binding that the raw text stays byte-identical in the report.
- **M2** also carries per-path records for true per-sink causal attribution,
  the exhausted-true-with-unswept-suffix detector at the budget edge, and a
  per-path causal record for each `Unconfirmed`.
- The structural split of `Exhausted` into `Exhausted` /
  `ExhaustedUnresolved` is **M2**. M1 already checks Theorem 1's side
  condition at diagnosis time (`coverage_licensed`), but the stop value in the
  report itself does not yet carry the split.
- **M3+** - contract synthesis, the soundness gate, and the closure scheduler -
  stay unbuilt until M1/M2 prove the diagnosis is right on real campaigns.

What M1 claims is accordingly narrow: *this* is the stop, *these* are the
blockers, *these* are the exact outcomes, and *this* is the strongest thing
any of it licenses. Narrow and true beats broad and unearned.

---

## License

Apache-2.0.
