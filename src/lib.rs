//! LACUNA - the **Demand-Driven Semantic Closure Engine**, Milestone 1:
//! **diagnosis without repair**.
//!
//! LACUNA reads what the hybrid engine already measured - its flip ledger, its
//! gap notes, its stop condition - and answers the question a report reader
//! actually has: *which semantic gap blocks which coverage, and at what trust
//! does the engine know it?*
//!
//! Milestone 1 synthesizes nothing and repairs nothing. It:
//!
//! 1. **Classifies** every raw gap into the blocker taxonomy - case A
//!    (unmodelled syscall), case B (lift cap / lift gap), case C (sealed
//!    hash/derivation), case D (symbolic address outside the model's window),
//!    plus the classes a real report needs to stay honest (solver bound,
//!    engine replay limit, a faithful guest trap, and an explicit bucket for
//!    anything the adapter does not know yet).
//! 2. **Ledgers** every flip attempt by its structured outcome
//!    ([`concolic_core::FlipOutcome`]): a proven-unflippable decision and a
//!    solver that timed out are different facts and are counted separately.
//! 3. **Ledgers every property query** by its structured outcome
//!    ([`concolic_core::PropertyOutcome`]): a query posed as a solve target
//!    is not the same fact as a post-run readback, and a confirmed witness,
//!    a proven local negative, an unreproduced model and a missed run are
//!    four different claims.
//! 4. **States the stop** - including what the stop does *not* say: budget
//!    stops do not carry "exhausted", and the diagnosis says so instead of
//!    letting silence read as coverage.
//! 5. **Attaches trust** to every claim via the fixed table (never inferred
//!    from the claim's tone): machine-checked run facts and completed solver
//!    verdicts are `Exact`; sealed values are `Conditional` on this input;
//!    model-mediated behavior is `Empirical`; absence of a verdict is
//!    `Unknown`. `SoundOverApprox` is reserved for reasoning over a sound
//!    over-approximation (the planned theory layer) and nothing in M1 earns
//!    it.
//!
//! The output is a [`Diagnosis`]: counts, a classified gap list, and a
//! certificate per claim. [`Diagnosis::render`] is the deterministic text
//! form; everything is also a public field for machine consumers - LACUNA is
//! meant to become the semantic coverage authority the rest of the
//! experimental stack queries.
//!
//! **What M1 deliberately is not.** The classifier reads the engine's gap
//! *strings*, which are a reviewed, stable format. The crate ships a generic
//! table and lets a frontend add its producer-specific patterns
//! ([`Classifier`]); the diagnosis surface does not move when a producer
//! rewords a note. And a certificate is only as complete as the report
//! behind it: unmodelled calls that the model *answered* are recorded by the
//! host as sink records, so they are inventoried separately, not here.
//!
//! **Scope.** Every item in this crate is stated over the report contract in
//! [`concolic_core`] - traces, decisions, outcomes, budgets. Nothing here
//! names an instruction set, a register, a syscall number or a memory
//! layout; a frontend supplies the report and (optionally) its gap patterns.

use std::collections::BTreeMap;

use concolic_core::{FlipOutcome, Opts, PropertyOutcome, Report};

// region:    --- taxonomy

/// What stopped or weakened a path, in the diagnosis's own terms.
///
/// Variants `UnmodelledSyscall`/`LiftCap`/`SealedDerivation` are the design's
/// cases A/B/C; the rest exist because a real report contains stops that are
/// neither of those and calling them "unclassified" would hide known facts.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum BlockerClass {
    /// **Case A.** The call is outside the host's syscall model: the lift
    /// trapped on it and the run ended at the call. The model's answer (if it
    /// had one) would be an approximation - nothing downstream of it was
    /// observed.
    UnmodelledSyscall,
    /// **Case B.** The run ended at a construct the lifted module does not
    /// carry: a call past the function cap, an opcode the lift refuses - the
    /// lift's emitted `unreachable`. Raising the lift's call cap (or lifting
    /// the gap) is the next move; the stop is reporting the module's extent,
    /// not the program's behavior.
    LiftCap,
    /// **Case C.** A digest or address was derived from attacker-controlled
    /// bytes. The symbolic layer has no theory for it, so the value is sealed
    /// to the real implementation's answer for THIS input: branches on it are
    /// constants to the solver. A re-run with different bytes changes it, but
    /// only under some other decision's flip.
    SealedDerivation,
    /// **Case D.** The walk used a symbolic address the model cannot answer
    /// for: the concrete execution landed on a cell outside the bounded
    /// address window (the seed's declared regions plus the cells the walk
    /// touched, capped per site). The run stopped AT the access, so nothing
    /// past it was observed - and unlike a solver bound, more time would not
    /// change the answer: the model is bounded by construction. Widening the
    /// window (a seed that declares the region, or a wider address window)
    /// is the next move.
    UnmodelledAddress,
    /// The solver hit a configured bound (clauses, budget) before a verdict.
    /// Not a negative answer - the absence of one.
    SolverGaveUp,
    /// The engines' own replay limits: walk/replay divergences, walk step
    /// budgets, register-model drift, host-model allocation failure. Says
    /// nothing about the program.
    EngineLimit,
    /// The engine's reference run trapped: the program's own behavior as the
    /// model defines it (an OOB access, a failed derivation, heap exhaustion),
    /// not a model limit. The note states the trap; whether the symbolic walk
    /// replayed the path is a separate note, never assumed. No claim is made
    /// about what the program would have done past it.
    GuestTrap,
    /// No adapter pattern matched. Preserved verbatim, counted, and stated as
    /// unclassified - a gap the diagnosis cannot yet name is reported as
    /// such, never dropped and never guessed.
    Unclassified,
}

impl BlockerClass {
    /// The one-character code used in the rendered diagnosis (`A`/`B`/`C` for
    /// the design's cases; short names for the rest).
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            BlockerClass::UnmodelledSyscall => "A",
            BlockerClass::LiftCap => "B",
            BlockerClass::SealedDerivation => "C",
            BlockerClass::UnmodelledAddress => "D",
            BlockerClass::SolverGaveUp => "solver",
            BlockerClass::EngineLimit => "engine",
            BlockerClass::GuestTrap => "trap",
            BlockerClass::Unclassified => "?",
        }
    }
}

/// How much a claim is worth. Assigned by the fixed table in
/// [`diagnose`] and its certificate step - never by the claim's tone, and never raised
/// because a result would be more useful at a higher level.
// No `Ord`: trust is not a total order that can be sorted or `min`-ed. A
// claim is never stronger than its weakest load-bearing evidence, but the
// levels are kinds of evidence, not a numeric scale; use the table in
// [`diagnose`], not a comparison.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Trust {
    /// A machine-checked fact about a run that happened (a verified flip, a
    /// reproduced violation, a stop the report states) or a solver verdict
    /// that completed (`Unsat`). The claim's own text says what it covers.
    Exact,
    /// Reserved: reasoning over a sound over-approximation (the planned
    /// theory layer - congruence-only claims, UF/array reasoning). Nothing
    /// in M1 earns this level, and nothing may claim it until the reasoning
    /// that would justify it exists.
    SoundOverApprox,
    /// True of the concrete run, conditional on its input: a sealed value, a
    /// derivation whose answer holds for THIS execution's bytes.
    Conditional,
    /// Observed engine behavior, not a proof: where the host model or the
    /// lift answered, downstream behavior is model-determined.
    Empirical,
    /// No verdict: the solver hit a bound, no flip was posed, or the report
    /// states no reason for the stop. The question is open.
    Unknown,
}

/// One gap, classified. The raw text is preserved verbatim: it is the
/// evidence for the certificate, and the classifier never rewrites it.
#[derive(Clone, Debug)]
pub struct ClassifiedGap {
    /// What class the adapter matched (see [`classify_gap`]).
    pub class: BlockerClass,
    /// The site the gap names, when its text carries one (`at 0x…`).
    pub site: Option<u64>,
    /// The engine's own gap text, unchanged.
    pub text: String,
}

/// One row of the flip ledger: what the engine attempted and arrived at.
#[derive(Clone, Debug)]
pub struct LedgerRow {
    /// The branch site's address.
    pub at: u64,
    /// What the attempt arrived at.
    pub outcome: FlipOutcome,
    /// The attempted input, as the engine recorded it.
    pub input: Vec<(String, u64)>,
}

/// One row of the property ledger: an invariant posed as a solve
/// target on a walked path, and what the engine's re-run made of it.
#[derive(Clone, Debug)]
pub struct PropertyRow {
    /// The invariant as written.
    pub label: String,
    /// What the query arrived at.
    pub outcome: PropertyOutcome,
    /// The observed and required operands, when a re-run confirmed a
    /// violation. This is the machine-checked witness, not prose.
    pub violation: Option<(u64, u64)>,
    /// The model the engine re-ran, when the outcome has one.
    pub input: Vec<(String, u64)>,
}

/// Why the search stopped - derived from the report's `exhausted` flag and the
/// budgets the session ran under.
///
/// `Exhausted` wins when both hold: emptying the frontier is the only
/// terminal claim, and a budget that was also hit does not weaken it.
///
/// The variant is a fact about the report. Whether it **licenses a coverage
/// claim** is a second question, answered by
/// [`Diagnosis::coverage_licensed`]: the adequacy theorem requires every
/// attempt in the ledger to have reached an exact outcome.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Stop {
    /// The report marks the search as complete: the frontier emptied with no
    /// attempt skipped by a budget and every discovered path walked. This
    /// licenses "no other input reaches anything new within the modelled
    /// surface" only when every decision the solver saw ended at an exact
    /// outcome; a ledger with an unresolved attempt leaves coverage open.
    Exhausted,
    /// The run budget was reached with the frontier not empty: decisions
    /// remain unposed. (The engine counts a run before it starts, so `runs`
    /// reaches the budget exactly; a sequential round never starts an attempt
    /// it cannot afford.)
    BudgetRuns,
    /// The verified-flip budget was reached. Coverage past the reached sinks
    /// is open.
    BudgetFlips,
    /// Stopped without the frontier emptying and without either budget being
    /// reached. The report does not mark exhaustion; any reason it recorded is
    /// in its gap ledger, classified like every other note. Coverage is open,
    /// and this variant exists so the reader is told that rather than left to
    /// assume silence meant exhaustion.
    Undetermined,
}

impl Stop {
    /// A one-line statement of what the stop means - and what it does not.
    #[must_use]
    pub fn claim(self) -> &'static str {
        match self {
            Stop::Exhausted => {
                "the report marks the search complete: the frontier emptied with no attempt \
                 skipped by a budget and every discovered path walked (whether that licenses a \
                 coverage claim depends on the flip ledger's outcomes - see the stop certificate)"
            }
            Stop::BudgetRuns => {
                "the search stopped at the run budget and the frontier did NOT empty: decisions \
                 remain unposed, so this is incomplete coverage - not exhaustion"
            }
            Stop::BudgetFlips => {
                "the search stopped at the verified-flip budget and the frontier did NOT empty: \
                 further flips were possible, so this is incomplete coverage - not exhaustion"
            }
            Stop::Undetermined => {
                "the search stopped without the frontier emptying and without a budget being \
                 reached: the report does not mark exhaustion, any limit it recorded is in the \
                 gap ledger, and coverage is open - treat as incomplete, not exhausted"
            }
        }
    }
}

/// One semantic relevance certificate: a claim, its trust, and the evidence
/// the engine already recorded for it.
#[derive(Clone, Debug)]
pub struct Certificate {
    /// The site the claim is about, when known.
    pub site: Option<u64>,
    /// The blocker class, when the certificate is about a gap.
    pub class: Option<BlockerClass>,
    /// How much the claim is worth (see [`Trust`]).
    pub trust: Trust,
    /// What is claimed, in one sentence.
    pub claim: String,
    /// The engine's own record that backs the claim.
    pub evidence: String,
}

// endregion: --- taxonomy

// region:    --- adapter

/// The site a gap text names: `… at 0x…` (most producers) or `… invoke 0x…`
/// (an alternate producer spelling). `None` when the text carries no site -
/// the certificate then states the fact without inventing one.
#[must_use]
pub fn site_in(text: &str) -> Option<u64> {
    for needle in [" at 0x", "invoke 0x"] {
        if let Some((.., rest)) = text.split_once(needle) {
            let hex: String = rest.chars().take_while(char::is_ascii_hexdigit).collect();
            if let Ok(v) = u64::from_str_radix(&hex, 16) {
                return Some(v);
            }
        }
    }
    None
}

/// How a [`Rule`] matches a gap text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Matcher {
    /// The text contains this substring.
    Contains(&'static str),
    /// The text starts with this prefix.
    Prefix(&'static str),
    /// The text starts with `prefix` and contains `contains`.
    PrefixAndContains {
        /// The required prefix.
        prefix: &'static str,
        /// A substring required after the prefix.
        contains: &'static str,
    },
}

impl Matcher {
    /// Whether `text` matches.
    #[must_use]
    pub fn matches(self, text: &str) -> bool {
        match self {
            Matcher::Contains(needle) => text.contains(needle),
            Matcher::Prefix(prefix) => text.starts_with(prefix),
            Matcher::PrefixAndContains { prefix, contains } => {
                text.starts_with(prefix) && text.contains(contains)
            }
        }
    }
}

/// One ordered classification rule: the first matching rule wins.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rule {
    /// The class a match assigns.
    pub class: BlockerClass,
    /// How the rule recognizes a gap.
    pub matcher: Matcher,
}

impl Rule {
    /// A rule that matches when the text contains `needle`.
    #[must_use]
    pub const fn contains(class: BlockerClass, needle: &'static str) -> Self {
        Self { class, matcher: Matcher::Contains(needle) }
    }

    /// A rule that matches when the text starts with `prefix`.
    #[must_use]
    pub const fn prefix(class: BlockerClass, prefix: &'static str) -> Self {
        Self { class, matcher: Matcher::Prefix(prefix) }
    }

    /// A rule that matches when the text starts with `prefix` and contains
    /// `contains`.
    #[must_use]
    pub const fn prefix_and_contains(
        class: BlockerClass,
        prefix: &'static str,
        contains: &'static str,
    ) -> Self {
        Self { class, matcher: Matcher::PrefixAndContains { prefix, contains } }
    }
}

/// An ordered gap classifier.
///
/// [`Classifier::generic`] is the crate's default: the producer phrasings the
/// taxonomy is stated over (a seal note, a model-boundary note, a solver
/// bound, a trap, an engine-level run failure, a walker limit). A frontend
/// whose engine spells an additional note differently adds its own
/// [`Rule`]s with [`Classifier::prepend`]; that is the whole adapter, and it
/// keeps a producer's private vocabulary out of this crate.
///
/// The first matching rule wins, so the order is the precedence order and a
/// more specific pattern must come first. No match is
/// [`BlockerClass::Unclassified`] - preserved, counted and stated as such,
/// never dropped and never guessed.
#[derive(Clone, Debug)]
pub struct Classifier {
    rules: Vec<Rule>,
}

impl Default for Classifier {
    fn default() -> Self {
        Self::generic()
    }
}

impl Classifier {
    /// The generic table, in precedence order:
    ///
    /// | pattern | class |
    /// |---|---|
    /// | `run trapped:` + `unreachable` | `LiftCap` |
    /// | `hashes attacker-derived bytes` / `derives from attacker-derived bytes` | `SealedDerivation` |
    /// | `is outside the syscall model` | `UnmodelledSyscall` |
    /// | `symbolic address` | `UnmodelledAddress` |
    /// | `solver Unknown at` (prefix) | `SolverGaveUp` |
    /// | `run trapped:` (prefix) | `GuestTrap` |
    /// | `run failed:` (prefix) | `EngineLimit` |
    /// | `walk step budget` / `walk could not replay` | `EngineLimit` |
    /// | *(no match)* | `Unclassified` |
    ///
    /// The lift-cap rule comes first because it is the most specific: a lift
    /// emits `unreachable` for everything it cannot carry, while any other
    /// trap is the guest's own behavior.
    #[must_use]
    pub fn generic() -> Self {
        Self {
            rules: vec![
                Rule::prefix_and_contains(
                    BlockerClass::LiftCap,
                    "run trapped:",
                    "unreachable",
                ),
                Rule::contains(BlockerClass::SealedDerivation, "hashes attacker-derived bytes"),
                Rule::contains(
                    BlockerClass::SealedDerivation,
                    "derives from attacker-derived bytes",
                ),
                Rule::contains(BlockerClass::UnmodelledSyscall, "is outside the syscall model"),
                Rule::contains(BlockerClass::UnmodelledAddress, "symbolic address"),
                Rule::prefix(BlockerClass::SolverGaveUp, "solver Unknown at"),
                Rule::prefix(BlockerClass::GuestTrap, "run trapped:"),
                Rule::prefix(BlockerClass::EngineLimit, "run failed:"),
                Rule::contains(BlockerClass::EngineLimit, "walk step budget"),
                Rule::contains(BlockerClass::EngineLimit, "walk could not replay"),
            ],
        }
    }

    /// Add `rule` ahead of every existing rule (a frontend-specific pattern
    /// that must be tried before the generic table).
    ///
    /// # Example
    ///
    /// ```
    /// use lacuna_core::{BlockerClass, Classifier, Rule};
    ///
    /// let note = "producer: the key schedule of attacker bytes is opaque";
    /// assert_eq!(
    ///     BlockerClass::Unclassified,
    ///     Classifier::generic().classify(note).class
    /// );
    ///
    /// let classifier = Classifier::generic().prepend(Rule::contains(
    ///     BlockerClass::SealedDerivation,
    ///     "key schedule of attacker bytes is opaque",
    /// ));
    /// assert_eq!(
    ///     BlockerClass::SealedDerivation,
    ///     classifier.classify(note).class
    /// );
    /// ```
    #[must_use]
    pub fn prepend(mut self, rule: Rule) -> Self {
        self.rules.insert(0, rule);
        self
    }

    /// Classify one raw gap: the first matching rule, or `Unclassified`.
    #[must_use]
    pub fn classify(&self, text: &str) -> ClassifiedGap {
        let class = self
            .rules
            .iter()
            .find(|r| r.matcher.matches(text))
            .map_or(BlockerClass::Unclassified, |r| r.class);
        ClassifiedGap { class, site: site_in(text), text: text.to_string() }
    }
}

/// Classify one raw gap with the generic [`Classifier`].
#[must_use]
pub fn classify_gap(text: &str) -> ClassifiedGap {
    Classifier::generic().classify(text)
}

/// The claim a gap class licenses, at the trust the table assigns it. One
/// place decides both, so a class can never be rendered at two trust levels.
fn certify_gap(gap: &ClassifiedGap) -> Certificate {
    let (trust, claim) = match gap.class {
        BlockerClass::SealedDerivation => (
            Trust::Conditional,
            "a digest/address derived from attacker-derived bytes is sealed to the real \
             implementation's value for THIS input: decisions on it are constants to the solver \
             - a re-run with different bytes changes it, but only under some other decision's \
             flip",
        ),
        BlockerClass::UnmodelledSyscall => (
            Trust::Empirical,
            "the call is outside the host's syscall model and the lift trapped on it: the run \
             ended at the call, so nothing downstream of it was observed, and the model's answer \
             (where one exists) is an approximation, not the runtime's",
        ),
        BlockerClass::LiftCap => (
            Trust::Empirical,
            "the run ended at a construct the lifted module does not carry (a call past the \
             function cap, or an opcode the lift refuses): this is the MODULE's extent, not the \
             program's behavior - raising the lift's call cap or lifting the gap is the next move",
        ),
        BlockerClass::UnmodelledAddress => (
            Trust::Unknown,
            "the walk's concrete execution used a symbolic address outside the bounded window \
             (the seed's declared regions plus the cells the walk touched, capped per site): the \
             run stopped at the access, nothing past it was observed, and more solver time cannot \
             change the answer - the model's address set is bounded by construction, so widening \
             it (a seed that declares the region, or a wider window) is the next move",
        ),
        BlockerClass::SolverGaveUp => (
            Trust::Unknown,
            "the solver hit a configured bound before a verdict: no answer in either direction \
             on the decision at this site - the absence of one, not a negative one",
        ),
        BlockerClass::EngineLimit => (
            Trust::Unknown,
            "the engines' own replay limits ended this path (a divergence, a walk budget, a \
             host-model limit): this says nothing about the program, and coverage past it is \
             open",
        ),
        BlockerClass::GuestTrap => (
            Trust::Empirical,
            "the engine's reference run trapped here: this is the program's own behavior as the \
             model defines it, not a model boundary, and no claim is made about what it would \
             have done past the trap",
        ),
        BlockerClass::Unclassified => (
            Trust::Unknown,
            "a limit the adapter cannot name yet: preserved verbatim and counted - not dropped, \
             not guessed",
        ),
    };
    Certificate {
        site: gap.site,
        class: Some(gap.class),
        trust,
        claim: claim.to_string(),
        evidence: gap.text.clone(),
    }
}

/// The certificate for one ledger row: what the attempt itself arrived at.
fn certify_flip(row: &LedgerRow, input: &str) -> Certificate {
    let (trust, claim): (Trust, &str) = match row.outcome {
        FlipOutcome::Verified => (
            Trust::Exact,
            "an input reaching this decision was found and the ENGINE ran it: the site is \
             reachable, and the attempt's input is the machine-checked witness",
        ),
        FlipOutcome::ProvenUnflippable => (
            Trust::Exact,
            "no assignment to the ATTACKER surface flips this decision under its path prefix \
             with non-attacker memory as seeded (the solver completed `Unsat`): under the \
             walker's own path formula, this decision is fixed",
        ),
        FlipOutcome::SolverUnknown => (
            Trust::Unknown,
            "the solver hit a configured bound before a verdict on this flip: nothing was \
             decided here in either direction",
        ),
        FlipOutcome::NotPosed => (
            Trust::Unknown,
            "no flip was posed at this decision (the walk could not replay this path, or built \
             no query): nothing was decided here in either direction",
        ),
        FlipOutcome::RunFailed => (
            Trust::Empirical,
            "the flipped run itself failed at the engine level: the module no longer runs under \
             the flipped state - no verdict about the decision",
        ),
        FlipOutcome::Unconfirmed => (
            Trust::Empirical,
            "the flipped run completed but did not flip the decision: the walker's model and \
             the engine's run disagree somewhere before this site, so the attempt is unverified \
             and was not explored further",
        ),
        FlipOutcome::AlreadyExplored => (
            Trust::Exact,
            "the engine's run DID take the opposite side of this decision, but the resulting \
             path was already explored: the model and the run agree, and no new decision path \
             was discovered past this flip",
        ),
    };
    let detail = if input.is_empty() { "seed input".to_string() } else { input.to_string() };
    Certificate {
        site: Some(row.at),
        class: None,
        trust,
        claim: claim.to_string(),
        evidence: format!("flip attempt at {:#x} ({:?}), input: {detail}", row.at, row.outcome),
    }
}

/// The certificate for one property-query row. The same discipline as the flip
/// ledger: a completed solver verdict and a re-run witness are `Exact`; a
/// disagreement between the walker's end-state term and the engine's readback
/// is `Empirical` (observed engine behavior, no verdict about the invariant);
/// a bound or a missed run is `Unknown`.
fn certify_property(row: &PropertyRow, input: &str) -> Certificate {
    let (trust, claim): (Trust, &str) = match row.outcome {
        PropertyOutcome::Confirmed => (
            Trust::Exact,
            "the solver found an input on the walked path that violates the invariant, the \
             engine RE-RAN that model, and the concrete readback violates it: this is a \
             machine-checked witness, not a solver claim",
        ),
        PropertyOutcome::Proven => (
            Trust::Exact,
            "no assignment to the ATTACKER surface on this walked path violates the invariant \
             (the solver completed `Unsat` under the path formula): a local negative, exact \
             with respect to the walker's formula",
        ),
        PropertyOutcome::SolverUnknown => (
            Trust::Unknown,
            "the solver hit a configured bound before a verdict on this property: nothing was \
             decided in either direction",
        ),
        PropertyOutcome::NotPosed => (
            Trust::Unknown,
            "the query had no verification run (the run budget was spent, an operand has no \
             symbolic form, or the path's run trapped with no post-state to read): a model is \
             not a finding without the engine's own re-run",
        ),
        PropertyOutcome::RunFailed => (
            Trust::Empirical,
            "the verification run trapped or failed at the engine level: no verdict about the \
             invariant",
        ),
        PropertyOutcome::Unreproduced => (
            Trust::Empirical,
            "the model re-ran but the concrete readback satisfies the invariant: the walker's \
             end-state term and the engine's memory disagree on this path, so the model is \
             unverified and no violation is claimed",
        ),
    };
    let detail = if input.is_empty() {
        // NotPosed means no verification run happened at all: there is no
        // applied model to describe, and "seed input" would imply one.
        match row.outcome {
            PropertyOutcome::NotPosed => "(none)".to_string(),
            _ => "seed input".to_string(),
        }
    } else {
        input.to_string()
    };
    let mut evidence = format!(
        "property query `{}` ({:?}), input: {detail}",
        row.label, row.outcome
    );
    if let Some((observed, required)) = row.violation {
        // The witness the re-run read back, in the same string as the claim it
        // supports: a consumer never has to infer it from prose.
        evidence.push_str(&format!(
            ", violation: observed {observed:#x} vs required {required:#x}"
        ));
    }
    Certificate { site: None, class: None, trust, claim: claim.to_string(), evidence }
}

// endregion: --- adapter

// region:    --- diagnosis

/// Outcomes that leave a decision's status open. The paper's adequacy theorem
/// for `Exhausted` requires every processed decision to end at an exact
/// outcome; one of these in the ledger means the frontier emptied without
/// that condition holding.
fn unresolved_flips(outcomes: &BTreeMap<FlipOutcome, usize>) -> usize {
    outcomes
        .iter()
        .filter(|(o, _)| {
            matches!(
                o,
                FlipOutcome::Unconfirmed
                    | FlipOutcome::SolverUnknown
                    | FlipOutcome::NotPosed
                    | FlipOutcome::RunFailed
            )
        })
        .map(|(_, n)| *n)
        .sum()
}

/// The stop the report states, given the budgets it ran under.
fn stop_of(report: &Report, opts: &Opts) -> Stop {
    if report.exhausted {
        Stop::Exhausted
    } else if report.runs >= opts.max_runs {
        Stop::BudgetRuns
    } else if report.flips_verified >= opts.max_flips {
        Stop::BudgetFlips
    } else {
        Stop::Undetermined
    }
}

/// What one concolic report means: the classified gaps, the flip ledger, the
/// stop, and a certificate per claim.
#[derive(Clone, Debug)]
pub struct Diagnosis {
    /// Concrete runs the session spent, as the engine recorded them. A
    /// sequential session checks before it starts another attempt, so it
    /// never exceeds `max_runs`; the mandatory base run still happens when
    /// `max_runs` is 0, so one run is possible there.
    pub runs: usize,
    /// Verified flips.
    pub flips_verified: usize,
    /// The base run's return value, when it returned.
    pub result: Option<i64>,
    /// Why the search stopped.
    pub stop: Stop,
    /// Every flip attempt, in decision order.
    pub ledger: Vec<LedgerRow>,
    /// Attempt counts per outcome.
    pub outcomes: BTreeMap<FlipOutcome, usize>,
    /// Every property query, in the order the engine posed them.
    pub properties: Vec<PropertyRow>,
    /// Query counts per property outcome.
    pub property_outcomes: BTreeMap<PropertyOutcome, usize>,
    /// Every gap, classified.
    pub gaps: Vec<ClassifiedGap>,
    /// Gap counts per class.
    pub classes: BTreeMap<BlockerClass, usize>,
    /// One per claim, in a fixed order: the stop, then every gap, then every
    /// flip-ledger row, then every property-query row.
    pub certificates: Vec<Certificate>,
}

/// Diagnose one concolic report under the options it ran with, using the
/// generic [`Classifier`].
///
/// `opts` is needed (not derivable from the report) because a stop is only
/// meaningful against the budgets it stopped within: `runs` alone cannot say
/// whether the search was cut short.
///
/// # Example
///
/// ```
/// use concolic_core::{FlipOutcome, FlipRec, Opts, Report};
/// use lacuna_core::{diagnose, Stop, Trust};
///
/// let report = Report {
///     runs: 2,
///     flips_verified: 1,
///     flips: vec![FlipRec {
///         at: 0x401010,
///         input: vec![("in!x".to_string(), 7)],
///         verified: true,
///         outcome: FlipOutcome::Verified,
///     }],
///     exhausted: true,
///     ..Report::default()
/// };
///
/// let diag = diagnose(&report, &Opts::default());
/// assert_eq!(Stop::Exhausted, diag.stop);
/// // Certificate 0 is the stop; certificate 1 is the verified flip.
/// assert_eq!(Trust::Exact, diag.certificates[0].trust);
/// assert_eq!(Trust::Exact, diag.certificates[1].trust);
/// ```
#[must_use]
pub fn diagnose(report: &Report, opts: &Opts) -> Diagnosis {
    diagnose_with(report, opts, &Classifier::generic())
}

/// Diagnose one concolic report with a frontend's own classifier.
///
/// This is the entry point for an engine whose gap vocabulary extends the
/// generic table: build a [`Classifier`] with the producer's rules prepended,
/// then pass it here. Everything else is identical to [`diagnose`].
#[must_use]
pub fn diagnose_with(report: &Report, opts: &Opts, classifier: &Classifier) -> Diagnosis {
    let stop = stop_of(report, opts);

    let gaps: Vec<ClassifiedGap> = report.gaps.iter().map(|g| classifier.classify(g)).collect();
    let mut classes: BTreeMap<BlockerClass, usize> = BTreeMap::new();
    for g in &gaps {
        *classes.entry(g.class).or_insert(0) += 1;
    }

    let mut ledger: Vec<LedgerRow> = Vec::with_capacity(report.flips.len());
    let mut outcomes: BTreeMap<FlipOutcome, usize> = BTreeMap::new();
    for f in &report.flips {
        *outcomes.entry(f.outcome).or_insert(0) += 1;
        ledger.push(LedgerRow { at: f.at, outcome: f.outcome, input: f.input.clone() });
    }

    let mut properties: Vec<PropertyRow> = Vec::with_capacity(report.properties.len());
    let mut property_outcomes: BTreeMap<PropertyOutcome, usize> = BTreeMap::new();
    for p in &report.properties {
        *property_outcomes.entry(p.outcome).or_insert(0) += 1;
        properties.push(PropertyRow {
            label: p.label.clone(),
            outcome: p.outcome,
            violation: p.violation,
            input: p.input.clone(),
        });
    }

    // Certificates, deterministic: the stop first (it frames everything
    // else), then the gaps in the report's order, then the ledger rows, then
    // the property queries. The property rows are appended last so the
    // existing certificate positions (and the tests that index them) do not
    // move when assertions are present.
    let mut certificates =
        Vec::with_capacity(1 + gaps.len() + ledger.len() + properties.len());
    let unresolved = unresolved_flips(&outcomes);
    let (stop_trust, stop_claim) = match stop {
        // A stated budget stop is a machine-checked fact about the run; the
        // claim text carries what it does and does not cover.
        Stop::BudgetRuns | Stop::BudgetFlips => (Trust::Exact, stop.claim().to_string()),
        Stop::Undetermined => (Trust::Unknown, stop.claim().to_string()),
        // `exhausted` is set when the worklist empties. Whether that licenses
        // a coverage claim is a separate question: the adequacy theorem needs
        // every attempt to have reached an exact outcome. If any attempt is
        // unresolved, the stop is still a fact about the report, but the
        // coverage claim is not licensed and the certificate says so.
        // Only here, with every attempt exact, does the universal claim hold.
        Stop::Exhausted if unresolved == 0 => (
            Trust::Exact,
            "the flip frontier emptied inside the budgets: every decision the solver saw was \
             flipped or proven unflippable under its prefix - within the modelled surface, no \
             other input reaches anything new (sealed constants and unmodelled answers were \
             never variable)"
                .to_string(),
        ),
        Stop::Exhausted => (
            Trust::Unknown,
            format!(
                "the report marks the flip frontier as emptied, but {unresolved} attempt(s) \
                 did not reach an exact outcome (Unconfirmed, SolverUnknown, NotPosed or \
                 RunFailed): the adequacy condition for exhaustion is NOT met, so this is not \
                 a coverage claim and coverage remains open"
            ),
        ),
    };
    certificates.push(Certificate {
        site: None,
        class: None,
        trust: stop_trust,
        claim: stop_claim,
        evidence: format!(
            "runs={} flips_verified={} result={} exhausted={} unresolved_attempts={unresolved}",
            report.runs,
            report.flips_verified,
            match report.result {
                Some(r) => format!("{r}"),
                None => "trapped".to_string(),
            },
            report.exhausted
        ),
    });
    certificates.extend(gaps.iter().map(certify_gap));
    certificates.extend(ledger.iter().map(|row| certify_flip(row, &fmt_input(&row.input))));
    certificates
        .extend(properties.iter().map(|row| certify_property(row, &fmt_input(&row.input))));

    Diagnosis {
        runs: report.runs,
        flips_verified: report.flips_verified,
        result: report.result,
        stop,
        ledger,
        outcomes,
        properties,
        property_outcomes,
        gaps,
        classes,
        certificates,
    }
}

// endregion: --- diagnosis

// region:    --- rendering

/// `x=0x1337, mem+96=0x5` - the input bindings, one deterministic string.
fn fmt_input(input: &[(String, u64)]) -> String {
    input.iter().map(|(n, v)| format!("{n}={v:#x}")).collect::<Vec<_>>().join(", ")
}

impl std::fmt::Display for Diagnosis {
    /// The deterministic text form: counters, then every certificate with its
    /// trust. Same report in, same bytes out.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LACUNA diagnosis (milestone 1: diagnosis without repair)\n")?;
        writeln!(
            f,
            "  runs {}  flips-verified {}  result {}",
            self.runs,
            self.flips_verified,
            match self.result {
                Some(r) => format!("{r} ({r:#x})"),
                None => "trapped before returning".to_string(),
            }
        )?;
        writeln!(f, "  stop: {:?}", self.stop)?;
        writeln!(f, "  outcomes ({})", self.outcomes.len())?;
        for (o, n) in &self.outcomes {
            writeln!(f, "    {o:?}: {n}")?;
        }
        if !self.property_outcomes.is_empty() {
            writeln!(f, "  property queries ({})", self.properties.len())?;
            for (o, n) in &self.property_outcomes {
                writeln!(f, "    {o:?}: {n}")?;
            }
        }
        writeln!(f, "  blockers ({})", self.classes.len())?;
        for (c, n) in &self.classes {
            writeln!(f, "    [{}] {c:?}: {n}", c.code())?;
        }
        writeln!(f, "  certificates ({})", self.certificates.len())?;
        for (i, c) in self.certificates.iter().enumerate() {
            let site = match c.site {
                Some(a) => format!(" site {a:#x}"),
                None => String::new(),
            };
            let class = match c.class {
                Some(cl) => format!(" class [{}]", cl.code()),
                None => String::new(),
            };
            writeln!(f, "    [{}] trust {:?}{class}{site}", i + 1, c.trust)?;
            writeln!(f, "        claim: {}", c.claim)?;
            writeln!(f, "        evidence: {}", c.evidence)?;
        }
        Ok(())
    }
}

impl Diagnosis {
    /// [`Display`](std::fmt::Display) as a `String`.
    ///
    /// Report-controlled strings (gap notes, labels, input names) are
    /// interpolated verbatim, including embedded newlines. This is a golden
    /// artifact for reports from a trusted engine, not a sanitizer for
    /// untrusted ones.
    #[must_use]
    pub fn render(&self) -> String {
        self.to_string()
    }

    /// Whether this diagnosis licenses a coverage claim.
    ///
    /// True only for an `Exhausted` stop whose flip ledger contains no
    /// unresolved attempt: the frontier emptied **and** every decision the
    /// solver saw reached an exact outcome (`Verified`, `ProvenUnflippable`
    /// or `AlreadyExplored`). A budget stop never licenses coverage, and
    /// `Undetermined` states no reason at all.
    ///
    /// This is the adequacy condition as a function, so a consumer does not
    /// have to re-derive it from the ledger or trust the stop certificate's
    /// tone.
    ///
    /// **Scope.** This is a predicate over the **flip** ledger - decision
    /// coverage. The property ledger is separate: a query that never reached
    /// a verdict (`SolverUnknown`, `NotPosed`, `RunFailed`) leaves the
    /// invariant question open, and this method does not speak for it.
    ///
    /// It reads each attempt's structured outcome; under the engine contract
    /// `FlipRec::verified` is true exactly for `Verified`, and a hand-built
    /// report must keep the two consistent.
    #[must_use]
    pub fn coverage_licensed(&self) -> bool {
        self.stop == Stop::Exhausted && unresolved_flips(&self.outcomes) == 0
    }
}

// endregion: --- rendering
