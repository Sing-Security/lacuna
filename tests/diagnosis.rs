//! LACUNA M1's proof obligations, stated over the neutral report contract:
//!
//! 1. The generic classifier recognizes the generic producer phrasings and
//!    reports any unknown note as `Unclassified` rather than guessing; a
//!    frontend can prepend its own rule without changing the crate.
//! 2. The stop table says what each stop does and does NOT mean, with
//!    `Exhausted` winning over reasons that merely co-occur with it.
//! 3. Trust is assigned by the table, not by the claim's tone.
//! 4. The property-query algebra distinguishes a re-run witness, a completed
//!    `Unsat`, an unreproduced model and a query that was never posed.

use concolic_core::{FlipOutcome, FlipRec, Opts, PropertyOutcome, PropertyRec, Report};
use lacuna_core::{
    BlockerClass, Classifier, Rule, Stop, Trust, classify_gap, diagnose, diagnose_with,
};

fn flip(at: u64, outcome: FlipOutcome) -> FlipRec {
    FlipRec {
        at,
        input: vec![("in!x".into(), 7)],
        verified: outcome == FlipOutcome::Verified,
        outcome,
    }
}

#[test]
fn test_the_generic_classifier_covers_the_taxonomy_and_never_guesses() {
    let cases: &[(&str, BlockerClass)] = &[
        (
            "producer: a call at 0x9058 hashes attacker-derived bytes - the symbolic layer \
             has no hash theory, so the digest is sealed to the real implementation's value for \
             THIS input",
            BlockerClass::SealedDerivation,
        ),
        (
            "producer: a derivation at 0x9178 derives from attacker-derived bytes - the \
             symbolic layer has no derive theory, so the address is sealed",
            BlockerClass::SealedDerivation,
        ),
        (
            "producer: a call at 0x9abc is outside the syscall model, so the lift trapped on \
             it - the run ends at the call",
            BlockerClass::UnmodelledSyscall,
        ),
        ("solver Unknown at 0x9068", BlockerClass::SolverGaveUp),
        (
            "run trapped: unreachable instruction executed (the lift lowers what it cannot \
             carry to unreachable)",
            BlockerClass::LiftCap,
        ),
        (
            "run trapped: out of bounds memory access",
            BlockerClass::GuestTrap,
        ),
        (
            "run failed: the reference engine reported a failure",
            BlockerClass::EngineLimit,
        ),
        (
            "producer: walk could not replay the concrete path",
            BlockerClass::EngineLimit,
        ),
        (
            "producer: symbolic address 0x101100 at 0x9050 is outside the modelled window",
            BlockerClass::UnmodelledAddress,
        ),
        ("producer: some future note shape", BlockerClass::Unclassified),
    ];
    for (text, want) in cases {
        assert_eq!(*want, classify_gap(text).class, "classified {text:?}");
    }

    // Precedence: a lift-emitted trap is more specific than a generic trap.
    assert_eq!(
        BlockerClass::LiftCap,
        classify_gap("run trapped: unreachable instruction executed").class
    );
    assert_eq!(
        BlockerClass::GuestTrap,
        classify_gap("run trapped: integer divide by zero").class
    );

    // Site extraction: the `at 0x…` producer spelling.
    assert_eq!(Some(0x9058), classify_gap(cases[0].0).site);
    assert_eq!(Some(0x9068), classify_gap(cases[3].0).site);
    assert_eq!(
        Some(0x9050),
        classify_gap(cases[8].0).site,
        "the site is the instruction, not the cell named earlier in the note"
    );
    // A text with no site stays without one - never invented.
    assert_eq!(None, classify_gap("producer: walk step budget").site);
}

#[test]
fn test_a_frontend_can_prepend_its_own_producer_rule() {
    // A frontend's private note, unknown to the generic table.
    let text = "producer: the host allocator ran past its declared end";
    assert_eq!(BlockerClass::Unclassified, classify_gap(text).class);

    let classifier = Classifier::generic().prepend(Rule::contains(
        BlockerClass::EngineLimit,
        "host allocator ran past",
    ));
    assert_eq!(BlockerClass::EngineLimit, classifier.classify(text).class);

    // Prepend really is precedence: the frontend's rule wins over a generic
    // rule that would otherwise match the same text.
    let specific = Classifier::generic().prepend(Rule::prefix(
        BlockerClass::GuestTrap,
        "run trapped:",
    ));
    assert_eq!(
        BlockerClass::GuestTrap,
        specific.classify("run trapped: unreachable instruction").class
    );

    // And the generic table is unchanged for everyone else.
    assert_eq!(
        BlockerClass::LiftCap,
        classify_gap("run trapped: unreachable instruction").class
    );
}

#[test]
fn test_the_stop_table_says_what_each_stop_does_and_does_not_mean() {
    let opts = Opts { max_runs: 64, max_flips: 32 };
    let at = |runs: usize, flips: usize, exhausted: bool| {
        let r = Report { runs, flips_verified: flips, exhausted, ..Report::default() };
        diagnose(&r, &opts).stop
    };
    assert_eq!(Stop::Exhausted, at(0, 0, true));
    // Exhaustion wins over a budget that co-occurred.
    assert_eq!(Stop::Exhausted, at(200, 0, true));
    assert_eq!(Stop::BudgetRuns, at(64, 0, false));
    assert_eq!(Stop::BudgetFlips, at(10, 32, false));
    assert_eq!(Stop::Undetermined, at(10, 0, false));

    // The claims are the honesty contract: a budget stop must SAY its
    // coverage is incomplete, and exhaustion's public one-liner must not
    // assert the universal that only the ledger-aware certificate can earn.
    assert!(Stop::BudgetRuns.claim().contains("NOT empty"));
    assert!(Stop::Undetermined.claim().contains("not exhausted"));
    assert!(Stop::Exhausted.claim().contains("frontier emptied"));
    assert!(Stop::Exhausted.claim().contains("flip ledger"));
}

#[test]
fn test_exhaustion_licenses_coverage_only_when_every_attempt_is_exact() {
    // The frontier emptied, but one attempt never reached an exact outcome:
    // the stop is still `Exhausted`, yet the adequacy condition for a coverage
    // claim is not met. The certificate must say so and must not be `Exact`.
    let unresolved = Report {
        runs: 3,
        flips_verified: 1,
        exhausted: true,
        flips: vec![
            flip(0x9068, FlipOutcome::Verified),
            flip(0x9070, FlipOutcome::Unconfirmed),
        ],
        ..Report::default()
    };
    let d = diagnose(&unresolved, &Opts::default());
    assert_eq!(Stop::Exhausted, d.stop);
    assert!(!d.coverage_licensed());
    assert_eq!(Trust::Unknown, d.certificates[0].trust);
    assert!(d.certificates[0].claim.contains("not a coverage claim"));
    // The universal is not stated when an attempt never resolved.
    assert!(!d.certificates[0].claim.contains("every decision the solver saw"));

    // All-exact outcomes: the same stop now licenses the scoped claim.
    let exact = Report {
        exhausted: true,
        flips: vec![
            flip(0x9068, FlipOutcome::Verified),
            flip(0x9070, FlipOutcome::ProvenUnflippable),
            flip(0x9078, FlipOutcome::AlreadyExplored),
        ],
        ..Report::default()
    };
    let d = diagnose(&exact, &Opts::default());
    assert!(d.coverage_licensed());
    assert_eq!(Trust::Exact, d.certificates[0].trust);
    assert!(d.certificates[0].claim.contains("every decision the solver saw"));

    // A budget stop never licenses coverage, even with an all-exact ledger.
    let budget = Report { runs: 64, exhausted: false, ..exact.clone() };
    let d = diagnose(&budget, &Opts { max_runs: 64, max_flips: 32 });
    assert_eq!(Stop::BudgetRuns, d.stop);
    assert!(!d.coverage_licensed());
}

#[test]
fn test_certificates_carry_the_tables_trust_and_render_deterministically() {
    let report = Report {
        result: Some(101),
        runs: 141,
        flips_verified: 1,
        sinks: Vec::new(),
        properties: Vec::new(),
        flips: vec![
            flip(0x9068, FlipOutcome::Verified),
            flip(0x9070, FlipOutcome::ProvenUnflippable),
            flip(0x9078, FlipOutcome::SolverUnknown),
            flip(0x9080, FlipOutcome::NotPosed),
            flip(0x9088, FlipOutcome::AlreadyExplored),
        ],
        gaps: vec![
            "producer: at 0x9058 a digest hashes attacker-derived bytes - sealed".into(),
            "producer: some future note shape".into(),
        ],
        exhausted: false,
    };
    let d = diagnose(&report, &Opts { max_runs: 64, max_flips: 32 });

    assert_eq!(Stop::BudgetRuns, d.stop);
    assert_eq!(5, d.ledger.len());
    assert_eq!(Some(&1), d.outcomes.get(&FlipOutcome::Verified));
    assert_eq!(Some(&1), d.outcomes.get(&FlipOutcome::SolverUnknown));
    assert_eq!(Some(&1), d.classes.get(&BlockerClass::SealedDerivation));
    assert_eq!(Some(&1), d.classes.get(&BlockerClass::Unclassified));

    // The trust table, in certificate order: stop, gaps, ledger.
    let trusts: Vec<Trust> = d.certificates.iter().map(|c| c.trust).collect();
    assert_eq!(
        vec![
            Trust::Exact,       // the stated budget stop
            Trust::Conditional, // the sealed value
            Trust::Unknown,     // the unclassified note
            Trust::Exact,       // verified flip
            Trust::Exact,       // proven unflippable
            Trust::Unknown,     // solver bound
            Trust::Unknown,     // not posed
            Trust::Exact,       // already-explored path
        ],
        trusts
    );
    assert_eq!(Some(0x9058), d.certificates[1].site);

    // Same report in, same bytes out.
    assert_eq!(d.render(), d.render());
    let text = d.render();
    for needle in [
        "LACUNA diagnosis",
        "stop: BudgetRuns",
        "[C] SealedDerivation: 1",
        "[?] Unclassified: 1",
        "trust Conditional class [C] site 0x9058",
        "trust Exact site 0x9068",
        "flip attempt at 0x9068 (Verified)",
        "flip attempt at 0x9088 (AlreadyExplored)",
    ] {
        assert!(text.contains(needle), "render missing {needle:?}:\n{text}");
    }

    // A frontend classifier is a drop-in: the diagnosis is otherwise identical.
    let d2 = diagnose_with(
        &report,
        &Opts { max_runs: 64, max_flips: 32 },
        &Classifier::generic(),
    );
    assert_eq!(d.render(), d2.render());
}

#[test]
fn test_property_queries_are_ledgered_at_the_tables_trust() {
    // The four property facts mean four different things: a re-run witness
    // and a completed UNSAT are `Exact`; an unreproduced model is an
    // observation about the engine, `Empirical`; a query that never got its
    // verification run is `Unknown`. The ledger, not the label, carries it.
    let report = Report {
        runs: 3,
        properties: vec![
            PropertyRec {
                label: "out <= 0x10".into(),
                outcome: PropertyOutcome::Confirmed,
                violation: Some((0x11, 0x10)),
                input: vec![("in!mem_0x101000".into(), 0x11)],
            },
            PropertyRec {
                label: "out == 7".into(),
                outcome: PropertyOutcome::Proven,
                violation: None,
                input: Vec::new(),
            },
            PropertyRec {
                label: "other".into(),
                outcome: PropertyOutcome::Unreproduced,
                violation: None,
                input: vec![("in!mem_0x101000".into(), 2)],
            },
            PropertyRec {
                label: "budget".into(),
                outcome: PropertyOutcome::NotPosed,
                violation: None,
                input: Vec::new(),
            },
        ],
        ..Report::default()
    };
    let d = diagnose(&report, &Opts::default());

    assert_eq!(4, d.properties.len());
    assert_eq!(Some(&1), d.property_outcomes.get(&PropertyOutcome::Confirmed));
    assert_eq!(Some(&1), d.property_outcomes.get(&PropertyOutcome::Proven));
    assert_eq!(Some(&1), d.property_outcomes.get(&PropertyOutcome::Unreproduced));
    assert_eq!(Some(&1), d.property_outcomes.get(&PropertyOutcome::NotPosed));

    // The stop certificate is first; the four property certificates follow.
    let trusts: Vec<Trust> = d.certificates.iter().skip(1).map(|c| c.trust).collect();
    assert_eq!(vec![Trust::Exact, Trust::Exact, Trust::Empirical, Trust::Unknown], trusts);

    // A confirmed violation carries its machine-checked operands: the row and
    // the certificate evidence must agree, not just the outcome label.
    assert_eq!(Some((0x11, 0x10)), d.properties[0].violation);
    assert!(d.certificates[1]
        .evidence
        .contains("violation: observed 0x11 vs required 0x10"));

    let text = d.render();
    for needle in [
        "property queries (4)",
        "Confirmed: 1",
        "property query `out <= 0x10` (Confirmed)",
        "property query `budget` (NotPosed)",
        // No verification run happened, so the evidence does not imply an
        // applied model.
        "property query `budget` (NotPosed), input: (none)",
    ] {
        assert!(text.contains(needle), "render missing {needle:?}:\n{text}");
    }
}

#[test]
fn test_fixed_claims_never_contradict_the_evidence_they_cite() {
    // An `Undetermined` stop can still carry a note that explains the stop.
    // The certificate must not claim the report omits what it just quoted,
    // and a `GuestTrap` note states what the reference run did - the walk's
    // replay is a separate note, not an assumption.
    let report = Report {
        runs: 3,
        flips_verified: 0,
        exhausted: false,
        gaps: vec![
            "run trapped: out of bounds memory access".into(),
            "walk could not replay the concrete path".into(),
        ],
        properties: vec![PropertyRec {
            label: "out == 0".into(),
            outcome: PropertyOutcome::NotPosed,
            violation: None,
            input: Vec::new(),
        }],
        ..Report::default()
    };
    let d = diagnose(&report, &Opts::default());
    assert_eq!(Stop::Undetermined, d.stop);
    assert_eq!(Trust::Unknown, d.certificates[0].trust);
    assert!(
        !d.certificates[0].claim.contains("does not state why"),
        "stop claim denies the gap it is about to quote: {}",
        d.certificates[0].claim
    );
    assert!(d.certificates[0].claim.contains("gap ledger"));

    // Certificates: stop, trap, replay limit, property.
    assert_eq!(BlockerClass::GuestTrap, d.certificates[1].class.unwrap());
    assert!(!d.certificates[1].claim.contains("both engines"));
    assert!(d.certificates[1].claim.contains("reference run trapped"));
    assert_eq!(BlockerClass::EngineLimit, d.certificates[2].class.unwrap());
    assert_eq!(Trust::Unknown, d.certificates[3].trust);
    assert!(d.certificates[3].evidence.contains("input: (none)"));
}
