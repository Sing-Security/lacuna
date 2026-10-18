//! Using a diagnosis as a machine-readable coverage gate.
//!
//! Run with:
//!
//! ```text
//! cargo run -p lacuna-core --example 05_coverage_gate
//! ```
//!
//! The point of a trust-carrying diagnosis is that a downstream consumer can
//! refuse to overclaim without re-reading prose. `Exhausted` is necessary but
//! not sufficient for a coverage statement: it scopes itself to "every
//! decision the solver saw", so a model-boundary gap (an unmodelled call, a
//! lift cap, an address outside the modelled window) still limits what the
//! run establishes about the program.
//!
//! This example is deliberately conservative. It never promotes a budget stop
//! to coverage, and it never reads `Unclassified` as anything but unclassified.

use concolic_core::{FlipOutcome, FlipRec, Opts, PropertyOutcome, PropertyRec, Report};
use lacuna_core::{BlockerClass, Diagnosis, Stop, Trust, diagnose};

/// What a consumer may say about coverage, derived only from public fields.
fn coverage_verdict(diag: &Diagnosis) -> String {
    // `coverage_licensed` is the adequacy condition: `Exhausted` *and* every
    // flip attempt reached an exact outcome. The stop alone is not enough.
    if !diag.coverage_licensed() {
        if diag.stop == Stop::Exhausted {
            let unresolved: usize = diag
                .outcomes
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
                .sum();
            return format!(
                "incomplete: the frontier emptied, but {unresolved} attempt(s) never \
                 reached an exact outcome: exhaustion does not license coverage"
            );
        }
        // A stated budget stop is exact about the STOP, not about coverage.
        return format!("incomplete: {}", diag.stop.claim());
    }
    // `coverage_licensed` is a predicate over the flip ledger (decision
    // coverage). Property queries are a separate ledger: a query that never
    // reached a verdict leaves the invariant question open, and a gate that
    // reports a clean surface must not fold that into silence.
    let properties_open: usize = diag
        .property_outcomes
        .iter()
        .filter(|(o, _)| {
            matches!(
                o,
                PropertyOutcome::SolverUnknown
                    | PropertyOutcome::NotPosed
                    | PropertyOutcome::RunFailed
            )
        })
        .map(|(_, n)| *n)
        .sum();
    let property_note = if properties_open == 0 {
        String::new()
    } else {
        format!(
            "; {properties_open} property query(ies) never reached a verdict, so the invariant \
             question stays open"
        )
    };
    let model_boundaries: Vec<&str> = diag
        .gaps
        .iter()
        .filter(|g| {
            matches!(
                g.class,
                BlockerClass::UnmodelledSyscall
                    | BlockerClass::LiftCap
                    | BlockerClass::UnmodelledAddress
            )
        })
        .map(|g| g.class.code())
        .collect();
    let unclassified = diag
        .gaps
        .iter()
        .filter(|g| g.class == BlockerClass::Unclassified)
        .count();
    if unclassified > 0 {
        // An unclassified gap might be a model boundary. The honest verdict
        // says that the gate cannot tell, rather than assuming it is not.
        return format!(
            "exhausted within the modelled surface, but {unclassified} gap(s) remain \
             unclassified: a model boundary cannot be ruled out{property_note}"
        );
    }
    if model_boundaries.is_empty() {
        format!(
            "exhausted within the modelled surface; no model-boundary gap was recorded\
             {property_note}"
        )
    } else {
        format!(
            "exhausted within the modelled surface, but the model itself ends at: {}\
             {property_note}",
            model_boundaries.join(", ")
        )
    }
}

fn main() {
    let base = Report {
        result: Some(0),
        runs: 9,
        flips_verified: 1,
        flips: vec![
            FlipRec {
                at: 0x401010,
                input: vec![("in!x".to_string(), 1)],
                verified: true,
                outcome: FlipOutcome::Verified,
            },
            FlipRec {
                at: 0x401020,
                input: Vec::new(),
                verified: false,
                outcome: FlipOutcome::ProvenUnflippable,
            },
        ],
        ..Report::default()
    };
    let opts = Opts::default();

    // 1. A clean exhaustion: the strongest statement the engine can license.
    let clean = Report { exhausted: true, ..base.clone() };
    let diag = diagnose(&clean, &opts);
    assert_eq!(Stop::Exhausted, diag.stop);
    assert_eq!(Trust::Exact, diag.certificates[0].trust);
    println!("clean exhaustion:\n  {}\n", coverage_verdict(&diag));

    // 2. Exhaustion with an unmodelled call: still exact about the frontier,
    //    but the model has a boundary and the gate says where.
    let bounded = Report {
        exhausted: true,
        gaps: vec!["a call at 0x4010f0 is outside the syscall model".to_string()],
        ..base.clone()
    };
    let diag = diagnose(&bounded, &opts);
    assert_eq!(Stop::Exhausted, diag.stop);
    println!("exhaustion with a model boundary:\n  {}\n", coverage_verdict(&diag));

    // 3. A budget stop: never promoted, regardless of the counters.
    let budget = Report { runs: opts.max_runs, ..base.clone() };
    let diag = diagnose(&budget, &opts);
    assert_eq!(Stop::BudgetRuns, diag.stop);
    println!("budget stop:\n  {}\n", coverage_verdict(&diag));

    // 4. An unknown note is reported as unknown, not guessed into a class.
    let unknown = Report {
        exhausted: true,
        gaps: vec!["a note this adapter does not know".to_string()],
        ..base.clone()
    };
    let diag = diagnose(&unknown, &opts);
    assert_eq!(Some(&1), diag.classes.get(&BlockerClass::Unclassified));
    println!("unclassified note:\n  {}\n", coverage_verdict(&diag));

    // 5. The frontier emptied, but one attempt never reached an exact
    //    outcome. The stop still says `Exhausted`; the adequacy condition
    //    does not hold, and the gate must not promote the stop to coverage.
    let unresolved = Report {
        exhausted: true,
        flips: vec![
            FlipRec {
                at: 0x4010a0,
                input: vec![("in!x".to_string(), 1)],
                verified: false,
                outcome: FlipOutcome::Unconfirmed,
            },
            FlipRec {
                at: 0x4010b0,
                input: Vec::new(),
                verified: false,
                outcome: FlipOutcome::ProvenUnflippable,
            },
        ],
        ..base.clone()
    };
    let diag = diagnose(&unresolved, &opts);
    assert_eq!(Stop::Exhausted, diag.stop);
    assert!(!diag.coverage_licensed());
    assert_eq!(Trust::Unknown, diag.certificates[0].trust);
    println!("exhausted with an unresolved attempt:\n  {}\n", coverage_verdict(&diag));

    // 6. The flip ledger licenses decision coverage, but a property query
    //    never reached a verdict. The gate must keep the invariant question
    //    open rather than report a clean surface.
    let property_open = Report {
        exhausted: true,
        properties: vec![PropertyRec {
            label: "out <= 0x10".to_string(),
            outcome: PropertyOutcome::NotPosed,
            violation: None,
            input: Vec::new(),
        }],
        ..base
    };
    let diag = diagnose(&property_open, &opts);
    assert!(diag.coverage_licensed());
    let verdict = coverage_verdict(&diag);
    assert!(verdict.contains("invariant question stays open"), "{verdict}");
    println!("decision coverage with an open property:\n  {verdict}\n");

    // Certificate order is a stable contract: stop, gaps, flips, properties.
    // Indexing into it is safe as long as the report shape is unchanged.
    let diag = diagnose(&unknown, &opts);
    assert_eq!(1 + 1 + 2, diag.certificates.len());
    assert!(diag.certificates[0].class.is_none());
    assert!(matches!(diag.certificates[1].class, Some(BlockerClass::Unclassified)));
    println!("certificate order verified (stop, gap, flip, flip).");
}
