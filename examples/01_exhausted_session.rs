//! A complete, exhausted session - the diagnosis at its strongest.
//!
//! Run with:
//!
//! ```text
//! cargo run -p lacuna-core --example 01_exhausted_session
//! ```
//!
//! The report below is what a hybrid engine hands back after it has flipped
//! every decision it could see. `exhausted: true` is the only claim that says
//! "the frontier emptied"; everything else in the diagnosis is an inventory of
//! what the frontier contained.
//!
//! Two facts are deliberately kept apart:
//!
//! - `ProvenUnflippable` is a *completed solver verdict* (`Unsat` under the
//!   path prefix). It is `Exact`.
//! - A sealed derivation is `Conditional`: the value is true of this concrete
//!   run, but only because the symbolic layer had no theory for it. It is not
//!   a proof about other inputs.
//!
//! The rendered output is a pure function of the report and the budgets
//! (paper §9, Theorem 7). Running this example twice produces the same bytes.

use concolic_core::{FlipOutcome, FlipRec, Opts, PropertyOutcome, PropertyRec, Report};
use lacuna_core::{Diagnosis, Trust, diagnose};

fn main() {
    let report = Report {
        result: Some(0),
        runs: 4,
        flips_verified: 1,
        sinks: Vec::new(),
        properties: vec![PropertyRec {
            label: "written == 0".to_string(),
            outcome: PropertyOutcome::Proven,
            violation: None,
            input: Vec::new(),
        }],
        flips: vec![
            FlipRec {
                at: 0x401010,
                input: vec![("in!x".to_string(), 0x1337)],
                verified: true,
                outcome: FlipOutcome::Verified,
            },
            FlipRec {
                at: 0x401040,
                input: Vec::new(),
                verified: false,
                outcome: FlipOutcome::ProvenUnflippable,
            },
            FlipRec {
                at: 0x401080,
                input: vec![("in!x".to_string(), 0x99)],
                // The run did flip, but onto a path already in the tree: the
                // engine's own predicate marks this `verified = false`.
                verified: false,
                outcome: FlipOutcome::AlreadyExplored,
            },
        ],
        gaps: vec![
            "a call at 0x4010f0 is outside the syscall model, so the lift trapped on it".to_string(),
            "a value at 0x401100 hashes attacker-derived bytes - sealed to this input".to_string(),
        ],
        exhausted: true,
    };
    let opts = Opts { max_runs: 64, max_flips: 32 };

    let diag: Diagnosis = diagnose(&report, &opts);

    // The stop certificate is first, then one per gap, then one per flip,
    // then one per property query (paper §8-§9).
    assert_eq!(1 + report.gaps.len() + report.flips.len() + report.properties.len(), diag.certificates.len());

    // Trust is assigned by the evidence table, never by the claim's tone:
    //   stop (stated)              -> Exact
    //   unmodelled call            -> Empirical
    //   sealed derivation          -> Conditional
    //   verified flip              -> Exact
    //   proven unflippable         -> Exact
    //   already-explored flip      -> Exact
    //   proven property            -> Exact
    let trusts: Vec<Trust> = diag.certificates.iter().map(|c| c.trust).collect();
    assert_eq!(
        vec![
            Trust::Exact,
            Trust::Empirical,
            Trust::Conditional,
            Trust::Exact,
            Trust::Exact,
            Trust::Exact,
            Trust::Exact,
        ],
        trusts
    );

    // A diagnosis is an artifact: same report in, same bytes out.
    assert_eq!(diag.render(), diag.render());

    print!("{}", diag.render());
}
