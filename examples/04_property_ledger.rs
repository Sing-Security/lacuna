//! The property ledger - six outcomes, three different kinds of claim.
//!
//! Run with:
//!
//! ```text
//! cargo run -p lacuna-core --example 04_property_ledger
//! ```
//!
//! A branch flip cannot reach a straight-line violation: if the bad store has
//! no decision in front of it, there is no branch to flip (paper §12.3,
//! Theorem 4). A property query asks the end-state question instead:
//! `path AND NOT invariant`, posed on each walked path.
//!
//! The ledger keeps the outcomes apart because they are not interchangeable:
//!
//! | outcome        | what it establishes                              | trust       |
//! |----------------|--------------------------------------------------|-------------|
//! | `Confirmed`    | solver model + engine re-run reproduced it       | `Exact`     |
//! | `Proven`       | `Unsat` under this path's assumptions            | `Exact`     |
//! | `SolverUnknown`| a bound stopped the solver                       | `Unknown`   |
//! | `NotPosed`     | no verification run was spent                    | `Unknown`   |
//! | `RunFailed`    | the verification re-run trapped or failed        | `Empirical` |
//! | `Unreproduced` | the model ran but did not violate                | `Empirical` |
//!
//! `Confirmed` is a witness; `Proven` is a local negative. `Unreproduced` is
//! evidence against the *model*, not for the program (paper §12.3,
//! Proposition 6). `NotPosed` stays `Unknown` on purpose: nothing was
//! observed, so nothing is claimed (Proposition 7).

use concolic_core::{Opts, PropertyOutcome, PropertyRec, Report};
use lacuna_core::{Trust, diagnose};

fn main() {
    let report = Report {
        result: Some(0),
        runs: 6,
        flips_verified: 0,
        properties: vec![
            PropertyRec {
                label: "out <= 0x10".to_string(),
                outcome: PropertyOutcome::Confirmed,
                violation: Some((0x11, 0x10)),
                input: vec![("in!mem_0x101000".to_string(), 0x11)],
            },
            PropertyRec {
                label: "out == 7".to_string(),
                outcome: PropertyOutcome::Proven,
                violation: None,
                input: Vec::new(),
            },
            PropertyRec {
                label: "checksum == 0".to_string(),
                outcome: PropertyOutcome::SolverUnknown,
                violation: None,
                input: Vec::new(),
            },
            PropertyRec {
                label: "len < 64".to_string(),
                outcome: PropertyOutcome::NotPosed,
                violation: None,
                input: Vec::new(),
            },
            PropertyRec {
                label: "handle is valid".to_string(),
                outcome: PropertyOutcome::RunFailed,
                violation: None,
                input: vec![("in!handle".to_string(), 3)],
            },
            PropertyRec {
                label: "other <= 1".to_string(),
                outcome: PropertyOutcome::Unreproduced,
                violation: None,
                input: vec![("in!mem_0x101008".to_string(), 0)],
            },
        ],
        ..Report::default()
    };

    let diag = diagnose(&report, &Opts::default());

    // One certificate per query, after the stop certificate, in pose order.
    assert_eq!(1 + 6, diag.certificates.len());
    // A confirmed violation carries its machine-checked witness, not just a
    // label: the ledger row and the certificate's evidence agree.
    assert_eq!(Some((0x11, 0x10)), diag.properties[0].violation);
    assert!(diag.certificates[1]
        .evidence
        .contains("violation: observed 0x11 vs required 0x10"));
    // A query that was never posed has no applied model to report: its
    // evidence says so instead of implying a seed input was used.
    assert!(diag.certificates[4].evidence.contains("(NotPosed), input: (none)"));
    let trusts: Vec<Trust> = diag.certificates.iter().skip(1).map(|c| c.trust).collect();
    assert_eq!(
        vec![
            Trust::Exact,     // Confirmed: solver + re-run witness
            Trust::Exact,     // Proven: completed Unsat
            Trust::Unknown,   // SolverUnknown: no verdict
            Trust::Unknown,   // NotPosed: nothing observed
            Trust::Empirical, // RunFailed: engine behavior, no verdict
            Trust::Empirical, // Unreproduced: walker/run disagreement
        ],
        trusts
    );

    // The rows are public data for machine consumers; the rendered form is
    // for humans. Both are deterministic.
    for row in &diag.properties {
        println!("{:<20} {:?}", row.label, row.outcome);
    }
    println!();

    let text = diag.render();
    assert!(text.contains("property queries (6)"));
    assert!(text.contains("property query `out <= 0x10` (Confirmed)"));
    print!("{text}");
}
