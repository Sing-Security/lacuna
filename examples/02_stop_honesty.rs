//! The stop table — what each stop means, and what it does **not** mean.
//!
//! Run with:
//!
//! ```text
//! cargo run -p lacuna-core --example 02_stop_honesty
//! ```
//!
//! A report that ran out of budget is not an exhausted report. The difference
//! is invisible in the counters alone: `runs: 16` says nothing until you know
//! `max_runs: 16`. That is why [`diagnose`] takes the budgets the session ran
//! under, not just the report.
//!
//! The stop certificate is `Exact` in every stated case — the stop *is* a
//! machine-checked fact about the run. What varies is the scope of the claim,
//! which the variant's text states in so many words. `Undetermined` is the
//! one stop that is itself `Unknown`.

use concolic_core::{FlipOutcome, FlipRec, Opts, Report};
use lacuna_core::{Stop, Trust, diagnose};

/// A ledger of `n` verified flips, so each report's `flips_verified` counter
/// is exactly the number of `Verified` rows it carries - the contract a real
/// engine keeps.
fn verified_flips(n: u64) -> Vec<FlipRec> {
    (0..n)
        .map(|i| FlipRec {
            at: 0x401000 + i * 0x10,
            input: vec![("x".to_string(), i)],
            verified: true,
            outcome: FlipOutcome::Verified,
        })
        .collect()
}

fn stop_trust(report: &Report, opts: &Opts) -> (Stop, Trust) {
    let diag = diagnose(report, opts);
    // The stop certificate is always first.
    (diag.stop, diag.certificates[0].trust)
}

fn main() {
    // The frontier emptied inside the budgets. Exhaustion wins even when a
    // budget was also reached.
    let exhausted = Report {
        runs: 64,
        flips_verified: 12,
        flips: verified_flips(12),
        exhausted: true,
        ..Report::default()
    };
    let (stop, trust) = stop_trust(&exhausted, &Opts { max_runs: 64, max_flips: 32 });
    assert_eq!((Stop::Exhausted, Trust::Exact), (stop, trust));
    println!("Exhausted: {}\n  -> {}\n", stop.claim(), trust_word(trust));

    // The run budget was reached with decisions still unposed.
    let runs_hit = Report {
        runs: 16,
        flips_verified: 1,
        flips: verified_flips(1),
        exhausted: false,
        ..Report::default()
    };
    let (stop, trust) = stop_trust(&runs_hit, &Opts { max_runs: 16, max_flips: 32 });
    assert_eq!((Stop::BudgetRuns, Trust::Exact), (stop, trust));
    println!("BudgetRuns: {}\n  -> {}\n", stop.claim(), trust_word(trust));

    // The verified-flip budget was reached.
    let flips_hit = Report {
        runs: 8,
        flips_verified: 8,
        flips: verified_flips(8),
        exhausted: false,
        ..Report::default()
    };
    let (stop, trust) = stop_trust(&flips_hit, &Opts { max_runs: 64, max_flips: 8 });
    assert_eq!((Stop::BudgetFlips, Trust::Exact), (stop, trust));
    println!("BudgetFlips: {}\n  -> {}\n", stop.claim(), trust_word(trust));

    // No exhaustion and no budget reached: the report neither marks the
    // frontier as emptied nor names a budget, so the diagnosis must not guess.
    let unknown = Report { runs: 8, flips_verified: 0, exhausted: false, ..Report::default() };
    let (stop, trust) = stop_trust(&unknown, &Opts { max_runs: 64, max_flips: 32 });
    assert_eq!((Stop::Undetermined, Trust::Unknown), (stop, trust));
    println!("Undetermined: {}\n  -> {}\n", stop.claim(), trust_word(trust));

    // The honesty law, stated as tests: every budget stop must SAY that
    // coverage is incomplete. Silence must never read as coverage.
    assert!(Stop::BudgetRuns.claim().contains("NOT empty"));
    assert!(Stop::BudgetFlips.claim().contains("NOT empty"));
    assert!(Stop::Undetermined.claim().contains("not exhausted"));
    // Exhaustion's public one-liner is the stop fact, not the coverage claim:
    // it says the coverage question depends on the ledger. Only the stop
    // certificate, which sees the ledger, may state the universal.
    assert!(Stop::Exhausted.claim().contains("frontier emptied"));
    assert!(Stop::Exhausted.claim().contains("flip ledger"));
    println!("All four stop claims passed the honesty checks.");
}

fn trust_word(trust: Trust) -> &'static str {
    match trust {
        Trust::Exact => "the stop is a machine-checked fact",
        Trust::SoundOverApprox => "reserved: nothing in milestone 1 earns this",
        Trust::Conditional => "true of this concrete run only",
        Trust::Empirical => "observed engine behavior, not a proof",
        Trust::Unknown => "no verdict",
    }
}
