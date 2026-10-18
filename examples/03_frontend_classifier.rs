//! Extending the classifier without teaching the public crate a private
//! vocabulary.
//!
//! Run with:
//!
//! ```text
//! cargo run -p lacuna-core --example 03_frontend_classifier
//! ```
//!
//! The generic table recognizes the producer phrasings the taxonomy is stated
//! over. An engine whose notes say something else has two honest options:
//!
//! 1. reword the note to a generic phrasing, or
//! 2. prepend a [`Rule`] that maps the engine's own phrasing to a class.
//!
//! This crate takes option 2 as an extension point and keeps the private
//! vocabulary in the frontend adapter. The effect is visible in the trust
//! table: an unrecognized note is `Unknown`; a note the adapter can name as a
//! sealed derivation is `Conditional`.

use concolic_core::{Opts, Report};
use lacuna_core::{
    BlockerClass, Classifier, Rule, Trust, classify_gap, diagnose, diagnose_with,
};

fn main() {
    // A note only this (hypothetical) engine emits. The generic table cannot
    // name it, so it stays `Unclassified` — preserved, counted, never guessed.
    let note = "producer: the key schedule of attacker bytes is opaque at 0x401120";
    let generic = classify_gap(note);
    assert_eq!(BlockerClass::Unclassified, generic.class);
    assert_eq!(Some(0x401120), generic.site);
    println!("generic:     {:?} (trust Unknown)\n", generic.class);

    // The frontend adapter knows what its own note means. `prepend` is the
    // whole adapter: the rule is tried before every generic rule.
    let classifier = Classifier::generic().prepend(Rule::contains(
        BlockerClass::SealedDerivation,
        "key schedule of attacker bytes is opaque",
    ));
    let extended = classifier.classify(note);
    assert_eq!(BlockerClass::SealedDerivation, extended.class);
    println!("extended:    {:?} (trust Conditional)\n", extended.class);

    // The same report diagnosed two ways. Only the gap certificate changes;
    // every other certificate is byte-identical.
    let report = Report {
        result: Some(0),
        runs: 1,
        gaps: vec![note.to_string()],
        exhausted: true,
        ..Report::default()
    };
    let opts = Opts::default();
    let plain = diagnose(&report, &opts);
    let adapted = diagnose_with(&report, &opts, &classifier);

    let plain_trust = plain.certificates[1].trust;
    let adapted_trust = adapted.certificates[1].trust;
    assert_eq!(Trust::Unknown, plain_trust);
    assert_eq!(Trust::Conditional, adapted_trust);
    assert_eq!(1, plain.classes[&BlockerClass::Unclassified]);
    assert_eq!(1, adapted.classes[&BlockerClass::SealedDerivation]);
    assert_eq!(plain.certificates.len(), adapted.certificates.len());

    println!("generic diagnosis:");
    print!("{}", plain.render());
    println!("\nwith the frontend classifier:");
    print!("{}", adapted.render());

    // Precedence is order, not specificity-by-magic: a frontend rule that is
    // too broad shadows the generic table for everyone who uses it. Put the
    // specific pattern first.
    let too_broad = Classifier::generic().prepend(Rule::contains(
        BlockerClass::EngineLimit,
        "producer:",
    ));
    assert_eq!(
        BlockerClass::EngineLimit,
        too_broad.classify("producer: the key schedule of attacker bytes is opaque").class,
        "a broad prepended rule wins - order is the precedence contract"
    );
    println!("\nprecedence check: a broad `producer:` rule shadows the specific one.");
}
