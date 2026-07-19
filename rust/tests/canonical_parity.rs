//! Canonical-JSON parity vectors. Every expected string below is the
//! LITERAL output of CPython:
//!   json.dumps(v, sort_keys=True, separators=(",", ":"))
//! and every expected float of repr(). If any of these ever fails,
//! the Rust and Python chains have forked -- fix Rust, never the
//! vector.

use pv_runtime::runtime::canonical_json::{canonical, py_float_repr};
use serde_json::json;

#[test]
fn float_repr_matches_cpython() {
    let cases: &[(f64, &str)] = &[
        (0.0, "0.0"),
        (-0.0, "-0.0"),
        (1.0, "1.0"),
        (100.0, "100.0"),
        (0.1, "0.1"),
        (0.25, "0.25"),
        (1e-4, "0.0001"),
        (1e-5, "1e-05"),          // CPython pads exponent to 2 digits
        (1e15, "1000000000000000.0"),
        (1e16, "1e+16"),          // CPython switches to sci at decpt>16
        (1e17, "1e+17"),          // serde_json would emit "1e17" -- fork
        (1.5e300, "1.5e+300"),
        (-2.5e-7, "-2.5e-07"),
        (1751700000.123, "1751700000.123"),
        (0.9, "0.9"),
        (0.45, "0.45"),
    ];
    for (x, want) in cases {
        assert_eq!(
            py_float_repr(*x).unwrap(),
            *want,
            "float repr fork for {x}"
        );
    }
}

#[test]
fn float_repr_rejects_non_finite() {
    assert!(py_float_repr(f64::NAN).is_err());
    assert!(py_float_repr(f64::INFINITY).is_err());
    assert!(py_float_repr(f64::NEG_INFINITY).is_err());
}

#[test]
fn ensure_ascii_matches_cpython() {
    // json.dumps({"a":"é"},sort_keys=True,separators=(",",":"))
    //   == '{"a":"\\u00e9"}'
    assert_eq!(
        canonical(&json!({"a": "é"})).unwrap(),
        r#"{"a":"\u00e9"}"#
    );
    // astral plane -> surrogate pair: 😀 U+1F600
    assert_eq!(
        canonical(&json!({"e": "😀"})).unwrap(),
        r#"{"e":"\ud83d\ude00"}"#
    );
    // control chars + shortcuts
    assert_eq!(
        canonical(&json!("a\nb\t\"c\"\\")).unwrap(),
        r#""a\nb\t\"c\"\\""#
    );
    assert_eq!(canonical(&json!("\u{0001}")).unwrap(), r#""\u0001""#);
    // 0x7f DEL is escaped by CPython
    assert_eq!(canonical(&json!("\u{007f}")).unwrap(), r#""\u007f""#);
}

#[test]
fn keys_sorted_nested_compact() {
    let v = json!({
        "z": {"b": 2, "a": 1},
        "a": [1, "x", null, true, false],
        "m": 3
    });
    assert_eq!(
        canonical(&v).unwrap(),
        r#"{"a":[1,"x",null,true,false],"m":3,"z":{"a":1,"b":2}}"#
    );
}

#[test]
fn ints_stay_ints_floats_stay_floats() {
    // Python: json.dumps({"i":3,"f":3.0}) -> '{"f":3.0,"i":3}'
    assert_eq!(
        canonical(&json!({"i": 3, "f": 3.0})).unwrap(),
        r#"{"f":3.0,"i":3}"#
    );
}

mod record_parity {
    use pv_runtime::runtime::decision_record::DecisionRecord;
    use pv_runtime::runtime::execution_record::ExecutionEvent;

    #[test]
    fn sealed_record_verifies_and_tamper_detected() {
        let mut r = DecisionRecord::new(
            "d-1".into(),
            "agent-1".into(),
            "payments.initiate_wire".into(),
            "block".into(),
            "invariant".into(),
            1751700000.0,
            None,
            "0".repeat(64),
        );
        let _ = r.seal();
        assert!(r.verify());
        r.decision = "allow".into();
        assert!(!r.verify(), "decision tamper must break verification");
    }

    #[test]
    fn execution_event_invalid_edges_is_error_over_ffi() {
        // The FFI constructor must REJECT invalid edges -- the old
        // parse-or-[] behavior let two different stored strings hash
        // identically.
        let bad = ExecutionEvent::py_new(
            "e-1".into(),
            "agent-1".into(),
            "d-1".into(),
            "ok".into(),
            "".into(),
            1751700000.0,
            "0".repeat(64),
            "{not json".into(),
        );
        assert!(bad.is_err(), "invalid edges must error, never default");
    }

    #[test]
    fn nan_drift_score_fails_closed() {
        let mut r = DecisionRecord::new(
            "d-nan".into(),
            "agent-1".into(),
            "x".into(),
            "allow".into(),
            "baseline".into(),
            1751700000.0,
            None,
            "0".repeat(64),
        );
        r.drift_score = f64::NAN;
        assert!(r.seal().is_err(), "NaN must not seal");
        assert!(!r.verify(), "unsealed record must not verify");
    }
}
