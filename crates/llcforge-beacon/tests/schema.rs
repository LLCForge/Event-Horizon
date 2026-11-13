//! Serialized alerts must validate against `schema/alert.v1.json`.
//!
//! A small validator for exactly the JSON Schema keywords the schema uses
//! (type, const, enum, required, properties, additionalProperties, items,
//! minLength, maxLength, maxItems, pattern "^https?://", format date-time),
//! so the test needs no extra dependencies.

use llcforge_beacon::{Alert, Severity};
use serde_json::Value;

fn schema() -> Value {
    serde_json::from_str(include_str!("../schema/alert.v1.json")).expect("schema is valid JSON")
}

fn validate(schema: &Value, v: &Value, path: &str, errs: &mut Vec<String>) {
    let s = schema.as_object().expect("schema object");
    if let Some(t) = s.get("type").and_then(Value::as_str) {
        let ok = match t {
            "object" => v.is_object(),
            "array" => v.is_array(),
            "string" => v.is_string(),
            "boolean" => v.is_boolean(),
            other => panic!("unsupported type {other}"),
        };
        if !ok {
            errs.push(format!("{path}: expected {t}"));
            return;
        }
    }
    if let Some(c) = s.get("const") {
        if c != v {
            errs.push(format!("{path}: expected const {c}"));
        }
    }
    if let Some(e) = s.get("enum").and_then(Value::as_array) {
        if !e.contains(v) {
            errs.push(format!("{path}: {v} not in enum"));
        }
    }
    if let Some(st) = v.as_str() {
        let n = st.chars().count() as u64;
        if s.get("minLength")
            .and_then(Value::as_u64)
            .is_some_and(|m| n < m)
        {
            errs.push(format!("{path}: too short"));
        }
        if s.get("maxLength")
            .and_then(Value::as_u64)
            .is_some_and(|m| n > m)
        {
            errs.push(format!("{path}: too long"));
        }
        if let Some(p) = s.get("pattern").and_then(Value::as_str) {
            assert_eq!(p, "^https?://", "validator only knows this pattern");
            if !(st.starts_with("http://") || st.starts_with("https://")) {
                errs.push(format!("{path}: pattern mismatch"));
            }
        }
        if s.get("format").and_then(Value::as_str) == Some("date-time") {
            if chrono::DateTime::parse_from_rfc3339(st).is_err() {
                errs.push(format!("{path}: not RFC 3339"));
            } else if !st.ends_with('Z') {
                errs.push(format!("{path}: not UTC (Z)"));
            }
        }
    }
    if let Some(arr) = v.as_array() {
        if s.get("maxItems")
            .and_then(Value::as_u64)
            .is_some_and(|m| arr.len() as u64 > m)
        {
            errs.push(format!("{path}: too many items"));
        }
        if let Some(items) = s.get("items") {
            for (i, it) in arr.iter().enumerate() {
                validate(items, it, &format!("{path}[{i}]"), errs);
            }
        }
    }
    if let Some(obj) = v.as_object() {
        let props = s.get("properties").and_then(Value::as_object);
        if let Some(req) = s.get("required").and_then(Value::as_array) {
            for r in req {
                let r = r.as_str().expect("required entries are strings");
                if !obj.contains_key(r) {
                    errs.push(format!("{path}: missing {r}"));
                }
            }
        }
        for (k, val) in obj {
            match props.and_then(|p| p.get(k)) {
                Some(ps) => validate(ps, val, &format!("{path}.{k}"), errs),
                None if s.get("additionalProperties") == Some(&Value::Bool(false)) => {
                    errs.push(format!("{path}: unexpected property {k}"))
                }
                None => {}
            }
        }
    }
}

fn errors(v: &Value) -> Vec<String> {
    let mut errs = Vec::new();
    validate(&schema(), v, "$", &mut errs);
    errs
}

#[test]
fn minimal_and_full_alerts_validate() {
    let minimal = Alert::new("vigil", "origin_hijack", Severity::Info, "t");
    let full = Alert::new(
        "herald",
        "cert_issued",
        Severity::Critical,
        "New certificate for www.example.org",
    )
    .resource("www.example.org")
    .summary("Unexpected issuer")
    .field("issuer", "Example CA")
    .field("serial", "01:02")
    .link("crt.sh", "https://example.net/?id=1")
    .resolved(true);
    for a in [minimal, full] {
        let v = serde_json::to_value(&a).unwrap();
        assert_eq!(errors(&v), Vec::<String>::new(), "{v}");
    }
}

#[test]
fn normalized_oversized_alert_validates() {
    let mut a =
        Alert::new("t", "k", Severity::Warning, "x".repeat(5000)).summary("y".repeat(100_000));
    for i in 0..200 {
        a = a.field(format!("k{i}"), "v".repeat(5000));
    }
    a = a.link("bad", "ftp://example.net/");
    a.normalize().unwrap();
    let v = serde_json::to_value(&a).unwrap();
    assert_eq!(errors(&v), Vec::<String>::new());
}

#[test]
fn validator_catches_violations() {
    let mut v = serde_json::to_value(Alert::new("t", "k", Severity::Info, "x")).unwrap();
    v["severity"] = "fatal".into();
    v["extra"] = 1.into();
    v["first_seen"] = "yesterday".into();
    v.as_object_mut().unwrap().remove("id");
    let e = errors(&v);
    assert_eq!(e.len(), 4, "{e:?}");
}
