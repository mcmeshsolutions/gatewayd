use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

const PAGES: [&str; 9] = ["/", "/panel", "/status", "/invite/{code}", "/view/{id}", "/contraption", "/isomap/{id}", "/timeline/{id}", "/digest/{id}"];

fn registered() -> BTreeMap<String, BTreeSet<String>> {
    let mut out: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for file in ["admin.rs", "panel.rs", "ops.rs", "worldgen.rs", "shard.rs"] {
        let src = std::fs::read_to_string(format!("{}/src/{file}", env!("CARGO_MANIFEST_DIR"))).unwrap();
        for line in src.lines().filter(|l| l.trim_start().starts_with(".route(\"")) {
            let rest = &line.trim_start()[".route(\"".len()..];
            let (path, tail) = rest.split_once('"').unwrap();
            let path = path.split('/').map(|s| s.strip_prefix(':').map_or(s.to_string(), |n| format!("{{{n}}}"))).collect::<Vec<_>>().join("/");
            let methods = out.entry(path).or_default();
            for m in ["get", "post", "put", "delete"] {
                if tail.contains(&format!("{m}(")) {
                    methods.insert(m.to_string());
                }
            }
        }
    }
    out.retain(|p, _| !PAGES.contains(&p.as_str()));
    out
}

#[test]
fn the_openapi_file_lists_exactly_the_registered_api_routes() {
    let doc: Value = serde_json::from_str(&std::fs::read_to_string(format!("{}/../docs/openapi.json", env!("CARGO_MANIFEST_DIR"))).unwrap()).unwrap();
    let documented: BTreeMap<String, BTreeSet<String>> = doc["paths"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(p, ops)| (p.clone(), ops.as_object().unwrap().keys().cloned().collect()))
        .collect();
    let live = registered();
    let missing: Vec<_> = live.iter().filter(|(p, m)| documented.get(*p) != Some(m)).map(|(p, m)| format!("{p} {m:?}")).collect();
    let stale: Vec<_> = documented.keys().filter(|p| !live.contains_key(*p)).collect();
    assert!(missing.is_empty(), "routes missing from or different in docs/openapi.json: {missing:?}");
    assert!(stale.is_empty(), "docs/openapi.json lists routes that are not registered: {stale:?}");
}

fn refs(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::Object(m) => {
            for (k, x) in m {
                if k == "$ref" {
                    out.push(x.as_str().unwrap().to_string());
                } else {
                    refs(x, out);
                }
            }
        }
        Value::Array(a) => a.iter().for_each(|x| refs(x, out)),
        _ => {}
    }
}

#[test]
fn every_schema_reference_resolves_and_required_fields_are_declared() {
    let doc: Value = serde_json::from_str(&std::fs::read_to_string(format!("{}/../docs/openapi.json", env!("CARGO_MANIFEST_DIR"))).unwrap()).unwrap();
    let schemas = doc["components"]["schemas"].as_object().unwrap();
    let mut all = Vec::new();
    refs(&doc, &mut all);
    assert!(!all.is_empty());
    for r in all {
        let name = r.strip_prefix("#/components/schemas/").unwrap_or_else(|| panic!("unexpected reference {r}"));
        assert!(schemas.contains_key(name), "{r} points at nothing");
    }
    for (name, s) in schemas {
        if let Some(req) = s["required"].as_array() {
            for f in req {
                assert!(s["properties"].get(f.as_str().unwrap()).is_some(), "{name}: required field {f} is not declared");
            }
        }
    }
    let with_body = doc["paths"].as_object().unwrap().values().flat_map(|m| m.as_object().unwrap().values()).filter(|op| op.get("requestBody").is_some()).count();
    assert!(with_body >= 25, "request bodies documented: {with_body}");
}
