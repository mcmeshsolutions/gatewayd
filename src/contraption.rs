use flate2::read::GzDecoder;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::io::Read;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KineticComponent {
    pub x: i32,
    pub y: i32,
    pub z: i32,
    pub r#type: String,
    pub axis: String,
    pub rpm: f64,
    pub direction: i32,
    pub color: [f32; 3],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StressReport {
    pub capacity_su: f64,
    pub impact_su: f64,
    pub net_su: f64,
    pub rpm: f64,
    pub overstressed: bool,
    pub stress_percent: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawMaterials {
    pub andesite_alloy: i32,
    pub zinc_ingot: i32,
    pub brass_ingot: i32,
    pub iron_ingot: i32,
    pub copper_ingot: i32,
    pub wood_planks: i32,
    pub redstone_dust: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BomReport {
    pub items: BTreeMap<String, i32>,
    pub raw_materials: RawMaterials,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContraptionInspection {
    pub name: String,
    pub components: Vec<KineticComponent>,
    pub stress: StressReport,
    pub bom: BomReport,
}

/// Computes raw materials needed from a block item BOM.
pub fn calculate_raw_materials(items: &BTreeMap<String, i32>) -> RawMaterials {
    let mut raw = RawMaterials {
        andesite_alloy: 0,
        zinc_ingot: 0,
        brass_ingot: 0,
        iron_ingot: 0,
        copper_ingot: 0,
        wood_planks: 0,
        redstone_dust: 0,
    };

    for (item, &count) in items {
        let c = count.max(0);
        match item.as_str() {
            "create:shaft" => {
                // 1 alloy = 2 shafts -> 1 alloy per 2 shafts
                raw.andesite_alloy += (c + 1) / 2;
            }
            "create:cogwheel" => {
                raw.andesite_alloy += (c + 1) / 2;
                raw.wood_planks += c;
            }
            "create:large_cogwheel" => {
                raw.andesite_alloy += (c + 1) / 2;
                raw.wood_planks += c * 2;
            }
            "create:water_wheel" => {
                raw.andesite_alloy += (c + 1) / 2;
                raw.wood_planks += c * 8;
            }
            "create:large_water_wheel" => {
                raw.andesite_alloy += (c + 1) / 2;
                raw.wood_planks += c * 16;
            }
            "create:steam_engine" => {
                raw.brass_ingot += c * 3;
                raw.copper_ingot += c * 2;
                raw.andesite_alloy += c;
            }
            "create:mechanical_press" => {
                raw.andesite_alloy += c * 2;
                raw.iron_ingot += c * 9; // iron block
                raw.wood_planks += c;
            }
            "create:mechanical_mixer" => {
                raw.andesite_alloy += c * 2;
                raw.iron_ingot += c * 5; // whisk
                raw.wood_planks += c;
            }
            "create:crushing_wheel" => {
                raw.andesite_alloy += c * 16;
                raw.wood_planks += c * 4;
            }
            "create:mechanical_saw" | "create:mechanical_drill" => {
                raw.andesite_alloy += c * 3;
                raw.iron_ingot += c * 3;
            }
            "create:gearbox" => {
                raw.andesite_alloy += c * 3;
                raw.wood_planks += c * 4;
            }
            "create:clutch" | "create:gearshift" => {
                raw.andesite_alloy += c * 2;
                raw.redstone_dust += c;
            }
            "create:andesite_casing" => {
                raw.andesite_alloy += c;
                raw.wood_planks += c;
            }
            "create:brass_casing" => {
                raw.brass_ingot += c;
                raw.wood_planks += c;
            }
            "create:copper_casing" => {
                raw.copper_ingot += c;
                raw.wood_planks += c;
            }
            _ => {
                // Generic fallback estimation
                if item.contains("shaft") {
                    raw.andesite_alloy += (c + 1) / 2;
                } else if item.contains("brass") {
                    raw.brass_ingot += c;
                } else if item.contains("iron") {
                    raw.iron_ingot += c;
                }
            }
        }
    }

    raw
}

/// Evaluates kinetic stress capacity and impact.
pub fn calculate_stress(components: &[KineticComponent], base_rpm: f64) -> StressReport {
    let mut capacity = 0.0;
    let mut impact = 0.0;

    for comp in components {
        let rpm = if comp.rpm.abs() > 0.01 { comp.rpm.abs() } else { base_rpm };
        match comp.r#type.as_str() {
            "create:water_wheel" => capacity += 256.0,
            "create:large_water_wheel" => capacity += 512.0,
            "create:windmill_bearing" | "create:sail" => capacity += 2048.0,
            "create:steam_engine" => capacity += 16384.0,
            "create:creative_motor" => capacity += 16384.0,
            "create:hand_crank" => capacity += 256.0,
            // Consumers: impact per RPM * rpm
            "create:mechanical_press" => impact += 8.0 * rpm,
            "create:mechanical_mixer" => impact += 8.0 * rpm,
            "create:crushing_wheel" => impact += 16.0 * rpm,
            "create:mechanical_saw" => impact += 4.0 * rpm,
            "create:mechanical_drill" => impact += 4.0 * rpm,
            "create:mechanical_harvester" => impact += 4.0 * rpm,
            "create:mechanical_plough" => impact += 4.0 * rpm,
            "create:deployer" => impact += 4.0 * rpm,
            "create:mechanical_arm" => impact += 8.0 * rpm,
            "create:millstone" => impact += 4.0 * rpm,
            "create:rope_pulley" => impact += 4.0 * rpm,
            "create:mechanical_piston" => impact += 4.0 * rpm,
            _ => {}
        }
    }

    let net_su = capacity - impact;
    let overstressed = impact > capacity;
    let stress_percent = if capacity > 0.0 {
        ((impact / capacity) * 100.0).min(999.9)
    } else if impact > 0.0 {
        999.0
    } else {
        0.0
    };

    StressReport {
        capacity_su: capacity,
        impact_su: impact,
        net_su,
        rpm: base_rpm,
        overstressed,
        stress_percent,
    }
}

/// Color mapping for WebGL component rendering.
pub fn component_color(block: &str) -> [f32; 3] {
    match block {
        "create:shaft" => [0.65, 0.65, 0.65],
        "create:cogwheel" => [0.72, 0.52, 0.32],
        "create:large_cogwheel" => [0.62, 0.42, 0.22],
        "create:water_wheel" | "create:large_water_wheel" => [0.35, 0.55, 0.75],
        "create:steam_engine" => [0.85, 0.65, 0.25],
        "create:mechanical_press" => [0.45, 0.50, 0.55],
        "create:mechanical_mixer" => [0.55, 0.45, 0.65],
        "create:crushing_wheel" => [0.35, 0.35, 0.40],
        "create:mechanical_saw" => [0.75, 0.75, 0.80],
        "create:mechanical_drill" => [0.40, 0.45, 0.50],
        "create:gearbox" => [0.50, 0.45, 0.40],
        "create:clutch" | "create:gearshift" => [0.60, 0.30, 0.30],
        _ => [0.55, 0.55, 0.55],
    }
}

/// Generates a demonstration contraption (Automated Press & Mixer line with Water Wheel).
pub fn demo_contraption(base_rpm: f64) -> ContraptionInspection {
    let rpm = if base_rpm <= 0.0 { 64.0 } else { base_rpm };
    let comps = vec![
        // Water wheel generator at x=0
        KineticComponent {
            x: 0,
            y: 1,
            z: 0,
            r#type: "create:water_wheel".into(),
            axis: "z".into(),
            rpm: 16.0,
            direction: 1,
            color: component_color("create:water_wheel"),
        },
        KineticComponent {
            x: 0,
            y: 1,
            z: -1,
            r#type: "create:water_wheel".into(),
            axis: "z".into(),
            rpm: 16.0,
            direction: 1,
            color: component_color("create:water_wheel"),
        },
        // Shaft connecting water wheel to large cog
        KineticComponent {
            x: 0,
            y: 1,
            z: 1,
            r#type: "create:shaft".into(),
            axis: "z".into(),
            rpm: 16.0,
            direction: 1,
            color: component_color("create:shaft"),
        },
        // Large cogwheel (16 RPM)
        KineticComponent {
            x: 0,
            y: 1,
            z: 2,
            r#type: "create:large_cogwheel".into(),
            axis: "z".into(),
            rpm: 16.0,
            direction: 1,
            color: component_color("create:large_cogwheel"),
        },
        // Small cogwheel meshing with large cog (steps up to 32 RPM, opposite direction)
        KineticComponent {
            x: 1,
            y: 2,
            z: 2,
            r#type: "create:cogwheel".into(),
            axis: "z".into(),
            rpm: 32.0,
            direction: -1,
            color: component_color("create:cogwheel"),
        },
        // Large cogwheel on same shaft (32 RPM)
        KineticComponent {
            x: 1,
            y: 2,
            z: 3,
            r#type: "create:large_cogwheel".into(),
            axis: "z".into(),
            rpm: 32.0,
            direction: -1,
            color: component_color("create:large_cogwheel"),
        },
        // Small cogwheel meshing (steps up to 64 RPM)
        KineticComponent {
            x: 2,
            y: 3,
            z: 3,
            r#type: "create:cogwheel".into(),
            axis: "z".into(),
            rpm: 64.0,
            direction: 1,
            color: component_color("create:cogwheel"),
        },
        // Transmission shaft line leading to machines
        KineticComponent {
            x: 2,
            y: 3,
            z: 4,
            r#type: "create:shaft".into(),
            axis: "z".into(),
            rpm: 64.0,
            direction: 1,
            color: component_color("create:shaft"),
        },
        KineticComponent {
            x: 2,
            y: 3,
            z: 5,
            r#type: "create:shaft".into(),
            axis: "z".into(),
            rpm: 64.0,
            direction: 1,
            color: component_color("create:shaft"),
        },
        // Mechanical Press
        KineticComponent {
            x: 2,
            y: 4,
            z: 5,
            r#type: "create:mechanical_press".into(),
            axis: "y".into(),
            rpm: 64.0,
            direction: 1,
            color: component_color("create:mechanical_press"),
        },
        // Gearbox changing axis towards mixer
        KineticComponent {
            x: 2,
            y: 3,
            z: 6,
            r#type: "create:gearbox".into(),
            axis: "x".into(),
            rpm: 64.0,
            direction: 1,
            color: component_color("create:gearbox"),
        },
        KineticComponent {
            x: 3,
            y: 3,
            z: 6,
            r#type: "create:shaft".into(),
            axis: "x".into(),
            rpm: 64.0,
            direction: 1,
            color: component_color("create:shaft"),
        },
        // Mechanical Mixer
        KineticComponent {
            x: 3,
            y: 4,
            z: 6,
            r#type: "create:mechanical_mixer".into(),
            axis: "y".into(),
            rpm: 64.0,
            direction: 1,
            color: component_color("create:mechanical_mixer"),
        },
    ];

    let mut items = BTreeMap::new();
    for comp in &comps {
        *items.entry(comp.r#type.clone()).or_insert(0) += 1;
    }

    let stress = calculate_stress(&comps, rpm);
    let raw_materials = calculate_raw_materials(&items);

    ContraptionInspection {
        name: "Automated Kinetic Press & Mixer Line".into(),
        components: comps,
        stress,
        bom: BomReport {
            items,
            raw_materials,
        },
    }
}

/// Parses raw text, JSON, or NBT schematic input and produces a ContraptionInspection.
pub fn inspect_bytes(data: &[u8], base_rpm: f64) -> ContraptionInspection {
    let rpm = if base_rpm <= 0.0 { 64.0 } else { base_rpm };

    // 1. Try JSON parsing
    if let Ok(v) = serde_json::from_slice::<Value>(data) {
        if let Some(insp) = parse_json_contraption(&v, rpm) {
            return insp;
        }
    }

    // 2. Try decompressing gzip if it has gzip magic bytes 0x1f, 0x8b
    let decompressed = if data.len() >= 2 && data[0] == 0x1f && data[1] == 0x8b {
        let mut d = GzDecoder::new(data);
        let mut buf = Vec::new();
        if d.read_to_end(&mut buf).is_ok() {
            buf
        } else {
            data.to_vec()
        }
    } else {
        data.to_vec()
    };

    // 3. Try UTF-8 text interpretation (scratchpad format or block list)
    if let Ok(text) = std::str::from_utf8(&decompressed) {
        if let Some(insp) = parse_text_contraption(text, rpm) {
            return insp;
        }
    }

    // 4. Fallback binary scan for Create components in raw NBT tags
    let mut items = BTreeMap::new();
    let mut components = Vec::new();

    let text_view = String::from_utf8_lossy(&decompressed);
    let create_types = [
        "create:shaft",
        "create:cogwheel",
        "create:large_cogwheel",
        "create:water_wheel",
        "create:large_water_wheel",
        "create:steam_engine",
        "create:mechanical_press",
        "create:mechanical_mixer",
        "create:crushing_wheel",
        "create:mechanical_saw",
        "create:mechanical_drill",
        "create:gearbox",
        "create:clutch",
        "create:gearshift",
        "create:andesite_casing",
        "create:brass_casing",
    ];

    let mut idx = 0;
    for ty in &create_types {
        let count = text_view.matches(ty).count();
        if count > 0 {
            items.insert(ty.to_string(), count as i32);
            for _ in 0..count {
                components.push(KineticComponent {
                    x: idx % 8,
                    y: (idx / 8) % 4,
                    z: idx / 32,
                    r#type: ty.to_string(),
                    axis: "y".into(),
                    rpm,
                    direction: 1,
                    color: component_color(ty),
                });
                idx += 1;
            }
        }
    }

    if components.is_empty() {
        return demo_contraption(rpm);
    }

    let stress = calculate_stress(&components, rpm);
    let raw_materials = calculate_raw_materials(&items);

    ContraptionInspection {
        name: "Inspected Create Schematic".into(),
        components,
        stress,
        bom: BomReport {
            items,
            raw_materials,
        },
    }
}

fn parse_json_contraption(v: &Value, rpm: f64) -> Option<ContraptionInspection> {
    let name = v.get("name").and_then(|n| n.as_str()).unwrap_or("Create Contraption").to_string();

    let mut components = Vec::new();
    let mut items = BTreeMap::new();

    if let Some(comps) = v.get("components").and_then(|c| c.as_array()) {
        for (i, c) in comps.iter().enumerate() {
            let ty = c.get("type").and_then(|s| s.as_str()).unwrap_or("create:shaft").to_string();
            let x = c.get("x").and_then(|n| n.as_i64()).unwrap_or(i as i64) as i32;
            let y = c.get("y").and_then(|n| n.as_i64()).unwrap_or(0) as i32;
            let z = c.get("z").and_then(|n| n.as_i64()).unwrap_or(0) as i32;
            let axis = c.get("axis").and_then(|s| s.as_str()).unwrap_or("y").to_string();
            let comp_rpm = c.get("rpm").and_then(|n| n.as_f64()).unwrap_or(rpm);
            let dir = c.get("direction").and_then(|n| n.as_i64()).unwrap_or(1) as i32;

            *items.entry(ty.clone()).or_insert(0) += 1;
            components.push(KineticComponent {
                x,
                y,
                z,
                r#type: ty.clone(),
                axis,
                rpm: comp_rpm,
                direction: dir,
                color: component_color(&ty),
            });
        }
    } else if let Some(bom_obj) = v.get("bom").and_then(|b| b.as_object()) {
        let mut idx = 0;
        for (k, val) in bom_obj {
            let count = val.as_i64().unwrap_or(1) as i32;
            *items.entry(k.clone()).or_insert(0) += count;
            for _ in 0..count {
                components.push(KineticComponent {
                    x: idx % 6,
                    y: (idx / 6) % 3,
                    z: idx / 18,
                    r#type: k.clone(),
                    axis: "y".into(),
                    rpm,
                    direction: 1,
                    color: component_color(k),
                });
                idx += 1;
            }
        }
    } else {
        return None;
    }

    let stress = calculate_stress(&components, rpm);
    let raw_materials = calculate_raw_materials(&items);

    Some(ContraptionInspection {
        name,
        components,
        stress,
        bom: BomReport {
            items,
            raw_materials,
        },
    })
}

fn parse_text_contraption(text: &str, rpm: f64) -> Option<ContraptionInspection> {
    let mut items = BTreeMap::new();
    let mut components = Vec::new();
    let mut name = "MCMesh Scratchpad Schematic".to_string();

    // Handle MCMESH_CREATE_SCHEMATIC_V1 header or Draft format
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("Draft[name=") {
            if let Some(rest) = trimmed.strip_prefix("Draft[name=") {
                if let Some(n) = rest.split(',').next() {
                    name = n.to_string();
                }
            }
        }
        // Check for "bom={...}"
        if let Some(bom_part) = trimmed.find("bom={") {
            let inner = &trimmed[bom_part + 5..];
            if let Some(end) = inner.find('}') {
                let kv_str = &inner[..end];
                for kv in kv_str.split(',') {
                    if let Some((k, v)) = kv.split_once('=') {
                        let k = k.trim().to_string();
                        if let Ok(c) = v.trim().parse::<i32>() {
                            *items.entry(k).or_insert(0) += c;
                        }
                    }
                }
            }
        }
        // Direct key-value or item line: "create:shaft 4" or "create:shaft: 4"
        if trimmed.starts_with("create:") {
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() >= 2 {
                let id = parts[0].trim_end_matches(':');
                if let Ok(cnt) = parts[1].parse::<i32>() {
                    *items.entry(id.to_string()).or_insert(0) += cnt;
                }
            }
        }
    }

    if items.is_empty() {
        return None;
    }

    let mut idx = 0;
    for (ty, &count) in &items {
        for _ in 0..count {
            components.push(KineticComponent {
                x: idx % 8,
                y: (idx / 8) % 4,
                z: idx / 32,
                r#type: ty.clone(),
                axis: if idx % 2 == 0 { "y" } else { "z" }.into(),
                rpm,
                direction: if idx % 2 == 0 { 1 } else { -1 },
                color: component_color(ty),
            });
            idx += 1;
        }
    }

    let stress = calculate_stress(&components, rpm);
    let raw_materials = calculate_raw_materials(&items);

    Some(ContraptionInspection {
        name,
        components,
        stress,
        bom: BomReport {
            items,
            raw_materials,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn demo_contraption_has_balanced_stress_and_complete_bom() {
        let demo = demo_contraption(64.0);
        assert!(!demo.components.is_empty());
        assert_eq!(demo.stress.capacity_su, 512.0); // 2 water wheels = 2 * 256
        assert!(demo.stress.impact_su > 0.0);
        assert!(demo.bom.items.contains_key("create:water_wheel"));
        assert!(demo.bom.items.contains_key("create:mechanical_press"));
        assert!(demo.bom.items.contains_key("create:mechanical_mixer"));
        assert!(demo.bom.raw_materials.andesite_alloy > 0);
        assert!(demo.bom.raw_materials.iron_ingot > 0);
    }

    #[test]
    fn stress_calculation_detects_overstressed_network() {
        let comps = vec![
            KineticComponent {
                x: 0,
                y: 0,
                z: 0,
                r#type: "create:water_wheel".into(),
                axis: "z".into(),
                rpm: 16.0,
                direction: 1,
                color: [0.0, 0.0, 0.0],
            },
            KineticComponent {
                x: 1,
                y: 0,
                z: 0,
                r#type: "create:crushing_wheel".into(),
                axis: "y".into(),
                rpm: 64.0, // 16 SU/RPM * 64 RPM = 1024 SU > 256 SU
                direction: 1,
                color: [0.0, 0.0, 0.0],
            },
        ];
        let rep = calculate_stress(&comps, 64.0);
        assert_eq!(rep.capacity_su, 256.0);
        assert_eq!(rep.impact_su, 1024.0);
        assert!(rep.overstressed);
        assert!(rep.stress_percent > 100.0);
    }

    #[test]
    fn parses_mcmesh_scratchpad_text_draft() {
        let text = "MCMESH_CREATE_SCHEMATIC_V1\nDraft[name=crusher, dim=minecraft:overworld, x=10, y=64, z=10, bom={create:shaft=5, create:mechanical_press=1}, hologram=true]";
        let insp = inspect_bytes(text.as_bytes(), 64.0);
        assert_eq!(insp.name, "crusher");
        assert_eq!(insp.bom.items.get("create:shaft"), Some(&5));
        assert_eq!(insp.bom.items.get("create:mechanical_press"), Some(&1));
        assert_eq!(insp.components.len(), 6);
    }

    #[test]
    fn parses_json_components() {
        let json_data = json!({
            "name": "Custom Gearbox Unit",
            "components": [
                {"type": "create:steam_engine", "x": 0, "y": 0, "z": 0},
                {"type": "create:mechanical_saw", "x": 1, "y": 0, "z": 0}
            ]
        });
        let insp = inspect_bytes(json_data.to_string().as_bytes(), 32.0);
        assert_eq!(insp.name, "Custom Gearbox Unit");
        assert_eq!(insp.stress.capacity_su, 16384.0);
        assert_eq!(insp.stress.impact_su, 128.0); // 4 * 32
        assert!(!insp.stress.overstressed);
    }
}
