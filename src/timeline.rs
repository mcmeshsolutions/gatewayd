use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeatmapPoint {
    pub x: i32,
    pub z: i32,
    pub build_intensity: i32,
    pub mine_intensity: i32,
    pub total: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeatmapBounds {
    pub min_x: i32,
    pub max_x: i32,
    pub min_z: i32,
    pub max_z: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeatmapResponse {
    pub world_id: String,
    pub grid_size: i32,
    pub bounds: HeatmapBounds,
    pub points: Vec<HeatmapPoint>,
    pub max_intensity: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HallOfFameLeader {
    pub rank: i32,
    pub player_uuid: String,
    pub player_name: String,
    pub blocks_placed: i64,
    pub blocks_mined: i64,
    pub playtime_seconds: i64,
    pub skin_url: String,
    pub badges: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorldMilestone {
    pub title: String,
    pub date_sec: i64,
    pub rev: String,
    pub by: String,
    pub icon: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HallOfFameResponse {
    pub world_id: String,
    pub leaders: Vec<HallOfFameLeader>,
    pub milestones: Vec<WorldMilestone>,
}

/// Generates top-down spatial heatmap data for player construction and excavation activity.
pub fn generate_heatmap(world_id: &str, radius_chunks: i32) -> HeatmapResponse {
    let r = radius_chunks.clamp(2, 16);
    let grid_size = 16; // 16-block resolution (1 point per chunk)
    let min_x = -r * grid_size;
    let max_x = r * grid_size;
    let min_z = -r * grid_size;
    let max_z = r * grid_size;

    let mut points = Vec::new();
    let mut max_intensity = 1;

    for cz in -r..=r {
        for cx in -r..=r {
            let dist_sq = (cx * cx + cz * cz) as f64;
            let center_falloff = (-dist_sq / 18.0).exp();

            // Central base has high building intensity
            let build = (center_falloff * 240.0 + (cx * 11 + cz * 7).abs() as f64 % 25.0) as i32;

            // Mining shafts and perimeter quarries
            let is_corridor = (cx.abs() == 2 || cz.abs() == 2) && dist_sq > 4.0;
            let mine = if is_corridor {
                (120.0 + (cx * 13 + cz * 17).abs() as f64 % 60.0) as i32
            } else {
                ((1.0 - center_falloff) * 60.0 + (cx * 5 + cz * 9).abs() as f64 % 20.0) as i32
            };

            let total = build + mine;
            if total > max_intensity {
                max_intensity = total;
            }

            points.push(HeatmapPoint {
                x: cx * grid_size,
                z: cz * grid_size,
                build_intensity: build,
                mine_intensity: mine,
                total,
            });
        }
    }

    HeatmapResponse {
        world_id: world_id.to_string(),
        grid_size,
        bounds: HeatmapBounds {
            min_x,
            max_x,
            min_z,
            max_z,
        },
        points,
        max_intensity,
    }
}

/// Generates Hall of Fame leaderboards and world historical milestones.
pub fn generate_hall_of_fame(world_id: &str) -> HallOfFameResponse {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let leaders = vec![
        HallOfFameLeader {
            rank: 1,
            player_uuid: "00000000-0000-0000-0000-000000000001".into(),
            player_name: "MeshMaster".into(),
            blocks_placed: 48920,
            blocks_mined: 31400,
            playtime_seconds: 142800,
            skin_url: "/v1/skins/default".into(),
            badges: vec!["Founding Father".into(), "Master Architect".into(), "Kinetic Pioneer".into()],
        },
        HallOfFameLeader {
            rank: 2,
            player_uuid: "00000000-0000-0000-0000-000000000002".into(),
            player_name: "DeepDelver".into(),
            blocks_placed: 12400,
            blocks_mined: 89650,
            playtime_seconds: 118400,
            skin_url: "/v1/skins/default".into(),
            badges: vec!["Deep Delver".into(), "Nether Scout".into(), "Ancient Debris Hoarder".into()],
        },
        HallOfFameLeader {
            rank: 3,
            player_uuid: "00000000-0000-0000-0000-000000000003".into(),
            player_name: "RedstoneWizard".into(),
            blocks_placed: 29800,
            blocks_mined: 18200,
            playtime_seconds: 94600,
            skin_url: "/v1/skins/default".into(),
            badges: vec!["Automator".into(), "Cogwheel Guru".into()],
        },
    ];

    let milestones = vec![
        WorldMilestone {
            title: "Genesis World Creation".into(),
            date_sec: now - 86400 * 7,
            rev: format!("{world_id}:R_0000"),
            by: "MeshMaster".into(),
            icon: "genesis".into(),
        },
        WorldMilestone {
            title: "Main Base Foundations & Warehouse".into(),
            date_sec: now - 86400 * 5,
            rev: format!("{world_id}:R_0012"),
            by: "MeshMaster".into(),
            icon: "foundation".into(),
        },
        WorldMilestone {
            title: "Nether Highway & Blaze Farm".into(),
            date_sec: now - 86400 * 3,
            rev: format!("{world_id}:R_0035"),
            by: "DeepDelver".into(),
            icon: "nether".into(),
        },
        WorldMilestone {
            title: "Automated Kinetic Factory Line".into(),
            date_sec: now - 86400 * 1,
            rev: format!("{world_id}:R_0088"),
            by: "RedstoneWizard".into(),
            icon: "factory".into(),
        },
        WorldMilestone {
            title: "Ender Dragon Defeated & Elytra Claimed".into(),
            date_sec: now - 14400,
            rev: format!("{world_id}:R_0120"),
            by: "MeshMaster & DeepDelver".into(),
            icon: "dragon".into(),
        },
    ];

    HallOfFameResponse {
        world_id: world_id.to_string(),
        leaders,
        milestones,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heatmap_generates_points_and_positive_max_intensity() {
        let hm = generate_heatmap("world1", 3);
        assert!(!hm.points.is_empty());
        assert!(hm.max_intensity > 0);
        assert_eq!(hm.bounds.min_x, -3 * 16);
        assert_eq!(hm.bounds.max_x, 3 * 16);
        for pt in &hm.points {
            assert!(pt.total >= 0);
            assert!(pt.total <= hm.max_intensity);
        }
    }

    #[test]
    fn hall_of_fame_has_ranked_leaders_and_milestones() {
        let hof = generate_hall_of_fame("world1");
        assert_eq!(hof.world_id, "world1");
        assert!(!hof.leaders.is_empty());
        assert_eq!(hof.leaders[0].rank, 1);
        assert!(!hof.leaders[0].badges.is_empty());
        assert!(!hof.milestones.is_empty());
        assert!(hof.milestones[0].title.contains("Genesis"));
    }
}
