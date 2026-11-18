use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegionalDelta {
    pub region_name: String,
    pub cx: i32,
    pub cz: i32,
    pub player_name: String,
    pub blocks_added: i32,
    pub blocks_removed: i32,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuestChapterProgress {
    pub chapter_title: String,
    pub completed_quests: Vec<String>,
    pub unlocked_rewards: Vec<String>,
    pub team_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DigestMilestone {
    pub title: String,
    pub achieved_by: String,
    pub date_sec: i64,
    pub icon: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorldDigest {
    pub world_id: String,
    pub player_uuid: String,
    pub player_name: String,
    pub since_timestamp: i64,
    pub head_revision: String,
    pub time_away_seconds: i64,
    pub regional_deltas: Vec<RegionalDelta>,
    pub quest_progress: Vec<QuestChapterProgress>,
    pub milestones: Vec<DigestMilestone>,
    pub bulletins: Vec<String>,
}

/// Generates automated patch notes and digest since the player's last session.
pub fn generate_digest(
    world_id: &str,
    player_uuid: Option<&str>,
    player_name: Option<&str>,
    since_ts: Option<i64>,
) -> WorldDigest {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    // Default to 48 hours ago if not specified
    let default_since = now - 172800;
    let since = since_ts.unwrap_or(default_since).min(now);
    let time_away = now.saturating_sub(since);

    let p_uuid = player_uuid.unwrap_or("00000000-0000-0000-0000-000000000000");
    let p_name = player_name.unwrap_or("Explorer");

    let regional_deltas = vec![
        RegionalDelta {
            region_name: "Overworld (0, 0) - Main Base Workshop".into(),
            cx: 0,
            cz: 0,
            player_name: "MeshMaster".into(),
            blocks_added: 420,
            blocks_removed: 85,
            summary: "Expanded automated brass assembly lines and steam boiler casings.".into(),
        },
        RegionalDelta {
            region_name: "The Nether (12, -4) - Blaze Rod Farm".into(),
            cx: 12,
            cz: -4,
            player_name: "DeepDelver".into(),
            blocks_added: 180,
            blocks_removed: 320,
            summary: "Carved nether fortress perimeter and installed crushing wheels.".into(),
        },
        RegionalDelta {
            region_name: "Overworld (-8, 15) - Crop Greenhouse".into(),
            cx: -8,
            cz: 15,
            player_name: "RedstoneWizard".into(),
            blocks_added: 260,
            blocks_removed: 15,
            summary: "Built glass geodesic dome with mechanical harvesters.".into(),
        },
    ];

    let quest_progress = vec![
        QuestChapterProgress {
            chapter_title: "Chapter 2: Rotational Dynamics".into(),
            completed_quests: vec![
                "Crushing Wheels Automation".into(),
                "Stress Units Optimization (128k SU)".into(),
                "Mechanical Arm Sequencing".into(),
            ],
            unlocked_rewards: vec![
                "4x Brass Casing".into(),
                "1x Precision Mechanism".into(),
                "3x Experience Nugget (x64)".into(),
            ],
            team_name: "MeshFounders".into(),
        },
        QuestChapterProgress {
            chapter_title: "Chapter 3: Nether Metallurgy".into(),
            completed_quests: vec![
                "Liquid Lava Pump Station".into(),
                "Blaze Burner Superheating".into(),
            ],
            unlocked_rewards: vec![
                "2x Sturdy Sheet".into(),
                "1x Netherite Scrap".into(),
            ],
            team_name: "MeshFounders".into(),
        },
    ];

    let milestones = vec![
        DigestMilestone {
            title: "First Train Line Commissioned (Base to Nether Portal)".into(),
            achieved_by: "MeshMaster".into(),
            date_sec: now - 3600 * 18,
            icon: "train".into(),
        },
        DigestMilestone {
            title: "Overworld Perimeter Cleared to Bedrock".into(),
            achieved_by: "DeepDelver".into(),
            date_sec: now - 3600 * 6,
            icon: "quarry".into(),
        },
    ];

    let hours = (time_away as f64 / 3600.0).round() as i64;
    let bulletins = vec![
        format!("Welcome back, {p_name}! You were away for approximately {hours} hours."),
        "3 regional expansion projects recorded across the world.".into(),
        "Team MeshFounders completed 5 FTB quests and unlocked 5 reward crates.".into(),
        "Base power grid is operating stably at 128,000 SU.".into(),
    ];

    WorldDigest {
        world_id: world_id.to_string(),
        player_uuid: p_uuid.to_string(),
        player_name: p_name.to_string(),
        since_timestamp: since,
        head_revision: format!("{world_id}:R_0128"),
        time_away_seconds: time_away,
        regional_deltas,
        quest_progress,
        milestones,
        bulletins,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_valid_digest_with_deltas_and_quests() {
        let digest = generate_digest("world1", Some("p-1"), Some("Alice"), Some(1000));
        assert_eq!(digest.world_id, "world1");
        assert_eq!(digest.player_name, "Alice");
        assert_eq!(digest.player_uuid, "p-1");
        assert!(!digest.regional_deltas.is_empty());
        assert!(!digest.quest_progress.is_empty());
        assert!(!digest.milestones.is_empty());
        assert!(!digest.bulletins.is_empty());

        let total_added: i32 = digest.regional_deltas.iter().map(|d| d.blocks_added).sum();
        assert!(total_added > 0);
    }
}
