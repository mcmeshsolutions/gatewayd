use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuestNode {
    pub id: String,
    pub title: String,
    pub description: String,
    pub icon: String,
    pub chapter_id: String,
    pub x: f64,
    pub y: f64,
    pub dependencies: Vec<String>,
    pub completed: bool,
    pub completed_by: Option<String>,
    pub completed_at: Option<i64>,
    pub rewards: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuestChapter {
    pub id: String,
    pub title: String,
    pub icon: String,
    pub description: String,
    pub total_quests: i32,
    pub completed_quests: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuestTreeResponse {
    pub world_id: String,
    pub team_id: String,
    pub team_name: String,
    pub chapters: Vec<QuestChapter>,
    pub nodes: Vec<QuestNode>,
}

/// Generates interactive FTB Quest progression tree with chapters and dependencies.
pub fn generate_quest_tree(world_id: &str, team_id: Option<&str>) -> QuestTreeResponse {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let team = team_id.unwrap_or("team_mesh_01");

    let chapters = vec![
        QuestChapter {
            id: "ch_intro".into(),
            title: "Getting Started".into(),
            icon: "compass".into(),
            description: "First steps into the world and fundamental tools.".into(),
            total_quests: 3,
            completed_quests: 3,
        },
        QuestChapter {
            id: "ch_kinetics".into(),
            title: "Rotational Kinetics".into(),
            icon: "gear".into(),
            description: "Harnessing kinetic stress, gearboxes, and shafts.".into(),
            total_quests: 5,
            completed_quests: 4,
        },
        QuestChapter {
            id: "ch_steam".into(),
            title: "Steam Dynamics".into(),
            icon: "boiler".into(),
            description: "High-pressure boilers, engines, and automated power.".into(),
            total_quests: 4,
            completed_quests: 2,
        },
        QuestChapter {
            id: "ch_logistics".into(),
            title: "Trains & Logistics".into(),
            icon: "train".into(),
            description: "High-speed rail, automated track laying, and item routing.".into(),
            total_quests: 3,
            completed_quests: 1,
        },
    ];

    let nodes = vec![
        // Intro chapter
        QuestNode {
            id: "q_root".into(),
            title: "And So It Begins".into(),
            description: "Gather wood, craft an engineering manual, and establish camp.".into(),
            icon: "book".into(),
            chapter_id: "ch_intro".into(),
            x: 80.0,
            y: 160.0,
            dependencies: vec![],
            completed: true,
            completed_by: Some("MeshMaster".into()),
            completed_at: Some(now - 86400 * 5),
            rewards: vec!["3x Bread".into(), "1x Wrench".into()],
        },
        QuestNode {
            id: "q_andesite".into(),
            title: "Andesite Alloy Mastery".into(),
            description: "Combine iron or zinc nuggets with andesite to form resilient alloy.".into(),
            icon: "ingot".into(),
            chapter_id: "ch_intro".into(),
            x: 220.0,
            y: 160.0,
            dependencies: vec!["q_root".into()],
            completed: true,
            completed_by: Some("MeshMaster".into()),
            completed_at: Some(now - 86400 * 4),
            rewards: vec!["16x Andesite Alloy".into()],
        },
        QuestNode {
            id: "q_waterwheel".into(),
            title: "Water Wheel Harnessing".into(),
            description: "Channel running water around a wooden paddle wheel for continuous rotation.".into(),
            icon: "wheel".into(),
            chapter_id: "ch_intro".into(),
            x: 360.0,
            y: 160.0,
            dependencies: vec!["q_andesite".into()],
            completed: true,
            completed_by: Some("DeepDelver".into()),
            completed_at: Some(now - 86400 * 4),
            rewards: vec!["4x Shaft".into(), "2x Small Cogwheel".into()],
        },

        // Kinetics chapter
        QuestNode {
            id: "q_speed".into(),
            title: "Speed & Torque Scaling".into(),
            description: "Sequence large and small cogwheels to double rotational speed.".into(),
            icon: "cog".into(),
            chapter_id: "ch_kinetics".into(),
            x: 500.0,
            y: 100.0,
            dependencies: vec!["q_waterwheel".into()],
            completed: true,
            completed_by: Some("RedstoneWizard".into()),
            completed_at: Some(now - 86400 * 3),
            rewards: vec!["8x Large Cogwheel".into()],
        },
        QuestNode {
            id: "q_press".into(),
            title: "Mechanical Pressing".into(),
            description: "Flatten ingots into industrial sheets using a mechanical press over a depot.".into(),
            icon: "anvil".into(),
            chapter_id: "ch_kinetics".into(),
            x: 500.0,
            y: 220.0,
            dependencies: vec!["q_waterwheel".into()],
            completed: true,
            completed_by: Some("MeshMaster".into()),
            completed_at: Some(now - 86400 * 3),
            rewards: vec!["8x Iron Sheet".into(), "1x Depot".into()],
        },
        QuestNode {
            id: "q_mixer".into(),
            title: "Heated Mechanical Mixer".into(),
            description: "Stir heated copper and zinc over a blaze burner to create brass ingots.".into(),
            icon: "blaze".into(),
            chapter_id: "ch_kinetics".into(),
            x: 640.0,
            y: 220.0,
            dependencies: vec!["q_press".into()],
            completed: true,
            completed_by: Some("DeepDelver".into()),
            completed_at: Some(now - 86400 * 2),
            rewards: vec!["12x Brass Ingot".into()],
        },
        QuestNode {
            id: "q_crushing".into(),
            title: "Dual Crushing Wheels".into(),
            description: "Set up counter-rotating giant stone wheels for ore multiplication.".into(),
            icon: "crusher".into(),
            chapter_id: "ch_kinetics".into(),
            x: 640.0,
            y: 100.0,
            dependencies: vec!["q_speed".into()],
            completed: true,
            completed_by: Some("RedstoneWizard".into()),
            completed_at: Some(now - 86400 * 2),
            rewards: vec!["2x Crushing Wheel".into()],
        },
        QuestNode {
            id: "q_sequenced".into(),
            title: "Precision Mechanism Assembly".into(),
            description: "Deploy mechanical deployers and conveyor belts for automated precision assembly.".into(),
            icon: "mechanism".into(),
            chapter_id: "ch_kinetics".into(),
            x: 780.0,
            y: 160.0,
            dependencies: vec!["q_mixer".into(), "q_crushing".into()],
            completed: false,
            completed_by: None,
            completed_at: None,
            rewards: vec!["4x Precision Mechanism".into(), "1x Rotational Speed Controller".into()],
        },

        // Steam chapter
        QuestNode {
            id: "q_boiler_setup".into(),
            title: "Pressurized Steam Boiler".into(),
            description: "Encase fluid tanks with boiler heat sources and water pumps for high SU output.".into(),
            icon: "boiler".into(),
            chapter_id: "ch_steam".into(),
            x: 920.0,
            y: 100.0,
            dependencies: vec!["q_sequenced".into()],
            completed: false,
            completed_by: None,
            completed_at: None,
            rewards: vec!["1x Steam Engine".into()],
        },
        QuestNode {
            id: "q_steam_engine".into(),
            title: "Steam Engine Max Power (128k SU)".into(),
            description: "Superheat 9 blaze burners simultaneously to reach Level 9 steam capacity.".into(),
            icon: "fire".into(),
            chapter_id: "ch_steam".into(),
            x: 1060.0,
            y: 100.0,
            dependencies: vec!["q_boiler_setup".into()],
            completed: false,
            completed_by: None,
            completed_at: None,
            rewards: vec!["1x Netherite Scrap".into()],
        },

        // Logistics chapter
        QuestNode {
            id: "q_track_lay".into(),
            title: "Automated Railway Line".into(),
            description: "Assemble train station blocks and lay 500 blocks of dual-track rail.".into(),
            icon: "rails".into(),
            chapter_id: "ch_logistics".into(),
            x: 920.0,
            y: 220.0,
            dependencies: vec!["q_sequenced".into()],
            completed: false,
            completed_by: None,
            completed_at: None,
            rewards: vec!["64x Train Track".into(), "1x Train Schedule".into()],
        },
    ];

    QuestTreeResponse {
        world_id: world_id.to_string(),
        team_id: team.to_string(),
        team_name: "MeshFounders".into(),
        chapters,
        nodes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quest_tree_generates_valid_chapters_and_nodes() {
        let resp = generate_quest_tree("world1", Some("team_a"));
        assert_eq!(resp.world_id, "world1");
        assert_eq!(resp.team_id, "team_a");
        assert!(!resp.chapters.is_empty());
        assert!(!resp.nodes.is_empty());

        // Validate dependencies link to existing node IDs
        let node_ids: std::collections::HashSet<String> = resp.nodes.iter().map(|n| n.id.clone()).collect();
        for node in &resp.nodes {
            for dep in &node.dependencies {
                assert!(node_ids.contains(dep), "Dependency {} of node {} must exist", dep, node.id);
            }
        }
    }
}
