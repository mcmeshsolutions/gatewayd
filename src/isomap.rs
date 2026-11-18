use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SunLighting {
    pub azimuth: f32,
    pub elevation: f32,
    pub light_color: [f32; 3],
    pub ambient_color: [f32; 3],
    pub time_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsoChunk {
    pub cx: i32,
    pub cz: i32,
    // [rx, y, rz, palette_idx, ao_level]
    pub voxels: Vec<[i32; 5]>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsoMapData {
    pub world_id: String,
    pub revision: String,
    pub sun: SunLighting,
    pub chunks: Vec<IsoChunk>,
    pub palette: Vec<String>,
}

/// Computes directional sun and ambient lighting based on Minecraft time-of-day (0..24000 ticks).
pub fn calculate_sun(time_of_day: i64, custom_angle: Option<f32>) -> SunLighting {
    let t = (time_of_day % 24000 + 24000) % 24000;

    let (azimuth, elevation, light_color, ambient_color, time_name) = match t {
        // Dawn / Sunrise (23000..1000)
        23000..=24000 | 0..=1000 => {
            let az = custom_angle.unwrap_or(85.0);
            (
                az,
                15.0,
                [1.0, 0.65, 0.35],
                [0.22, 0.24, 0.35],
                "Dawn / Sunrise".to_string(),
            )
        }
        // Morning (1001..5000)
        1001..=5000 => {
            let az = custom_angle.unwrap_or(135.0);
            (
                az,
                45.0,
                [1.0, 0.95, 0.75],
                [0.28, 0.32, 0.45],
                "Morning".to_string(),
            )
        }
        // Midday / Noon (5001..7000)
        5001..=7000 => {
            let az = custom_angle.unwrap_or(180.0);
            (
                az,
                75.0,
                [1.0, 0.98, 0.92],
                [0.35, 0.40, 0.50],
                "Midday / Noon".to_string(),
            )
        }
        // Afternoon (7001..11000)
        7001..=11000 => {
            let az = custom_angle.unwrap_or(225.0);
            (
                az,
                45.0,
                [1.0, 0.88, 0.65],
                [0.30, 0.32, 0.42],
                "Afternoon".to_string(),
            )
        }
        // Golden Hour / Sunset (11001..13000)
        11001..=13000 => {
            let az = custom_angle.unwrap_or(270.0);
            (
                az,
                12.0,
                [1.0, 0.48, 0.22],
                [0.25, 0.20, 0.35],
                "Golden Hour / Sunset".to_string(),
            )
        }
        // Dusk / Twilight (13001..14500)
        13001..=14500 => {
            let az = custom_angle.unwrap_or(285.0);
            (
                az,
                2.0,
                [0.55, 0.35, 0.55],
                [0.15, 0.16, 0.28],
                "Dusk / Twilight".to_string(),
            )
        }
        // Night / Midnight (14501..22999)
        _ => {
            let az = custom_angle.unwrap_or(0.0);
            (
                az,
                65.0,
                [0.22, 0.32, 0.58], // Cool blue moonlight
                [0.08, 0.10, 0.18],
                "Night / Midnight".to_string(),
            )
        }
    };

    SunLighting {
        azimuth,
        elevation,
        light_color,
        ambient_color,
        time_name,
    }
}

/// Generates isometric voxel data with ambient occlusion.
pub fn generate_isomap(
    world_id: &str,
    revision: &str,
    center_cx: i32,
    center_cz: i32,
    radius: i32,
    time_of_day: i64,
    sun_angle: Option<f32>,
    ao_enabled: bool,
) -> IsoMapData {
    let sun = calculate_sun(time_of_day, sun_angle);
    let r = radius.clamp(1, 8);

    let palette = vec![
        "minecraft:grass_block".to_string(),
        "minecraft:stone".to_string(),
        "minecraft:dirt".to_string(),
        "minecraft:water".to_string(),
        "minecraft:sand".to_string(),
        "minecraft:oak_planks".to_string(),
        "minecraft:cobblestone".to_string(),
        "minecraft:glass".to_string(),
        "minecraft:lantern".to_string(),
        "create:andesite_casing".to_string(),
    ];

    let mut chunks = Vec::new();
    for dz in -r..=r {
        for dx in -r..=r {
            let cx = center_cx + dx;
            let cz = center_cz + dz;
            let mut voxels = Vec::new();

            for rx in 0..16 {
                for rz in 0..16 {
                    let wx = cx * 16 + rx;
                    let wz = cz * 16 + rz;

                    // Deterministic height profile with hills and base structures
                    let h1 = ((wx as f64 * 0.08).sin() * 5.0) as i32;
                    let h2 = ((wz as f64 * 0.08).cos() * 5.0) as i32;
                    let y = 64 + h1 + h2;

                    // Choose material based on location and height
                    let p_idx = if wx.abs() < 12 && wz.abs() < 12 {
                        // Central base area
                        if (wx + wz).abs() % 4 == 0 {
                            9 // andesite casing
                        } else if (wx - wz).abs() % 3 == 0 {
                            5 // oak planks
                        } else {
                            6 // cobblestone
                        }
                    } else if y <= 62 {
                        3 // water
                    } else if y == 63 {
                        4 // sand
                    } else if (wx * 7 + wz * 13).abs() % 17 == 0 {
                        1 // stone outcrop
                    } else {
                        0 // grass block
                    };

                    // Ambient occlusion calculation (0..3):
                    // Crevices with higher surrounding ground have darker occlusion
                    let ao = if ao_enabled {
                        let n_h1 = (((wx + 1) as f64 * 0.08).sin() * 5.0) as i32;
                        let n_h2 = (((wz + 1) as f64 * 0.08).cos() * 5.0) as i32;
                        let neighbor_y = 64 + n_h1 + n_h2;
                        if neighbor_y > y {
                            1 // shaded crevice
                        } else if neighbor_y == y {
                            2 // slight occlusion
                        } else {
                            3 // open sunlit face
                        }
                    } else {
                        3
                    };

                    voxels.push([rx, y, rz, p_idx, ao]);
                }
            }

            chunks.push(IsoChunk { cx, cz, voxels });
        }
    }

    IsoMapData {
        world_id: world_id.to_string(),
        revision: revision.to_string(),
        sun,
        chunks,
        palette,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sun_lighting_calculates_all_day_phases() {
        let dawn = calculate_sun(0, None);
        assert_eq!(dawn.time_name, "Dawn / Sunrise");
        assert!(dawn.light_color[0] > 0.9);

        let noon = calculate_sun(6000, None);
        assert_eq!(noon.time_name, "Midday / Noon");
        assert_eq!(noon.elevation, 75.0);

        let sunset = calculate_sun(12000, None);
        assert_eq!(sunset.time_name, "Golden Hour / Sunset");

        let midnight = calculate_sun(18000, None);
        assert_eq!(midnight.time_name, "Night / Midnight");
        assert!(midnight.light_color[2] > midnight.light_color[0]); // blue moonlight
    }

    #[test]
    fn isomap_generates_chunks_with_ao() {
        let data = generate_isomap("world1", "rev1", 0, 0, 1, 6000, None, true);
        assert_eq!(data.chunks.len(), 9); // (2*1 + 1)^2 = 9 chunks
        let ch = &data.chunks[0];
        assert_eq!(ch.voxels.len(), 256); // 16x16 voxels
        for v in &ch.voxels {
            assert!(v[4] >= 0 && v[4] <= 3, "AO level must be in 0..3");
        }
    }
}
