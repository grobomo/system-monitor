use colored::Colorize;
use serde::Serialize;
use std::path::Path;

#[derive(Debug, Clone, Serialize)]
pub struct DiskReport {
    pub drives: Vec<DriveInfo>,
    pub projects: Vec<ProjectDiskUsage>,
    pub suggestions: Vec<CleanupSuggestion>,
    pub scanned_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DriveInfo {
    pub letter: String,
    pub total_gb: f64,
    pub free_gb: f64,
    pub used_percent: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProjectDiskUsage {
    pub name: String,
    pub path: String,
    pub size_mb: f64,
    pub has_git: bool,
    pub node_modules_mb: Option<f64>,
    pub target_mb: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CleanupSuggestion {
    pub path: String,
    pub size_mb: f64,
    pub category: String, // "safe" | "review"
    pub reason: String,
}

/// Generate a full disk report.
pub fn scan() -> DiskReport {
    let drives = scan_drives();
    let (projects, suggestions) = scan_projects();
    let scanned_at = chrono::Local::now()
        .format("%Y-%m-%d %H:%M:%S")
        .to_string();

    DiskReport {
        drives,
        projects,
        suggestions,
        scanned_at,
    }
}

/// Display disk report to terminal.
pub fn show_disk_status() {
    let report = scan();

    println!("{}", "=== Disk Monitor ===".bold());
    println!();

    // Drive space
    println!("{}", "Drive Space:".bold());
    for d in &report.drives {
        let bar = usage_bar(d.used_percent);
        let color = if d.used_percent > 90.0 {
            "red"
        } else if d.used_percent > 75.0 {
            "yellow"
        } else {
            "green"
        };
        let pct_str = format!("{:.1}%", d.used_percent);
        let pct_colored = match color {
            "red" => pct_str.red().bold().to_string(),
            "yellow" => pct_str.yellow().to_string(),
            _ => pct_str.green().to_string(),
        };
        println!(
            "  {}:  {} {:.1} GB free / {:.1} GB total  {}",
            d.letter.bold(),
            bar,
            d.free_gb,
            d.total_gb,
            pct_colored,
        );
    }
    println!();

    // Top projects by size
    if !report.projects.is_empty() {
        println!("{}", "Projects by size (top 15):".bold());
        let mut sorted = report.projects.clone();
        sorted.sort_by(|a, b| b.size_mb.partial_cmp(&a.size_mb).unwrap_or(std::cmp::Ordering::Equal));
        for p in sorted.iter().take(15) {
            let size_str = if p.size_mb >= 1024.0 {
                format!("{:.1} GB", p.size_mb / 1024.0)
            } else {
                format!("{:.0} MB", p.size_mb)
            };
            let extras = build_extras(p);
            println!(
                "  {:>8}  {}{}",
                size_str.white(),
                p.name.cyan(),
                if extras.is_empty() {
                    String::new()
                } else {
                    format!("  ({})", extras.dimmed())
                },
            );
        }
        println!();
    }

    // Cleanup suggestions
    if !report.suggestions.is_empty() {
        println!("{}", "Cleanup suggestions:".bold());
        for s in &report.suggestions {
            let size_str = if s.size_mb >= 1024.0 {
                format!("{:.1} GB", s.size_mb / 1024.0)
            } else {
                format!("{:.0} MB", s.size_mb)
            };
            let icon = if s.category == "safe" {
                "SAFE".green().to_string()
            } else {
                "REVIEW".yellow().to_string()
            };
            println!(
                "  [{}] {:>8}  {} — {}",
                icon,
                size_str,
                s.path.dimmed(),
                s.reason,
            );
        }
        println!();
        println!(
            "{}",
            "  (Advisory only — no files will be deleted automatically)"
                .dimmed()
        );
    } else {
        println!("{}", "No cleanup suggestions.".green());
    }
}

fn build_extras(p: &ProjectDiskUsage) -> String {
    let mut parts = Vec::new();
    if let Some(nm) = p.node_modules_mb {
        if nm > 1.0 {
            parts.push(format!("node_modules: {:.0}MB", nm));
        }
    }
    if let Some(t) = p.target_mb {
        if t > 1.0 {
            parts.push(format!("target/: {:.0}MB", t));
        }
    }
    if !p.has_git {
        parts.push("no git".to_string());
    }
    parts.join(", ")
}

// ─── Drive scanning ───────────────────────────────────────────────────

fn scan_drives() -> Vec<DriveInfo> {
    let mut drives = Vec::new();

    // Check common drive letters
    for letter in b'C'..=b'Z' {
        let root = format!("{}:\\", letter as char);
        let root_wide: Vec<u16> = root.encode_utf16().chain(std::iter::once(0)).collect();

        unsafe {
            let mut free_bytes: u64 = 0;
            let mut total_bytes: u64 = 0;

            let ok = windows::Win32::Storage::FileSystem::GetDiskFreeSpaceExW(
                windows::core::PCWSTR(root_wide.as_ptr()),
                None,
                Some(&mut total_bytes),
                Some(&mut free_bytes),
            );

            if ok.is_ok() && total_bytes > 0 {
                let total_gb = total_bytes as f64 / (1024.0 * 1024.0 * 1024.0);
                let free_gb = free_bytes as f64 / (1024.0 * 1024.0 * 1024.0);
                let used_percent = ((total_gb - free_gb) / total_gb * 100.0 * 10.0).round() / 10.0;

                drives.push(DriveInfo {
                    letter: format!("{}:", letter as char),
                    total_gb: (total_gb * 10.0).round() / 10.0,
                    free_gb: (free_gb * 10.0).round() / 10.0,
                    used_percent,
                });
            }
        }
    }

    drives
}

fn usage_bar(percent: f64) -> String {
    let filled = (percent / 5.0).round() as usize;
    let empty = 20usize.saturating_sub(filled);
    let bar = format!("[{}{}]", "#".repeat(filled), "-".repeat(empty));
    if percent > 90.0 {
        bar.red().to_string()
    } else if percent > 75.0 {
        bar.yellow().to_string()
    } else {
        bar.green().to_string()
    }
}

// ─── Project scanning ─────────────────────────────────────────────────

fn scan_projects() -> (Vec<ProjectDiskUsage>, Vec<CleanupSuggestion>) {
    let projects_dir = dirs::home_dir()
        .map(|h| h.join("Documents").join("ProjectsCL1"))
        .unwrap_or_default();

    if !projects_dir.exists() {
        return (Vec::new(), Vec::new());
    }

    let mut projects = Vec::new();
    let mut suggestions = Vec::new();

    // Scan top-level and one level of org dirs (e.g. _grobomo/*, _tmemu/*)
    let entries = match std::fs::read_dir(&projects_dir) {
        Ok(e) => e,
        Err(_) => return (Vec::new(), Vec::new()),
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }

        let name = entry.file_name().to_string_lossy().to_string();

        // If it starts with _ it's an org dir — scan children
        if name.starts_with('_') {
            if let Ok(children) = std::fs::read_dir(&path) {
                for child in children.flatten() {
                    let child_path = child.path();
                    if !child_path.is_dir() {
                        continue;
                    }
                    let child_name = format!(
                        "{}/{}",
                        name,
                        child.file_name().to_string_lossy()
                    );
                    let (proj, sugs) = scan_single_project(&child_path, &child_name);
                    projects.push(proj);
                    suggestions.extend(sugs);
                }
            }
        } else {
            let (proj, sugs) = scan_single_project(&path, &name);
            projects.push(proj);
            suggestions.extend(sugs);
        }
    }

    (projects, suggestions)
}

fn scan_single_project(
    path: &Path,
    name: &str,
) -> (ProjectDiskUsage, Vec<CleanupSuggestion>) {
    let mut suggestions = Vec::new();

    let has_git = path.join(".git").exists();

    // Check node_modules
    let nm_path = path.join("node_modules");
    let node_modules_mb = if nm_path.exists() {
        let size = dir_size_fast(&nm_path);
        let mb = size as f64 / (1024.0 * 1024.0);
        if mb > 100.0 {
            suggestions.push(CleanupSuggestion {
                path: nm_path.to_string_lossy().to_string(),
                size_mb: (mb * 10.0).round() / 10.0,
                category: "safe".to_string(),
                reason: "node_modules can be reinstalled with npm install".to_string(),
            });
        }
        Some((mb * 10.0).round() / 10.0)
    } else {
        None
    };

    // Check Rust target/
    let target_path = path.join("target");
    let target_mb = if target_path.exists() && path.join("Cargo.toml").exists() {
        let size = dir_size_fast(&target_path);
        let mb = size as f64 / (1024.0 * 1024.0);
        if mb > 200.0 {
            suggestions.push(CleanupSuggestion {
                path: target_path.to_string_lossy().to_string(),
                size_mb: (mb * 10.0).round() / 10.0,
                category: "safe".to_string(),
                reason: "Rust target/ can be rebuilt with cargo build".to_string(),
            });
        }
        Some((mb * 10.0).round() / 10.0)
    } else {
        None
    };

    // Check .venv / venv
    for venv_name in &[".venv", "venv"] {
        let venv_path = path.join(venv_name);
        if venv_path.exists() {
            let size = dir_size_fast(&venv_path);
            let mb = size as f64 / (1024.0 * 1024.0);
            if mb > 50.0 {
                suggestions.push(CleanupSuggestion {
                    path: venv_path.to_string_lossy().to_string(),
                    size_mb: (mb * 10.0).round() / 10.0,
                    category: "review".to_string(),
                    reason: "Python venv — recreatable if requirements.txt exists".to_string(),
                });
            }
        }
    }

    // Total project size (quick estimate: sum immediate children sizes)
    let total_size = dir_size_fast(path);
    let size_mb = (total_size as f64 / (1024.0 * 1024.0) * 10.0).round() / 10.0;

    let proj = ProjectDiskUsage {
        name: name.to_string(),
        path: path.to_string_lossy().to_string(),
        size_mb,
        has_git,
        node_modules_mb,
        target_mb,
    };

    (proj, suggestions)
}

/// Fast directory size calculation — walks directory tree, sums file sizes.
/// Skips symlinks and junctions to avoid infinite loops.
fn dir_size_fast(path: &Path) -> u64 {
    let mut total: u64 = 0;
    let mut stack = vec![path.to_path_buf()];

    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };

        for entry in entries.flatten() {
            let ft = match entry.file_type() {
                Ok(ft) => ft,
                Err(_) => continue,
            };

            if ft.is_file() {
                if let Ok(meta) = entry.metadata() {
                    total += meta.len();
                }
            } else if ft.is_dir() {
                // Skip junctions/symlinks
                stack.push(entry.path());
            }
            // Skip symlinks (ft.is_symlink()) — file_type() already resolves
        }
    }

    total
}

// ─── Guard integration ────────────────────────────────────────────────

/// Check for low disk space. Returns drives below threshold (10% free).
pub fn check_disk_for_guard() -> Vec<DriveInfo> {
    scan_drives()
        .into_iter()
        .filter(|d| (100.0 - d.used_percent) < 10.0)
        .collect()
}
