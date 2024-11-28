pub fn find_pkg() -> Option<String> {
    let base_dir = "/data/data/";

    match explore_app_packages(base_dir) {
        Ok(p) => return Some(p),
        Err(_) => return None,
    }
}
use std::fs;
use std::path::Path;
fn explore_app_packages(base_dir: &str) -> Result<String, std::io::Error> {
    let entries = fs::read_dir(base_dir)?;
    let mut pkg: String = String::from("");

    for entry in entries.filter_map(Result::ok) {
        let app_package = entry.file_name().into_string().unwrap_or_default();

        if app_package.starts_with('.') || app_package.is_empty() {
            continue;
        }

        let app_files_dir = Path::new(base_dir).join(&app_package).join("files");

        if !app_files_dir.exists() && !app_files_dir.is_dir() {
            continue;
        }

        if let Some(p) = traverse_files(&app_files_dir, &app_package) {
            pkg = String::from(&p);
        }
    }
    Ok(pkg)
}

fn traverse_files(dir: &Path, app_package: &str) -> Option<String> {
    let mut result: Option<String> = None;
    if !dir.exists() || !dir.is_dir() {
        return None;
    }

    let mut version_found = false;
    let mut lib_found = false;

    for entry in fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        let entry_path = entry.path();

        if entry_path.is_dir() {
            match traverse_files(&entry_path, app_package) {
                Some(p) => return Some(p),
                None => (),
            };
        } else {
            if entry_path.ends_with("version.gg") {
                version_found = true;
            }
            if entry_path.ends_with("lib01.so") {
                lib_found = true;
            }
        }

        if version_found && lib_found {
            result = Some(app_package.to_owned());
            return result;
        }
    }
    result
}

use std::process::{Command, Stdio};
pub fn get_pid(app_package: &str) -> Option<u32> {
    let output = Command::new("ps")
        .arg("-A")
        .stdout(Stdio::piped())
        .output()
        .ok()?;

    let output_str = String::from_utf8_lossy(&output.stdout);

    for line in output_str.lines() {
        if line.contains(app_package) {
            let parts: Vec<&str> = line.split_whitespace().collect();

            if let Some(pid_str) = parts.get(1) {
                if let Ok(pid) = pid_str.parse::<u32>() {
                    return Some(pid);
                }
            }
        }
    }

    None
}
