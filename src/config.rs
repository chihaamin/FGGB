use serde::{Deserialize, Serialize};
use serde_json::Result;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::{env, result};

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    pub gg_package: String,
    pub path: String,
}

pub fn configure() -> Result<Config> {
    let dir = env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(|p| p.to_path_buf()))
        .expect("Failed to determine current directory");

    let json_path = dir.join("config.json");

    if Path::new(&json_path).exists() {
        let file_content = fs::read_to_string(&json_path).expect("Failed to read Config.json.");
        let config: Config = serde_json::from_str(&file_content)?;

        // Validate the deserialized configuration
        if !validate_config(&config) {
            return Ok(reconf(&json_path))?;
        }
        return Ok(config);
    }
    return Ok(reconf(&json_path))?;
}

fn reconf(json_path: &PathBuf) -> Result<Config> {
    match find_pkg() {
        Some((pkg, path)) => {
            let config = Config {
                gg_package: pkg,
                path: String::from(path.to_str().unwrap()),
            };
            let json_content =
                serde_json::to_string_pretty(&config).expect("Failed to serialize Config.json.");
            fs::write(&json_path, json_content).expect("Failed to write Config.json.");

            return Ok(config);
        }
        None => {
            return Err(serde_json::Error::io(std::io::Error::new(
                ErrorKind::Other,
                format!("Cannot create Config.json."),
            )))
        }
    }
}
fn validate_config(config: &Config) -> bool {
    !config.gg_package.is_empty() && !config.path.is_empty()
}
fn traverse_files(dir: &Path, app_package: &str) -> Option<(String, PathBuf)> {
    let mut result: Option<(String, PathBuf)> = None;
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
                Some((pkg, path)) => return Some((pkg, path)),
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
            result = Some((String::from(app_package), entry_path));
            return result;
        }
    }
    result
}
fn explore_app_packages(base_dir: &str) -> result::Result<(String, PathBuf), std::io::Error> {
    let entries = fs::read_dir(base_dir)?;
    // let mut pkg: String = String::from("");

    for entry in entries.filter_map(result::Result::ok) {
        let app_package = entry.file_name().into_string().unwrap_or_default();

        if app_package.starts_with('.') || app_package.is_empty() {
            continue;
        }

        let app_files_dir = Path::new(base_dir).join(&app_package).join("files");

        if !app_files_dir.exists() && !app_files_dir.is_dir() {
            continue;
        }

        if let Some((pkg, path)) = traverse_files(&app_files_dir, &app_package) {
            return Ok((pkg, path));
        }
    }
    Err(std::io::Error::new(
        ErrorKind::NotFound,
        format!("Cannot find Package"),
    ))
}

fn find_pkg() -> Option<(String, PathBuf)> {
    let base_dir = "/data/data/";

    match explore_app_packages(base_dir) {
        Ok((pkg, path)) => return Some((pkg, path)),
        Err(_) => return None,
    }
}
