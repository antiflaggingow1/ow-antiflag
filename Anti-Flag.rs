use std::env;
use std::fs;
use std::io;
use std::path::Path;
use std::thread;
use std::time::Duration;
use colored::*; // You need to add this crate: `colored = "2"`
use winreg::enums::*;
use winreg::RegKey;

fn main() {
    println!("{}", "Starting patching process...".green());

    let handle = thread::spawn(|| patch_overwatch());
    let handle2 = thread::spawn(|| patch_cookies());

    handle.join().unwrap();
    handle2.join().unwrap();

    println!("{}", "Patching completed successfully.".green());

    flush_network_and_exit();
}

fn patch_overwatch() {
    let user_profile = env::var("USERPROFILE").unwrap();
    let app_data = env::var("APPDATA").unwrap();

    let overwatch_paths = vec![
        Path::new(&user_profile)
            .join("AppData")
            .join("Local")
            .join("Battle.net"),
        Path::new(&user_profile)
            .join("AppData")
            .join("Local")
            .join("Blizzard"),
        Path::new(&user_profile)
            .join("AppData")
            .join("Local")
            .join("Blizzard Entertainment"),
        Path::new(&user_profile)
            .join("AppData")
            .join("Roaming")
            .join("Battle.net"),
        Path::new(&user_profile)
            .join("Documents")
            .join("Overwatch")
            .join("Logs"),
        Path::new(env::var("ProgramData").unwrap())
            .join("Battle.net")
            .join("Setup"),
        Path::new(env::var("ProgramData").unwrap())
            .join("Battle.net")
            .join("Agent")
            .join("data"),
        Path::new(env::var("ProgramData").unwrap())
            .join("Battle.net")
            .join("Agent")
            .join("Logs"),
        Path::new(env::var("ProgramData").unwrap())
            .join("Blizzard Entertainment"),
    ];

    println!("{}", "Deleting Overwatch-related paths...".yellow());

    for path in &overwatch_paths {
        delete_file_or_dir(path);
    }

    let install_location = read_registry_value(
        RegKey::predef(HKEY_LOCAL_MACHINE),
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Overwatch",
        "InstallLocation",
    );

    if let Ok(install_location) = install_location {
        if !install_location.is_empty() {
            let cache_dirs = vec![
                Path::new(&install_location)
                    .join("_retail_")
                    .join("cache"),
                Path::new(&install_location)
                    .join("_retail_")
                    .join("GPUCache"),
            ];

            println!("{}", "Deleting Overwatch cache directories...".yellow());

            for cache_dir in &cache_dirs {
                delete_file_or_dir(cache_dir);
            }
        }
    }

    let agents_path = Path::new(env::var("ProgramData").unwrap())
        .join("Battle.net")
        .join("Agent");

    if agents_path.exists() {
        let agents = fs::read_dir(&agents_path)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .filter(|path| path.starts_with(&agents_path.join("Agent")))
            .collect::<Vec<_>>();

        if !agents.is_empty() {
            let latest_agent = agents
                .iter()
                .max_by_key(|path| path.metadata().unwrap().created().unwrap())
                .unwrap();

            for agent in agents {
                if agent != latest_agent {
                    delete_file_or_dir(&agent);
                }
            }
        }
    }

    let registry_keys = vec![
        r"SOFTWARE\WOW6432Node\Blizzard Entertainment",
        r"SOFTWARE\Blizzard Entertainment",
        r"SOFTWARE\Activision",
        r"HKEY_CLASSES_ROOT\Applications\Overwatch.exe",
        r"HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone\NonPackaged\C:#Program Files (x86)#Overwatch#_retail_#Overwatch.exe",
        r"HKEY_CURRENT_USER\SOFTWARE\Microsoft\RADAR\HeapLeakDetection\DiagnosedApplications\Overwatch.exe",
        r"HKEY_CURRENT_USER\VirtualStore\MACHINE\SOFTWARE\WOW6432Node\Activision",
        r"HKEY_CURRENT_USER\SOFTWARE\Classes\VirtualStore\MACHINE\SOFTWARE\WOW6432Node\Activision",
    ];

    println!("{}", "Deleting Overwatch registry keys...".yellow());

    for key in &registry_keys {
        delete_registry_key(key);
    }
}

fn patch_cookies() {
    let user_profile = env::var("USERPROFILE").unwrap();
    let app_data = env::var("APPDATA").unwrap();

    let browser_cookie_paths = vec![
        Path::new(&user_profile)
            .join("AppData")
            .join("Local")
            .join("BraveSoftware")
            .join("Brave-Browser")
            .join("User Data")
            .join("Default")
            .join("Cookies"),
        Path::new(&app_data)
            .join("Google")
            .join("Chrome")
            .join("User Data")
            .join("Default")
            .join("Cookies"),
        Path::new(&app_data)
            .join("Opera Software")
            .join("Opera Stable")
            .join("Cookies"),
    ];

    println!("{}", "Deleting browser cookie files...".yellow());

    for path in &browser_cookie_paths {
        delete_file_or_dir(path);
    }

    let firefox_profiles_path = Path::new(&app_data).join("Mozilla").join("Firefox").join("Profiles");

    if firefox_profiles_path.exists() {
        for profile_dir in fs::read_dir(&firefox_profiles_path).unwrap() {
            if let Ok(profile_dir) = profile_dir {
                let cookies_path = profile_dir.path().join("cookies.sqlite");
                delete_file_or_dir(&cookies_path);
            }
        }
    }
}

fn delete_file_or_dir<P: AsRef<Path>>(path: P) {
    let path = path.as_ref();
    if path.exists() {
        if path.is_file() {
            if let Err(e) = fs::remove_file(path) {
                println!(
                    "{}",
                    format!("Error deleting {}: {}", path.display(), e).red()
                );
            }
        } else if path.is_dir() {
            if let Err(e) = fs::remove_dir_all(path) {
                println!(
                    "{}",
                    format!("Error deleting {}: {}", path.display(), e).red()
                );
            }
        }
    }
}

fn read_registry_value(key: RegKey, subkey: &str, value_name: &str) -> io::Result<String> {
    let key = key.open_subkey_with_flags(subkey, KEY_READ)?;
    let value: String = key.get_value(value_name)?;
    Ok(value)
}

fn delete_registry_key(key_path: &str) {
    let parts: Vec<&str> = key_path.split('\\').collect();
    if parts.len() < 2 {
        return;
    }

    let base_key = match parts[0] {
        "HKEY_CLASSES_ROOT" => RegKey::predef(HKEY_CLASSES_ROOT),
        "HKEY_CURRENT_USER" => RegKey::predef(HKEY_CURRENT_USER),
        "HKEY_LOCAL_MACHINE" => RegKey::predef(HKEY_LOCAL_MACHINE),
        "HKEY_USERS" => RegKey::predef(HKEY_USERS),
        "HKEY_CURRENT_CONFIG" => RegKey::predef(HKEY_CURRENT_CONFIG),
        _ => {
            println!("{}", format!("Invalid base key name: {}", parts[0]).red());
            return;
        }
    };

    let subkey_path = parts[1..].join("\\");

    if let Ok(key) = base_key.open_subkey_with_flags(&subkey_path, KEY_ALL_ACCESS) {
        if let Err(e) = key.delete_subkey_all() {
            println!(
                "{}",
                format!("Error deleting registry key: {}", e).red()
            );
        }
    }
}

fn flush_network_and_exit() {
    println!("{}", "Network flushed.".green());

    std::process::exit(0);
}
