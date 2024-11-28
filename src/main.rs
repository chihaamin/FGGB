#[allow(clippy::all)]
mod bindings {
    include!("./bind.rs");
}

mod gg;
pub use gg::*;

mod bind;
pub use bind::*;

mod device;
pub use device::*;

mod device_manager;
pub use device_manager::*;

mod error;
pub use error::Error;

mod injector;
pub use injector::*;

mod process;
pub use process::*;

mod script;
pub use script::*;

mod session;
pub use session::*;

mod variant;
pub use variant::*;

mod frida;
pub use frida::*;
use std::collections::HashMap;
use std::sync::LazyLock;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

static FRIDA: LazyLock<Frida> = LazyLock::new(|| unsafe { Frida::obtain() });

#[tokio::main]
async fn main() -> std::io::Result<()> {
    // TCP listener
    let listener = TcpListener::bind("127.0.0.1:6699").await?;
    println!("XEKEX Server listening on http://localhost:6699");

    loop {
        let (mut socket, _addr) = listener.accept().await?;

        tokio::spawn(async move {
            let mut temp_buffer = vec![0; 1024];
            let mut buffer: Vec<u8> = Vec::new();
            match socket.read(&mut temp_buffer).await {
                Ok(n) if n == 0 => return, // Connection closed
                Ok(n) => {
                    let request = String::from_utf8_lossy(&temp_buffer[..n]);
                    if let Some(content_length) = get_content_length(&request) {
                        // extend buf
                        buffer = vec![0; content_length];
                        buffer.extend_from_slice(&temp_buffer[..=n]);

                        let mut total_read = n;
                        while total_read < content_length {
                            let additional_read =
                                socket.read(&mut buffer[total_read..]).await.unwrap_or(0);
                            if additional_read == 0 {
                                break; // End of stream
                            }
                            total_read += additional_read;
                        }
                    } else {
                        let response = format!(
                            "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\n\r\ncontent length must be specified!"
                        );
                        socket.write_all(response.as_bytes()).await.unwrap();
                    }
                    if let Some((method, path)) = parse_method_and_path(&request) {
                        if method == "POST" {
                            if let Some(body_start) = request.find("\r\n\r\n") {
                                let body = &request[(body_start + 4)..]; // Skip past the headers

                                if body.len() == 0 {
                                    let response = format!(
                                        "HTTP/1.1 500 OK\r\nContent-Type: text/plain\r\n\r\nNo Script Provided!");
                                    socket.write_all(response.as_bytes()).await.unwrap();
                                }

                                // Parse query
                                let mut pid = 0;
                                let mut gg_pkg = String::new();
                                if let Some(query) = path.split('?').nth(1) {
                                    let params = parse_query_params(query);
                                    if let Some(app_pid) = params.get("pid") {
                                        pid = String::from(app_pid).parse::<u32>().unwrap();
                                    }
                                    if let Some(pkg) = params.get("gg") {
                                        gg_pkg = String::from(pkg)
                                    } else {
                                        if let Some(pkg) = gg::find_pkg() {
                                            gg_pkg = pkg
                                        }
                                    }
                                    // for further buffer sweap
                                    let _gg_pid = gg::get_pid(&gg_pkg);
                                    // println!("{:?}", _gg_pid);
                                }

                                let response: String;
                                match start_frida_bindings(pid, body) {
                                    Ok((status, package)) => {
                                        response = format!(
                                                "HTTP/1.1 {} OK\r\nContent-Type: text/plain\r\n\r\nScript Loaded in {} Successfully",
                                                status,package
                                            );
                                    }
                                    Err(kind) => {
                                        response = format!(
                                                "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\n\r\n{}",
                                                kind
                                            );
                                    }
                                }

                                socket.write_all(response.as_bytes()).await.unwrap();
                            }
                        }
                    }
                }
                Err(e) => eprintln!("Failed to read from socket: {}", e),
            }
        });
    }
}

fn start_frida_bindings(pid: u32, script: &str) -> Result<(i32, String)> {
    let device_manager = DeviceManager::obtain(&FRIDA);
    let local_device = device_manager.get_remote_device("localhost")?;

    let apps = enumerate_processes(&local_device)?;

    let session = local_device.attach(pid)?;

    if session.is_detached() {
        return Err(error::Error::SessionDetachError);
    }

    let mut script_option = script::ScriptOption::default();
    let script = session.create_script(script, &mut script_option)?;

    script.load()?;
    /*
    todo! generate sig for successful attach instead of fancy response
    sweaping buffer in lua with frida buffer for interaction irt.
     */
    let mut package = String::new();
    if let Some((_, (_, p))) = apps.iter().enumerate().find(|(_, (num, _))| *num == pid) {
        package = String::from(p);
    }
    Ok((200, package))
}

fn enumerate_processes(device: &Device) -> Result<Vec<(u32, String)>> {
    let mut result = vec![];
    let procs;

    match device.enumerate_processes() {
        Ok(p) => procs = p,
        Err(e) => return Err(e),
    }

    for process in procs {
        result.push((process.get_pid(), String::from(process.get_name())))
    }
    Ok(result)
}

fn parse_method_and_path(request: &str) -> Option<(&str, &str)> {
    let mut parts = request.split_whitespace();
    let method = parts.next()?;
    let path = parts.next()?;
    Some((method, path))
}

fn parse_query_params(query: &str) -> HashMap<String, String> {
    query
        .split('&')
        .filter_map(|param| {
            let mut split = param.splitn(2, '=');
            let key = split.next()?.to_string();
            let value = split.next()?.to_string();
            Some((key, value))
        })
        .collect()
}

fn get_content_length(request: &str) -> Option<usize> {
    request
        .lines()
        .find(|line| line.to_lowercase().starts_with("content-length:"))
        .and_then(|line| line.split(':').nth(1))
        .and_then(|len| len.trim().parse::<usize>().ok())
}
