/*
 * Copyright © 2020-2022 Keegan Saunders
 * Copyright © 2022 Jean Marchand
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

//! Frida bindings for Rust.

#![allow(clippy::missing_safety_doc)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(improper_ctypes)]

#[allow(clippy::all)]
mod bindings {
    include!("./bind.rs");
}
// bind support aarch64 only!
mod bind;
pub use bind::*;
use std::ffi::CStr;

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

#[doc(hidden)]
pub type Result<T> = std::result::Result<T, error::Error>;

/// Context required for instantiation of all structures under the Frida namespace.
pub struct Frida;

impl Frida {
    /// Obtain a Frida handle, ensuring that the runtime is properly initialized. This may
    /// be called as many times as needed, and results in a no-op if the Frida runtime is
    /// already initialized.
    pub unsafe fn obtain() -> Frida {
        bind::frida_init();
        Frida {}
    }

    /// Gets the current version of frida core
    pub fn version() -> &'static str {
        let version = unsafe { CStr::from_ptr(bind::frida_version_string() as _) };
        version.to_str().unwrap_or_default()
    }

    /// Schedules the closure to be executed on the main frida context.
    pub fn schedule_on_main<F>(&self, func: F)
    where
        F: FnOnce() + Send + 'static,
    {
        unsafe {
            unsafe extern "C" fn trampoline<F: FnOnce() + Send + 'static>(
                func: bind::gpointer,
            ) -> bind::gboolean {
                let func: &mut Option<F> = &mut *(func as *mut Option<F>);
                let func = func
                    .take()
                    .expect("schedule_on_main closure called multiple times");
                func();
                bind::G_SOURCE_REMOVE as bind::gboolean
            }
            unsafe extern "C" fn destroy_closure<F: FnOnce() + Send + 'static>(
                ptr: bind::gpointer,
            ) {
                let _ = Box::<Option<F>>::from_raw(ptr as *mut _);
            }

            let func = Box::into_raw(Box::new(Some(func)));
            let source = bind::_frida_g_idle_source_new();
            let ctx = bind::frida_get_main_context();

            bind::_frida_g_source_set_callback(
                source,
                Some(trampoline::<F>),
                func as bind::gpointer,
                Some(destroy_closure::<F>),
            );
            bind::_frida_g_source_attach(source, ctx);
            bind::_frida_g_source_unref(source);
        }
    }
}

impl Drop for Frida {
    fn drop(&mut self) {
        unsafe { bind::frida_deinit() };
    }
}

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
        // Spawn a new task to handle the connection

        tokio::spawn(async move {
            // Read the buffer

            let mut buffer = vec![0; 1024];
            match socket.read(&mut buffer).await {
                Ok(n) if n == 0 => return, // Connection closed
                Ok(n) => {
                    let request = String::from_utf8_lossy(&buffer[..n]);

                    // Parse the request
                    if let Some((method, path)) = parse_method_and_path(&request) {
                        if method == "POST" {
                            if let Some(body_start) = request.find("\r\n\r\n") {
                                let body = &request[(body_start + 4)..]; // Skip past the headers

                                if body.len() == 0 {
                                    // check if we got a frida script!
                                    let response = format!(
                                        "HTTP/1.1 500 OK\r\nContent-Type: text/plain\r\n\r\nNo Script Provided!");
                                    socket.write_all(response.as_bytes()).await.unwrap();
                                }

                                // Parse query parameters (?pid=19920)
                                let mut pid = 0;
                                if let Some(query) = path.split('?').nth(1) {
                                    let params = parse_query_params(query);
                                    if let Some(app_pid) = params.get("pid") {
                                        pid = String::from(app_pid).parse::<u32>().unwrap();
                                    }
                                }

                                let response: String;
                                match start_frida_bindings(pid, body) {
                                    Some((status, package)) => {
                                        response = format!(
                                                "HTTP/1.1 {} OK\r\nContent-Type: text/plain\r\n\r\nScript Loaded in {} Successfully",
                                                status,package
                                            );
                                    }
                                    None => {
                                        response = format!(
                                                "HTTP/1.1 500 OK\r\nContent-Type: text/plain\r\n\r\nReceived target {} isn't executed yet! or got Terminated!",
                                                pid
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

fn start_frida_bindings(pid: u32, script: &str) -> Option<(i32, String)> {
    let device_manager = DeviceManager::obtain(&FRIDA);
    let local_device = device_manager.get_remote_device("localhost").unwrap();
    let apps = enumerate_processes(&local_device);
    let is_app_valid = apps.iter().any(|(num, _)| *num == pid);
    if !is_app_valid {
        None
    } else {
        let session = local_device.attach(pid).unwrap();

        if session.is_detached() {
            println!("Session is detached");
            return None;
        }

        let mut script_option = script::ScriptOption::default();
        let script = match session.create_script(script, &mut script_option) {
            Ok(s) => s,
            Err(err) => {
                println!("{}", err);
                return None;
            }
        };
        script.load().unwrap();

        let mut package = String::new();
        if let Some((_, (_, p))) = apps.iter().enumerate().find(|(_, (num, _))| *num == pid) {
            package = p.to_owned();
        }
        Some((200, package))
    }
}

fn enumerate_processes(device: &Device) -> Vec<(u32, String)> {
    let mut result = vec![];
    for procs in device.enumerate_processes() {
        result.push((procs.get_pid(), String::from(procs.get_name())))
    }
    result
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
