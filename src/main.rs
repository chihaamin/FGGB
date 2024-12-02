#[allow(clippy::all)]
mod bindings {
    include!("./bind.rs");
}
mod bind;
mod config;
mod define;
mod device;
mod device_manager;
mod error;
mod frida;
mod gg;
mod injector;
mod process;
mod script;
mod server;
mod session;
mod variant;

pub use config::*;
pub use define::*;
pub use device::*;
pub use device_manager::*;
pub use error::*;
pub use frida::*;

pub use process::*;
pub use script::*;
pub use session::*;

use std::sync::LazyLock;

static FRIDA: LazyLock<Frida> = LazyLock::new(|| unsafe { Frida::obtain() });

#[tokio::main]
async fn main() {
    let sock_channel: Channel<Pipe<String>> = define::Channel::new(32); // Channel for socket -> watchdog
    let gg_channel: Channel<Pipe<String>> = define::Channel::new(32); // Channel for watchdog -> socket

    let socket_server_handle = tokio::spawn({
        let channel = define::Channel::from(sock_channel.sender.clone(), gg_channel.receiver);

        async move {
            if let Err(e) = server::run(channel).await {
                eprintln!("Socket Server error: {}", e);
            }
        }
    });

    let gg_watchdog_handle = tokio::spawn({
        let channel = define::Channel::from(gg_channel.sender.clone(), sock_channel.receiver);

        async move {
            if let Err(e) = gg::watchdog(channel).await {
                eprintln!("GG Watchdog error: {}", e);
            }
        }
    });

    let _ = tokio::try_join!(socket_server_handle, gg_watchdog_handle);
}
