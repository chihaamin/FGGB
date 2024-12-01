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
    let sock_channel: Channel<String> = define::Channel::new(32); // Channel for socket -> gg watcher
    let gg_channel: Channel<String> = define::Channel::new(32); // Channel for gg watcher -> socket

    let socket_server_handle = tokio::spawn({
        let channel = define::Channel::from(sock_channel.sender.clone(), gg_channel.receiver);

        async move {
            if let Err(e) = server::run(channel).await {
                eprintln!("Socket server error: {}", e);
            }
        }
    });

    let process_watcher_handle = tokio::spawn({
        let channel = define::Channel::from(gg_channel.sender.clone(), sock_channel.receiver);

        async move {
            if let Err(e) = gg::watchdog(channel).await {
                eprintln!("GG watcher error: {}", e);
            }
        }
    });

    let _ = tokio::try_join!(socket_server_handle, process_watcher_handle);
}
