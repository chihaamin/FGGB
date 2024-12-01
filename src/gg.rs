use tokio::time::Duration;
#[derive(Debug)]
pub struct GameGuardian {
    pub package: String,
    pub path: String,
    pid: Option<u32>,
}
impl GameGuardian {
    fn new(package: String, path: String, pid: Option<u32>) -> Self {
        GameGuardian { package, path, pid }
    }
}

pub async fn watchdog(mut channel: Channel<String>) -> Result<(), Box<dyn std::error::Error>> {
    println!("Watching for GameGuardian...");
    let mut gg: GameGuardian;
    match configure() {
        Ok(conf) => {
            gg = GameGuardian::new(conf.gg_package, conf.path, None);
            println!("{:?}", gg)
        }
        Err(e) => return Err(Box::new(e)),
    }

    loop {
        let pid = get_pid(&gg.package).await;
        if let Some(pid) = pid {
            gg.pid = Some(pid);
            process_logic(pid).await;

            if let Err(e) = wait_for_process_to_terminate(pid).await {
                eprintln!("Error while waiting for GameGuardian termination: {}", e);
            }

            println!("GameGuardian::PID {} terminated. Resuming watchdog...", pid);
        }

        // listen for incoming data
        if let Some(message) = channel.receive().await {
            println!("Received message from socket server: {}", message);
            let _ = channel
                .send(Pipe {
                    msg: (format!("Processed message: {}", message)),
                    payload: (format!("")),
                })
                .await?;
        }

        tokio::time::sleep(Duration::from_secs(1)).await; // Polling interval
    }
}

async fn process_logic(_pid: u32) {
    todo!();
}

async fn wait_for_process_to_terminate(pid: u32) -> Result<(), Box<dyn std::error::Error>> {
    // Simulate waiting for a process to terminate
    println!("Waiting for process PID {} to terminate...", pid);

    // Replace this with actual process monitoring logic using system APIs or crates
    // This is a simulation of waiting
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Log process termination
    println!("Process PID {} has terminated.", pid);
    Ok(())
}

use crate::{
    configure, enumerate_processes, error, frida, get_pid, script, Channel, DeviceManager, Message,
    Pipe, ScriptHandler, FRIDA,
};

use std::thread;
fn invoke(pid: u32) -> frida::Result<Handler> {
    let device_manager = DeviceManager::obtain(&FRIDA);
    let local_device = device_manager.get_remote_device("localhost")?;

    let _apps = enumerate_processes(&local_device)?;

    let session = local_device.attach(pid)?;

    if session.is_detached() {
        return Err(error::Error::SessionDetachError);
    }

    let mut script_option = script::ScriptOption::default();
    let script_src = r#""#; // payload

    let mut script = session.create_script(script_src, &mut script_option)?;

    script.load()?;
    let msg_handler = script.handle_message(Handler);
    if let Err(err) = msg_handler {
        panic!("{:?}", err);
    }
    for _ in 0..2 {
        thread::sleep(Duration::from_secs(1));
        println!("{:?}", script.list_exports().unwrap());
    }

    Ok(Handler)
}

struct Handler;

impl ScriptHandler for Handler {
    fn on_message(&mut self, message: &Message) {
        println!("- {:?}", message);
    }
}
