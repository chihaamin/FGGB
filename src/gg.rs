use tokio::time::{sleep, Duration};

use crate::{
    configure, enumerate_processes, error, frida, get_pid, script, Channel, DeviceManager, Message,
    MsgType, Pipe, ScriptHandler, FRIDA,
};

#[derive(Debug, Clone)]
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

pub async fn watchdog(_channel: Channel<Pipe<String>>) -> Result<(), Box<dyn std::error::Error>> {
    println!("Watching for GameGuardian...");
    let gg: GameGuardian;
    match configure() {
        Ok(conf) => {
            gg = GameGuardian::new(conf.gg_package, conf.path, None);
            println!("{:?}", gg)
        }
        Err(e) => return Err(Box::new(e)),
    }
    let inner_channel: Channel<Pipe<Option<u32>>> = Channel::new(32);

    let watchdog = tokio::spawn({
        let mut inner_channel = inner_channel.clone();
        async move {
            loop {
                match get_pid(&gg.package).await {
                    Some(pid) => {
                        let _ = inner_channel
                            .send(Pipe {
                                msg: MsgType::GameGuardianGotPid,
                                payload: Some(pid),
                            })
                            .await;
                    }
                    None => {
                        let _ = inner_channel
                            .send(Pipe {
                                msg: MsgType::GameGuardianPidLost,
                                payload: None,
                            })
                            .await;
                    }
                }
                sleep(Duration::from_secs(1)).await;
            }
        }
    });

    let gg_frida_impl = tokio::spawn({
        let mut inner_channel = inner_channel.clone();
        let mut prev_pid: Option<u32> = None;
        async move {
            loop {
                if let Some(message) = inner_channel.receive().await {
                    match message.payload {
                        Some(pid) => {
                            if prev_pid == Some(pid) {
                                continue;
                            }
                            println!("GameGuardian@pid-{}", pid);
                            prev_pid = Some(pid);
                        }
                        None => prev_pid = None,
                    }
                } else {
                    //terminate
                    break;
                }
                sleep(Duration::from_secs(1)).await;
            }
        }
    });
    let _ = tokio::try_join!(watchdog, gg_frida_impl);
    Ok(())
}

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

    Ok(Handler)
}

struct Handler;

impl ScriptHandler for Handler {
    fn on_message(&mut self, message: &Message) {
        println!("- {:?}", message);
    }
}
