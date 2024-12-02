use std::collections::HashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::{enumerate_processes, Channel, MsgType, Pipe};

pub async fn run(channel: Channel<Pipe<String>>) -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:6699").await?;
    println!("Socket server running on 127.0.0.1:6699");
    // todo! restart on port in use
    loop {
        let (socket, _) = listener.accept().await?;
        tokio::spawn({
            let mut ch = channel.clone();
            async move {
                let mut buf = vec![0; 1024];
                let mut stream = tokio::io::BufReader::new(socket);
                loop {
                    let n = match stream.read(&mut buf).await {
                        Ok(n) if n == 0 => break, // Connection closed
                        Ok(n) => n,
                        Err(_) => break,
                    };

                    let request = String::from_utf8_lossy(&buf[..n]);

                    if let Some((method, path)) = parse_method_and_path(&request) {
                        if method == "POST" {
                            if let Some(body_start) = request.find("\r\n\r\n") {
                                let body = &request[(body_start + 4)..];

                                if body.len() == 0 {
                                    stream.write_all(format!(
                                            "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\n\r\nNo Script Provided!").as_bytes()).await.unwrap();
                                }

                                // Parse query

                                if let Some(query) = path.split('?').nth(1) {
                                    let params = parse_query_params(query);
                                    if let Some(app_pid) = params.get("pid") {
                                        let message = String::from(app_pid);
                                        let _ = ch
                                            .send(Pipe {
                                                msg: MsgType::Socket,
                                                payload: message.clone(),
                                            })
                                            .await;
                                    } else {
                                        stream.write_all(format!(
                                            "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\n\r\nNo Pid Provided!").as_bytes()).await.unwrap();
                                    }
                                }

                                match start_frida_bindings(0, body) {
                                    Ok((status, package)) => {
                                        stream.write_all(format!(
                                                "HTTP/1.1 {} ok\r\nContent-Type: text/plain\r\n\r\nScript Loaded in {} Successfully",
                                                status,package
                                            ).as_bytes()).await.unwrap();
                                    }
                                    Err(kind) => {
                                        stream.write_all(format!(
                                                "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\n\r\n{}",
                                                kind
                                            ).as_bytes()).await.unwrap();
                                    }
                                }
                            }
                        }
                    } else {
                        stream.write_all("ok".as_bytes()).await.unwrap();
                    }

                    let message = String::from_utf8_lossy(&buf[..n]).to_string();

                    let _ = ch.send(Pipe {
                        msg: MsgType::POST,
                        payload: message,
                    });

                    if let Some(message) = ch.receive().await {
                        println!("Received message from GG watchdog: {}", message);
                        let _ = ch
                            .send(Pipe {
                                msg: MsgType::Socket,
                                payload: (format!("")),
                            })
                            .await;
                    }
                }
            }
        });
    }
}

fn start_frida_bindings(pid: u32, script: &str) -> crate::Result<(i32, String)> {
    let device_manager = crate::DeviceManager::obtain(&crate::FRIDA);
    let local_device = device_manager.get_remote_device("localhost")?;

    let apps = enumerate_processes(&local_device)?;

    let session = local_device.attach(pid)?;

    if session.is_detached() {
        return Err(crate::error::Error::SessionDetachError);
    }

    let mut script_option = crate::script::ScriptOption::default();
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
