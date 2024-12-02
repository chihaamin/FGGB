use std::fmt;
use std::sync::Arc;
use tokio::sync::{
    mpsc::{self, channel, Receiver, Sender},
    Mutex,
};
#[derive(Debug, Clone)]
pub enum MsgType {
    Socket,
    Process,
    GameGuardian,
    GameGuardianGotPid,
    GameGuardianPidLost,
    Frida,
    FridaScript,
    POST,
    GET,
}
pub struct Pipe<T> {
    pub msg: MsgType,
    pub payload: T,
}
impl<T> Clone for Pipe<T>
where
    T: Clone,
{
    fn clone(&self) -> Self {
        Pipe {
            msg: self.msg.clone(),
            payload: self.payload.clone(),
        }
    }
}
impl<T> fmt::Display for Pipe<T>
where
    T: Clone + fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Pipe: Message = {:?}, Payload = {:?}",
            self.msg, self.payload
        )
    }
}
impl<T> fmt::Debug for Pipe<T>
where
    T: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.payload)
    }
}

pub struct Channel<T: Clone> {
    pub sender: Arc<Mutex<Sender<T>>>,
    pub receiver: Arc<Mutex<Receiver<T>>>,
}

impl<T> Channel<T>
where
    T: Clone + std::fmt::Debug,
{
    pub fn new(buffer_size: usize) -> Self {
        let (sender, receiver) = channel::<T>(buffer_size);
        Channel {
            sender: Arc::new(Mutex::new(sender)),
            receiver: Arc::new(Mutex::new(receiver)),
        }
    }
    pub fn from(sender: Arc<Mutex<Sender<T>>>, receiver: Arc<Mutex<Receiver<T>>>) -> Self {
        Channel { sender, receiver }
    }

    pub async fn send(&mut self, msg: T) -> Result<(), mpsc::error::SendError<T>> {
        let tx = self.sender.lock().await;
        match tx.send(msg.clone()).await {
            Ok(_) => Ok(()),
            Err(e) => {
                eprintln!("Failed to send message");
                return Err(e);
            }
        }
    }
    pub async fn receive(&mut self) -> Option<T> {
        // Lock the receiver first and immediately drop the lock
        let mut rx = self.receiver.lock().await;
        if let Some(msg) = rx.recv().await {
            return Some(msg);
        }
        None
    }
}
impl<T: Clone> Clone for Channel<T> {
    fn clone(&self) -> Self {
        Channel {
            sender: self.sender.clone(),
            receiver: self.receiver.clone(),
        }
    }
}
