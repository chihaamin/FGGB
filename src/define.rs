use std::fmt;
use std::sync::Arc;
use tokio::sync::{
    mpsc::{self, channel, Receiver, Sender},
    Mutex,
};

pub struct Pipe<T> {
    pub msg: String, // todo! pre defined enum
    pub payload: T,  // todo! change this into a buffer for fast data transfer
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
    T: Clone + fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Pipe: Message = {}, Payload = {}",
            self.msg, self.payload
        )
    }
}

pub struct Channel<T: Clone> {
    pub sender: Arc<Mutex<Sender<Pipe<T>>>>,
    pub receiver: Arc<Mutex<Receiver<Pipe<T>>>>,
}

impl<T> Channel<T>
where
    T: Clone + fmt::Display,
{
    // Create a new Channel
    pub fn new(buffer_size: usize) -> Self {
        let (sender, receiver) = channel::<Pipe<T>>(buffer_size);
        Channel {
            sender: Arc::new(Mutex::new(sender)),
            receiver: Arc::new(Mutex::new(receiver)),
        }
    }
    pub fn from(
        sender: Arc<Mutex<Sender<Pipe<T>>>>,
        receiver: Arc<Mutex<Receiver<Pipe<T>>>>,
    ) -> Self {
        Channel { sender, receiver }
    }

    pub async fn send(&mut self, msg: Pipe<T>) -> Result<(), mpsc::error::SendError<Pipe<T>>> {
        match self.sender.lock().await.send(msg.clone()).await {
            Ok(_) => Ok(()),
            Err(e) => {
                eprintln!("Failed to send message to GameGuardian watchdog");
                return Err(e);
            }
        }
        // self.sender.send(value).await
    }
    pub async fn receive(&mut self) -> Option<Pipe<T>> {
        match self.receiver.lock().await.recv().await {
            Some(msg) => {
                println!("Received from GameGuardian watchdog: {}", msg);
                return Some(msg);
            }
            None => return None,
        }
        // self.receiver.recv().await
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
