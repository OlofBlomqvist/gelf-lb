use std::collections::HashMap;
use crate::GelfChunkedMessage;

pub struct State {
    pub chunked_messages : std::sync::Mutex<HashMap<u64,GelfChunkedMessage>>,
    pub nr_of_forwarded_messages_the_last_thirty_seconds : std::sync::RwLock<u64>,
    pub nr_of_handled_udp_packets_the_thirty_seconds : std::sync::RwLock<u64>
}