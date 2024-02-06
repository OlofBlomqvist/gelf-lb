use std::collections::HashMap;
use crate::GelfChunkedMessage;

#[derive(Debug)]
pub struct State {
    pub chunked_messages : std::sync::Mutex<HashMap<u64,GelfChunkedMessage>>,
    pub nr_of_forwarded_messages : std::sync::RwLock<u64>,
    pub nr_of_handled_udp_packets : std::sync::RwLock<u64>,
    pub otf_massage_required: bool
}