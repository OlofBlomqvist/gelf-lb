use std::{collections::HashMap, io::Read, net::SocketAddr, time::{SystemTime, UNIX_EPOCH}};
use anyhow::Context;
use flate2::{bufread::GzDecoder, Compression};
use serde::{de::{self, Visitor}, Deserialize, Deserializer, Serialize};
use serde_json::Value;

#[derive(Serialize, Deserialize, Debug)]
pub struct GelfMessage {
    pub version: String,
    pub host: String,
    pub short_message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub full_message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>, 
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub facility: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    #[serde(deserialize_with = "deserialize_line")]
    pub line: Option<String>,
    #[serde(flatten)]
    pub additional_fields: HashMap<String, Value>,
}


// Custom deserializer for the `line` field
fn deserialize_line<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    struct StringOrNumberVisitor;

    impl<'de> Visitor<'de> for StringOrNumberVisitor {
        type Value = Option<String>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a string or a number")
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(Some(value.to_string()))
        }

        fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(Some(value.to_string()))
        }
    }

    deserializer.deserialize_any(StringOrNumberVisitor)
}

#[derive(Clone,Debug)]
// Define a struct to hold GELF packets.
pub struct GelfPacket {
    pub data: Vec<u8>,
    pub message_id: u64,
    #[allow(dead_code)]
    pub sequence_number: u8,
    #[allow(dead_code)]
    pub total_chunks: u8,
    pub source_ip: SocketAddr,
}

impl GelfPacket {
    pub fn new_chunked(
        data: Vec<u8>,
        message_id: u64,
        sequence_number: u8,
        total_chunks: u8,
        source_ip: SocketAddr,
    ) -> Self {
        GelfPacket {
            data,
            message_id,
            sequence_number,
            total_chunks,
            source_ip,
        }
    }
    pub fn new_simple(
        data: Vec<u8>,
        source_ip: SocketAddr,
    ) -> Self {
        GelfPacket {
            data,
            message_id: 0,
            sequence_number: 0,
            total_chunks: 0,
            source_ip,
        }
    }
    // https://go2docs.graylog.org/5-0/getting_in_log_data/gelf.html
    // Method to check if the packet is chunked.
    pub fn is_chunked(&self) -> bool {
        // Check if the packet starts with the specific bytes 0x1e followed by 0x0f.
        self.data.len() >= 5 && self.data[0] == 0x1e && self.data[1] == 0x0f
    }

}


// Parse GELF packet to extract message ID, sequence number, and total chunks.
pub fn parse_chunk_info(data: &[u8]) -> (u64, u8, u8) {
    if data.len() >= 12 && data[0] == 0x1e && data[1] == 0x0f {
        // Check if it's a valid chunked packet.
        let mut message_id = [0u8; 8];
        message_id.copy_from_slice(&data[2..10]); // Extract 8-byte message ID.
        let num_be = u64::from_be_bytes(message_id);
        let sequence_number = data[10]; // Sequence number is the 11th byte.
        let total_chunks = data[11]; // Total chunks count is the 12th byte.
        (num_be, sequence_number, total_chunks)
    } else {
        // Invalid chunked packet, returning None for message_id to indicate error.
        (0, 0, 0)
    }
}


#[derive(Debug,Clone)]
pub struct GelfChunkedMessage { 
    pub chunks : Vec<GelfPacket>,
    pub arrival_time : chrono::DateTime<chrono::Utc>,
    pub expected_max_chunks : usize,
    pub id : u64
}
impl GelfChunkedMessage {
    pub fn new(initial_packet:GelfPacket) -> Self {
        Self {
            id: initial_packet.message_id,
            arrival_time: chrono::Utc::now(),
            expected_max_chunks: initial_packet.total_chunks as usize,
            chunks: vec![initial_packet],            
        }
    }
    pub fn age_in_seconds(&self) -> i64 {
        (chrono::Utc::now() - self.arrival_time).num_seconds()
    }
    
    pub fn is_complete(&self) -> bool {
        self.chunks.len() >= self.expected_max_chunks
    }
}

#[derive(Debug)]
pub enum GelfMessageWrapper {
    Chunked(GelfChunkedMessage),
    Simple(GelfPacket)
}

fn calculate_packet_sizes(total_size: usize, max_packet_size: usize) -> (usize, Vec<usize>) {
    let number_of_full_packets = total_size / max_packet_size;
    let remaining_bytes = total_size % max_packet_size;
    let number_of_packets = if remaining_bytes > 0 {
        number_of_full_packets + 1
    } else {
        number_of_full_packets
    };

    let mut packet_sizes = vec![max_packet_size; number_of_full_packets];
    if remaining_bytes > 0 {
        packet_sizes.push(remaining_bytes);
    }

    (number_of_packets, packet_sizes)
}

fn create_packets(data: &[u8], packet_sizes: Vec<usize>, id: u64) -> Vec<Vec<u8>> {
    
    let mut packets = Vec::new();
    let mut start = 0;
    for (index,&size) in packet_sizes.iter().enumerate() {
        let end = start + size;
        let mut packet = vec![0x1e,0x0f]; // add magic to mark that this is a chunked package (2 bytes)
        packet.extend_from_slice(&id.to_be_bytes()); // add message id (8 bytes)
        packet.push(index as u8);
        packet.push(packet_sizes.len() as u8);
        packet.extend_from_slice(&data[start..end]);
        packets.push(packet);
        start = end;
    }

    packets
}

// silly little method for generating psuedo-random message ids for chunking
fn generate_message_id() -> u64 {
    let mut message_id = [0u8; 8];
    message_id[0] = b'G';
    message_id[1] = b'L';
    message_id[2] = b'B';
    if let Ok(duration) = SystemTime::now().duration_since(UNIX_EPOCH) {
        let nanos = duration.as_nanos();
        // Take the least significant 5 bytes of the nanoseconds
        // and place them into the message_id array starting at index 3
        for i in 0..5 {
            message_id[3 + i] = (nanos >> (i * 8) & 0xff) as u8;
        }
    }
    u64::from_be_bytes(message_id)
}


fn gzip_compress(bytes: &[u8]) -> std::io::Result<Vec<u8>> {
    use flate2::write::GzEncoder;
    let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
    std::io::Write::write_all(&mut encoder, bytes)?;
    encoder.finish()
}

#[allow(dead_code)]
fn gzip_decompress(compressed_bytes: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut decoder = GzDecoder::new(compressed_bytes);
    let mut buf = Vec::new();
    decoder.read_to_end(&mut buf)?;
    Ok(buf)
}

impl GelfMessageWrapper {

    pub fn set_payload(&mut self,new_payload_msg:GelfMessage,config:&crate::Configuration) {


        let serialized = serde_json::to_string(&new_payload_msg).map_err(|e|format!("{e:?}")).expect("should always be possible to serialize gelfmsg");
        let json_bytes = serialized.into_bytes();

        let use_gzip = config.use_gzip.unwrap_or_default(); 
        let mut compressed_bytes : Option<Vec<u8>> = None;
        
        if use_gzip {
           let zips = gzip_compress(&json_bytes).expect("should always be possible to gzip the payload..");
           compressed_bytes = Some(zips);
        };

        // keep pointing to the original byte array unless using compression
        let bytes = match &compressed_bytes {
            Some(x) => x,
            None => &json_bytes,
        };

        // we only ever do this internal re-chunking if we have modified the payload of a message,
        // otherwise we just forward the message (chunked or not) as is.

        // when we chunk, we just do it with safe upper bounds so that we can be sure that our chunks are below the set limits
        // configured in the settings.

        let udp_hdr_size = 8; // Source Port (16 bits),Destination Port (16 bits),Length (16 bits),Checksum (16 bits)
        let ip_hdr_size = 60; // ipv6 is 40 and ipv4 ranges between 20-60, so we just pick the safe value here.
        let payload_size = bytes.len();
        let total = payload_size + ip_hdr_size + udp_hdr_size; // [ IP [ UDP [ PAYLOAD ]]] | full size

        // todo: make configurable
        let max_allowed_packet_size = config.chunk_size as usize; // Maximum size of each packet in bytes

        if total > max_allowed_packet_size {
           
            // each byte is allowed to be max_allowed_packet_size minus 12 bytes for the gelf chunk header, 68 for udp and ip headers
            let (number_of_packets, packet_sizes) = calculate_packet_sizes(bytes.len(), max_allowed_packet_size - 68 - 12);
        
            //log::trace!("we need to chunk this message of {total} bytes in to {number_of_packets} chunks ({packet_sizes:?})");

            let pkg_id = self.pkg_id().unwrap_or_else(||generate_message_id()); // todo: if the package was not originally chunked, we wont have an id and we should generate one
            let pkg_src = self.pkg_src();
            let pkg_arrival_time = chrono::Utc::now();

            let data_for_each_pkg = create_packets(&bytes,packet_sizes, pkg_id );


            let packets : Vec<GelfPacket> = data_for_each_pkg.into_iter().enumerate().map(|(i,bytes)| 
                GelfPacket::new_chunked(bytes, pkg_id, i as u8, number_of_packets as u8, pkg_src)
            ).collect();
            *self = GelfMessageWrapper::Chunked(GelfChunkedMessage { id: pkg_id, chunks: packets, arrival_time: pkg_arrival_time, expected_max_chunks: number_of_packets});
           

        } else {
            log::trace!("we do not need to chunk this message as it is only going to be {} bytes in total",total);
            *self = GelfMessageWrapper::Simple(GelfPacket::new_simple(bytes.to_vec(), self.pkg_src()))
        }

    }

    pub fn pkg_id(&self) -> Option<u64> {
        match self {
            GelfMessageWrapper::Chunked(x) => Some(x.id),
            GelfMessageWrapper::Simple(_) => None,
        }
    }

    pub fn pkg_src(&self) -> SocketAddr {
        match self {
            GelfMessageWrapper::Chunked(x) => x.chunks[0].source_ip,
            GelfMessageWrapper::Simple(x) => x.source_ip,
        }
    }

    pub fn is_chunked(&self) -> bool {
        match self {
            GelfMessageWrapper::Chunked(_) => true,
            GelfMessageWrapper::Simple(_) => false,
        }
    }

    pub fn is_complete(&self) -> bool {
           
        match self {
            GelfMessageWrapper::Chunked(x) => {
                x.is_complete()
            },
            _ => true,
        }

    }


    pub fn get_payload(&self) -> anyhow::Result<GelfMessage> {

        let payload = match self {
            GelfMessageWrapper::Chunked(chunk_info) => {
                let mut s = vec![];
                for pkg in &chunk_info.chunks {
                    let payload = pkg.data[12..].to_vec();
                    s.extend_from_slice(&payload);
                }
                Self::convert_payload_to_utf8_string(&s)

            },
            GelfMessageWrapper::Simple(pkg) => Self::convert_payload_to_utf8_string(&pkg.data).context("failed to decode packet as gelf json")
        }?;

        let result = serde_json::from_str::<GelfMessage>(&payload).context("failed to parse payload json as gelfmessage")?;
        
        Ok(result)
        
    }

    fn convert_payload_to_utf8_string(payload_bytes:&[u8]) -> anyhow::Result<String> {
        
        let is_gzipped = payload_bytes.len() > 3 && payload_bytes[0] == 0x1F && payload_bytes[1] == 0x8B;
        
        if is_gzipped {
            let mut decoder = GzDecoder::new(&*payload_bytes);
            let mut json_data = String::new();
            decoder.read_to_string(&mut json_data).context("failed to read gzipped data")?;
            Ok(json_data)
        } else {
            let json_data = serde_json::from_slice(&payload_bytes)?;
            Ok(json_data)
        }

    }

    

}