use std::net::IpAddr;
use std::net::SocketAddr;

use etherparse::ip_number;
use etherparse::Ipv4Header;
use etherparse::IpHeader;
use etherparse::Ipv6Header;
use etherparse::PacketBuilder;

pub (crate) fn build_custom_packet(source: SocketAddr, destination: SocketAddr, payload: &[u8]) -> Vec<u8> {

    let ip_header = match source.ip() {
        IpAddr::V4(source_ip) => 
            match destination.ip() {
                IpAddr::V4(dest_ip) => {
                    IpHeader::Version4(
                        Ipv4Header::new(
                            payload.len() as u16,
                            32, 
                            ip_number::UDP, 
                            source_ip.octets(),
                            dest_ip.octets()
                        ),
                        Default::default()
                    )
                },
                _ => unreachable!(),
            }        
        IpAddr::V6(source_ip) => 
            match destination.ip() {
                IpAddr::V6(dest_ip) => {
                    IpHeader::Version6(
                        Ipv6Header {
                            traffic_class: 0, // Default traffic class
                            flow_label: 0,    // Default flow label
                            payload_length: payload.len() as u16,
                            next_header: 17,  // Indicates UDP
                            hop_limit: 64,    // Typical default value for hop limit
                            source: source_ip.octets(),
                            destination: dest_ip.octets(),
                        },
                        Default::default()
                    )
                }
                _ => unreachable!(),
            }  
    };


    let builder = PacketBuilder::
        ip(ip_header)
        .udp(6666,
        destination.port());


    let mut result = Vec::<u8>::with_capacity(builder.size(payload.len()));
    builder.write(&mut result, &payload).unwrap();
    
    result
}