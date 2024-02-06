use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket};
use anyhow::Context;
use serde_json::Value;

use crate::{send_raw, GelfMessageWrapper, GelfPacket};


// for chunked messages we always should select the same backend for each chunk
fn select_backend(backends: &[SocketAddr], value: u64) -> &SocketAddr {
    // Calculate the segment size based on the number of backends
    let segment_size = u8::MAX as usize / backends.len();
    // Calculate the index of the backend based on the value
    let index = (value as usize) / segment_size;
    // Clamp the index to the range of the backends vector to avoid going out of bounds
    let clamped_index = index.min(backends.len() - 1);
    &backends[clamped_index]
}


pub fn balancer(state: std::sync::Arc<crate::State>,config:std::sync::Arc<crate::Configuration>,receiver: std::sync::mpsc::Receiver<GelfMessageWrapper>,backends: Vec<SocketAddr>) {
    
    let mut backend_cycle = backends.iter().cycle();
    let normal_sender_socket_v4 : UdpSocket = UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(std::net::Ipv4Addr::UNSPECIFIED,0))).unwrap();
    let normal_sender_socket_v6 : UdpSocket = UdpSocket::bind(SocketAddr::V6(SocketAddrV6::new(std::net::Ipv6Addr::UNSPECIFIED,0, 0, 0))).unwrap();
    
    loop {

        let mut packet = receiver.recv().expect("Failed to receive packet");

        // if we do not need to do any modification to messages in flight, we can just pass on any packet without temp storage
        if state.otf_massage_required {
            if let GelfMessageWrapper::Chunked(mut chunked_pkg) = packet {
                let mut guard = state.chunked_messages.lock().unwrap();
                let existing_info = guard.get_mut(&chunked_pkg.id);
                
                if let Some(old) = existing_info {  
                    old.chunks.push(chunked_pkg.chunks.remove(0));
                    if old.is_complete() == false {
                        // we added the chunk to our existing info about this message, but we are still waiting for more chunks
                        continue
                    }
                } else {
                    // this is the first chunk we see for this message, so we can continue after adding it to the state.
                    guard.insert(chunked_pkg.id, chunked_pkg);
                    continue
                }
                // here we now know that we have all chunks that we expected to see for this message..
                // lets remove it from the state and pass it on to the next step
                let (_,completed_chunked_pkg) = guard.remove_entry(&chunked_pkg.id).expect("failed to remove chunk entry prior to step 2. this is a bug in gelflb.");
                packet = GelfMessageWrapper::Chunked(completed_chunked_pkg)
            } 
        }

        let selected_backend_socket = if packet.is_chunked() {
            if let Some(pkg_id) = packet.pkg_id() {
                Some(select_backend(&backends,pkg_id))
            } else {
                log::warn!("We received a chunked message with no id. this should not be possible..");
                None
            }         
        } else {
            Some(backend_cycle.next().unwrap())
        };

        if let Some(backend) = selected_backend_socket {
            match massage(&state,&config,&mut packet) {
                Ok(()) => {
                    match forward(&config,&packet, backend,&normal_sender_socket_v4,&normal_sender_socket_v6) {
                        Ok(()) =>

                            match packet {
                                GelfMessageWrapper::Chunked(msg) => {
                                    let chunk_count = msg.chunks.len();
                                    // if this is a complete gathering of packets in a chunk we count it as a single message
                                    if chunk_count > 1 {
                                        state.nr_of_forwarded_messages.write().and_then(|mut x|Ok(*x=*x+1))
                                            .expect("should always be possible to increment fwd count");
                                    }
                                    // if this is forwarded as-is without temp storage, we will only have a single incomplete chunk here,
                                    // and so we will only log this as a message for a single one of the packets/chunks of this message 
                                    else if chunk_count == 1 {
                                        if msg.chunks[0].sequence_number == 0 {
                                            state.nr_of_forwarded_messages.write().and_then(|mut x|Ok(*x=*x+1))
                                            .expect("should always be possible to increment fwd count");
                                        }
                                    }
                                    // this is just not supposed to be possible  
                                    else {
                                        panic!("there is a bug in gelflb: forwarding of a chunked packed failed due to it having 0 or less packets: {:?}",msg)
                                    }
                                },
                                GelfMessageWrapper::Simple(_) => {
                                    state.nr_of_forwarded_messages.write().and_then(|mut x|Ok(*x=*x+1))
                                        .expect("should always be possible to increment fwd count");
                                },
                            }
                            
                        Err(e) => 
                            log::error!("failed to forward a message - at least one packet was not sent! {e}.")
                    }
                },
                Err(msg) => eprintln!("packet massage failure: {msg}")
            }
        }
    }

}


fn massage(state: &crate::State,config:&crate::Configuration,packet: &mut GelfMessageWrapper) -> anyhow::Result<()> {
    
    if state.otf_massage_required == false { 
        log::trace!("massaging is disabled, sub-routine bypassed");
        return Ok (())
     }
    
    log::trace!("massaging a packet");

    let mut j = packet.get_payload()?;
   
    let src_key = "_gelflb_original_source_addr";
    if config.attach_source_info {
        if !j.additional_fields.contains_key(src_key) {
            log::trace!("attaching {src_key} field to a message.");
            j.additional_fields.extend(vec![(src_key.into(), Value::from(packet.pkg_src().ip().to_string()))]);
        }
    }

    if config.strip_fields.len() > 0 {
        log::trace!("making sure to strip these fields from a message: {:?}",config.strip_fields);
        j.additional_fields.retain(|x,_|!config.strip_fields.contains(&format!("_{x}")));
    }
    
    for bad_key in &config.blank_fields {
        if let Some(baddy) = j.additional_fields.get_mut(&format!("_{bad_key}")) {
            log::trace!("masking the following key in a message: {}",bad_key);
            if baddy.is_string() { 
                *baddy = "******".into();
            }
        }
    }

    packet.set_payload(j,&config);

    Ok(())

}

fn forward(config:&crate::Configuration,packet: &GelfMessageWrapper, selected_backend_socket: &SocketAddr, normal_socket_v4: &UdpSocket,normal_socket_v6: &UdpSocket) -> anyhow::Result<()> {
   
    let src = packet.pkg_src();

    let mut packets : Vec<&GelfPacket> = vec![];
    match packet {
        GelfMessageWrapper::Chunked(c) => {
            for p in &c.chunks { 
                packets.push(p)
            }
        },
        GelfMessageWrapper::Simple(p) => packets.push(p),
    };

    for pkg in packets {
        
        if config.transparent {
            let data =  crate::package_builder::build_custom_packet(
                src.clone(), 
                *selected_backend_socket, 
                &pkg.data
            );
            log::trace!("forwarding a packet via raw socket");
            send_raw(&data,*selected_backend_socket).context("failed to send raw")?;
        } else {
            if selected_backend_socket.is_ipv4() {
                log::trace!("forwarding via basic ipv4 udp socket");
                normal_socket_v4.send_to(&pkg.data, *selected_backend_socket).context("failed to send")?;
            } else {
                log::trace!("forwarding via basic ipv6 udp socket");
                normal_socket_v6.send_to(&pkg.data, *selected_backend_socket).context("failed to send")?;
            }
            
        }
   }

   Ok(())

    
}
