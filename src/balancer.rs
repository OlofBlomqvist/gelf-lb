use std::net::{SocketAddr, UdpSocket};
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


pub(crate) fn balancer(state: std::sync::Arc<crate::State>,config:std::sync::Arc<crate::Configuration>,receiver: std::sync::mpsc::Receiver<GelfMessageWrapper>,backends: Vec<SocketAddr>) {
    
    let mut backend_cycle = backends.iter().cycle();
    let normal_socket = UdpSocket::bind("0.0.0.0:0").unwrap();
    loop {

        let mut packet = receiver.recv().expect("Failed to receive packet");

        if packet.is_complete() == false {
            
            let pkg_id = packet.pkg_id().expect("balancer saw chunked pkg with no id. this is a bug in gelflb");
            let mut guard = state.chunked_messages.lock().unwrap();
            
            let mut chunked_pkg = match packet {
                GelfMessageWrapper::Chunked(x) => x,
                GelfMessageWrapper::Simple(_) => unreachable!(),
            };

            let existing_info = guard.get_mut(&pkg_id);
            
            if let Some(old) = existing_info {  
                old.chunks.push(chunked_pkg.chunks.remove(0));
                if old.is_complete() == false {
                    // we added the chunk to our existing info about this message, but we are still waiting for more chunks
                    continue
                }
            } else {
                // this is the first chunk we see for this message, so we can continue after adding it to the state.
                guard.insert(pkg_id, chunked_pkg);
                continue
            }
            // here we now know that we have all chunks that we expected to see for this message..
            // lets remove it from the state and pass it on to the next step
            let (_,completed_chunked_pkg) = guard.remove_entry(&pkg_id).expect("failed to remove chunk entry prior to step 2. this is a bug in gelflb.");
            packet = GelfMessageWrapper::Chunked(completed_chunked_pkg)
            
        }

        let selected_backend_socket = if packet.is_chunked() {
            if let Some(pkg_id) = packet.pkg_id() {
                Some(select_backend(&backends,pkg_id))
            } else {
                eprint!("chunked message without id should not be possible..");
                None
            }         
        } else {
            Some(backend_cycle.next().unwrap())
        };

        if let Some(backend) = selected_backend_socket {
            match massage(&config,&mut packet) {
                Ok(()) => {
                    forward(&config,&packet, backend,&normal_socket);
                    state.nr_of_forwarded_messages_the_last_thirty_seconds.write().and_then(|mut x|Ok(*x=*x+1))
                    .expect("should always be possible to increment fwd count");
                },
                Err(msg) => eprintln!("packet massage failure: {msg}")
            }
        }
    }

}


fn massage(config:&crate::Configuration,packet: &mut GelfMessageWrapper) -> anyhow::Result<()> {
    
    if config.attach_source_info == false && config.blank_fields.len() == 0 && config.strip_fields.len() == 0 { return Ok(())}

    let mut j = packet.get_payload()?;
   
    let src_key = "_gelflb_original_source_addr";
    if config.attach_source_info {
        if !j.additional_fields.contains_key(src_key) {
            j.additional_fields.extend(vec![(src_key.into(), Value::from(packet.pkg_src().ip().to_string()))]);
        }
    }

    if config.strip_fields.len() > 0 {
        j.additional_fields.retain(|x,_|!config.strip_fields.contains(&format!("_{x}")));
    }
    
    for bad_key in &config.blank_fields {
        if let Some(baddy) = j.additional_fields.get_mut(&format!("_{bad_key}")) {
            if baddy.is_string() { 
                *baddy = "******".into();
            }
        }
    }

    packet.set_payload(j,&config);

    Ok(())

}

fn forward(config:&crate::Configuration,packet: &GelfMessageWrapper, selected_backend_socket: &SocketAddr, normal_socket: &UdpSocket) {
   
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
            send_raw(&data,*selected_backend_socket).unwrap();
        } else {
            normal_socket.send_to(&pkg.data, *selected_backend_socket).unwrap();
        }
   }

    
}
