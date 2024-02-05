
mod package_builder;
mod balancer;
mod gelf;
use std::{collections::HashMap, net::{IpAddr, SocketAddr, ToSocketAddrs, UdpSocket}, str::FromStr, sync::RwLock, time::Duration};

use gelf::*;

mod configuration;
use configuration::*;

mod state;
use state::*;

#[cfg(target_os="windows")]
mod windows;
#[cfg(target_os="windows")]
use crate::windows::*;

#[cfg(target_os="linux")]
mod linux;
#[cfg(target_os="linux")]
use crate::linux::*;

fn main() {

    let args: Vec<String> = std::env::args().collect();
   
    let cfg_file = if args.len() == 2 {
        &args[1]
    } else if args.len() > 2 {
        panic!("Expected a single argument, received {}",args.len()-1)
    } else {
        "gelflb.toml"
    };

    let config_string = std::fs::read_to_string(cfg_file)
        .expect("Failed to read the config file");

    let config: configuration::Configuration = toml::from_str(&config_string)
        .expect("Failed to parse the TOML");

    
    //env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    env_logger::builder()
    .filter_level(config.log_level.parse().unwrap())
    .format_target(false)
    .format_timestamp(None)
    .init();


    let info = os_info::get();
    if info.os_type() == os_info::Type::Windows {
        let edition = info.edition().unwrap();
        if !edition.contains("Server") {
            if config.transparent {
                panic!("Transparent mode is not supported on your OS. You may wish to enable the 'attach_source_info' setting instead?")
            }
        }
    }

    let listen_addr: SocketAddr = format!("{}:{}",config.listen_ip,config.listen_port).parse().expect("Invalid listen address");

    let socket = UdpSocket::bind(&listen_addr).expect("Failed to bind to address");

    let backend_servers: Vec<SocketAddr> = config.backends.iter().map(|x|
        format!("{}:{}",x.ip,x.port).to_socket_addrs().expect("invalid backend").next().expect("invalid backend")
        //format!("{}:{}",x.ip,x.port).parse().expect("invalid backend!")
    ).collect();

    for b in &backend_servers {
        if config.transparent {
            if b.is_ipv6() && listen_addr.is_ipv4() {
                panic!("invalid configuration! you cannot use ipv4 backends while listening on ipv6 when you use transparent mode.")
            } else if b.is_ipv6() && listen_addr.is_ipv6() {
                panic!("invalid configuration! you cannot use ipv6 backends while listening on ipv4 when you use transparent mode.")
            }
        }
    }

    let (sender, receiver) = 
        std::sync::mpsc::channel::<GelfMessageWrapper>();
    
    let config = std::sync::Arc::new(config);
    let state = std::sync::Arc::new(crate::State { nr_of_handled_udp_packets_the_thirty_seconds: RwLock::new(0),  nr_of_forwarded_messages_the_last_thirty_seconds: RwLock::new(0), chunked_messages: std::sync::Mutex::new(HashMap::new())});
    
    let balancer_state = state.clone();
    let balancer_config = config.clone();
    let cleanup_state = state.clone();

    // init balancer thread
    std::thread::spawn(move||balancer::balancer(balancer_state.clone(),balancer_config.clone(),receiver,backend_servers));
    
    // perform periodic cleanup in separate thread
    std::thread::spawn(move|| {
        let cleanup_state = cleanup_state;
        loop {            
            std::thread::sleep(Duration::from_secs(10));
            
            let mut nr_removed = 0;
            {
                let mut guard = cleanup_state.chunked_messages.lock().unwrap();    
                let before = guard.len();
                guard.retain(|_k,v|v.age_in_seconds() < 10);
                nr_removed += before.abs_diff(guard.len());
            }
            if nr_removed > 0 {
                log::debug!("Dropped {nr_removed} messages due to not receiving all chunks within 10 seconds!");
            } else {
                log::trace!("All is good, we do not have any old chunks :D")
            }
        }
    });

    let info_state = state.clone();
    std::thread::spawn(move || {
        let info_state = info_state;
        loop {
            std::thread::sleep(Duration::from_secs(30));
            let (handled,forwarded) = {
                let mut guard_handled = info_state.nr_of_handled_udp_packets_the_thirty_seconds.write().unwrap();
                let mut guard_fwt = info_state.nr_of_forwarded_messages_the_last_thirty_seconds.write().unwrap();
                let result = (*guard_handled,*guard_fwt);   
                *guard_handled = 0;
                *guard_fwt = 0;
                result
            };
            log::info!("In the last 30 seconds we have handled {handled} udp packets messages and successfully forwarded {forwarded} messages");
        }
    });  
    let mut buf = [0u8; 65_000];
    let uses_whitelist = config.allowed_source_ips.len() > 0;
    let mut whitelist = vec![];
    for x in &config.allowed_source_ips {
        whitelist.push(IpAddr::from_str(&x).unwrap())
    }

    log::info!("GELF_LB RUNNING ON {}:{}",config.listen_ip,config.listen_port);

    loop {

        let (len, client_addr) = socket.recv_from(&mut buf).expect("Failed to receive packet");
        
        state.nr_of_handled_udp_packets_the_thirty_seconds.write().and_then(|mut x|Ok(*x=*x+1))
            .expect("should always be possible to increment handled count");
        
        if uses_whitelist {
            if !whitelist.contains(&client_addr.ip()) {
                log::trace!("ignoring sender due to not existing in whitelist: {:?}",client_addr.ip());
                continue
            }
        }
        let packet_data = buf[..len].to_vec();        
        let (message_id, sequence_number, total_chunks) = crate::gelf::parse_chunk_info(&packet_data);
        let gelf_packet = GelfPacket::new_chunked(
            packet_data,
            message_id,
            sequence_number,
            total_chunks,
            client_addr,
        );
        let wrapped = if gelf_packet.is_chunked() {
            GelfMessageWrapper::Chunked(GelfChunkedMessage::new(gelf_packet))
        } else {
            GelfMessageWrapper::Simple(gelf_packet)
        };
        sender
            .send(wrapped)
            .expect("Failed to send packet to worker");
    }
}

