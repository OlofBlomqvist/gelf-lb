fn htons(u: u16) -> u16 {
    u.to_be()
}

use std::io::{self, Result};
use std::net::SocketAddr;
use libc::{socket, sendto, SOCK_RAW, IPPROTO_RAW, sockaddr, close};
use libc::{sockaddr_in, sockaddr_in6, AF_INET, AF_INET6};

pub (crate) fn send_raw(packet: &[u8], destination: SocketAddr) -> Result<()> {
    log::info!("Sending a single packet to: {:?}",destination);
    let sock = match destination {
        SocketAddr::V4(_) => unsafe { socket(AF_INET, SOCK_RAW, IPPROTO_RAW) },
        SocketAddr::V6(_) => unsafe { socket(AF_INET6, SOCK_RAW, IPPROTO_RAW) },
    };

    if sock < 0 {
        return Err(io::Error::last_os_error());
    }

    let send_result = match destination {
        SocketAddr::V4(addr) => {
            let sockaddr = sockaddr_in {
                sin_family: AF_INET as u16,
                sin_port: htons(addr.port()),
                sin_addr: libc::in_addr { s_addr: u32::from_ne_bytes(addr.ip().octets()) },
                sin_zero: [0; 8],
            };

            unsafe {
                sendto(
                    sock,
                    packet.as_ptr().cast(),
                    packet.len(),
                    0,
                    &sockaddr as *const _ as *const sockaddr,
                    std::mem::size_of::<sockaddr_in>() as libc::socklen_t,
                )
            }
        },
        SocketAddr::V6(addr) => {
            let sockaddr = sockaddr_in6 {
                sin6_family: AF_INET6 as u16,
                sin6_port: htons(addr.port()),
                sin6_addr: libc::in6_addr { s6_addr: addr.ip().octets() },
                sin6_flowinfo: addr.flowinfo(),
                sin6_scope_id: addr.scope_id(),
                
            };

            unsafe {
                sendto(
                    sock,
                    packet.as_ptr().cast(),
                    packet.len(),
                    0,
                    &sockaddr as *const _ as *const sockaddr,
                    std::mem::size_of::<sockaddr_in6>() as libc::socklen_t,
                )
            }
        },
    };

    let _ = unsafe { close(sock) };

    if send_result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
