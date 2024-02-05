
use std::net::SocketAddr;
use windows::{
    core::*,
    Win32::Networking::WinSock::*
};

fn make_word(low: u8, high: u8) -> u16 {
    ((high as u16) << 8) | (low as u16)
}

pub fn send_raw(bytes: &[u8], destination: SocketAddr) -> Result<()> {
    unsafe {
        let mut wsadata = WSADATA::default();
        let result = WSAStartup(make_word(2, 2), &mut wsadata);
        if result != 0 {
            return Err(Error::from_win32());
        }

        let af = match destination {
            SocketAddr::V4(_) => AF_INET,
            SocketAddr::V6(_) => AF_INET6,
        };
        let sock = WSASocketW(af.0 as i32, SOCK_RAW.0, IPPROTO_UDP.0, None, 0, 0);
        if sock == INVALID_SOCKET {
            let error = WSAGetLastError();
            WSACleanup();
            panic!("{error:?}");
        }

        if af == AF_INET {
            let result = setsockopt(sock,    IPPROTO_IP.0, IP_HDRINCL, Some(&[1, 0, 0, 0]));
            if result == SOCKET_ERROR {
                let error = WSAGetLastError();
                closesocket(sock);
                WSACleanup();
                panic!("{error:?}");
            }
        } else {
            let result = setsockopt(sock,    IPPROTO_IP.0, IPV6_HDRINCL, Some(&[1, 0, 0, 0]));
            if result == SOCKET_ERROR {
                let error = WSAGetLastError();
                closesocket(sock);
                WSACleanup();
                panic!("{error:?}");
            } 
        }
        
        match destination {
            SocketAddr::V4(addr_v4) => {
                let dest_ip = addr_v4.ip().octets();
                let dest_port = addr_v4.port();

                let dest_addr = SOCKADDR_IN {
                    sin_family: AF_INET,
                    sin_port: htons(dest_port),
                    sin_addr: IN_ADDR { S_un: IN_ADDR_0 { S_addr: u32::from_ne_bytes(dest_ip) } },
                    sin_zero: [0; 8],
                };

                let result = sendto(
                    sock,
                    bytes,
                    0,
                    &dest_addr as *const _ as *const SOCKADDR,
                    std::mem::size_of::<SOCKADDR_IN>() as i32,
                );

                if result == SOCKET_ERROR {
                    let error = WSAGetLastError();
                    closesocket(sock);
                    WSACleanup();
                    panic!("{error:?}");
                }
            },
            SocketAddr::V6(addr_v6) => {
                let dest_ip = addr_v6.ip().octets();
                let dest_port = addr_v6.port();
                let flow_info = addr_v6.flowinfo();
                let scope_id = addr_v6.scope_id();

                let dest_addr = SOCKADDR_IN6 {
                    sin6_family: AF_INET6,
                    sin6_port: htons(dest_port),
                    sin6_flowinfo: flow_info,
                    sin6_addr: IN6_ADDR { u: IN6_ADDR_0 { Byte: dest_ip } },
                    Anonymous: SOCKADDR_IN6_0 { sin6_scope_id: scope_id }, 
                };
                
                let result = sendto(
                    sock,
                    bytes,
                    0,
                    &dest_addr as *const _ as *const SOCKADDR,
                    std::mem::size_of::<SOCKADDR_IN6>() as i32,
                );

                if result == SOCKET_ERROR {
                    let error = WSAGetLastError();
                    closesocket(sock);
                    WSACleanup();
                    panic!("{error:?}");
                }
            },
        }

        closesocket(sock);
        WSACleanup();
    }

    Ok(())
}