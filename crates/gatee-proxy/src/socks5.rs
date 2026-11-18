use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Parses a SOCKS5 proxy address string that may contain a URL scheme or embedded credentials.
/// Returns the host:port string to connect to and optional (username, password).
pub fn parse_socks5_proxy_addr<'a>(
    proxy_addr: &'a str,
    auth: Option<(&'a str, &'a str)>,
) -> (String, Option<(String, String)>) {
    let clean = proxy_addr
        .strip_prefix("socks5://")
        .or_else(|| proxy_addr.strip_prefix("socks5h://"))
        .unwrap_or(proxy_addr)
        .trim_end_matches('/');

    if let Some((userinfo, hostport)) = clean.rsplit_once('@') {
        let extracted_auth = if let Some((u, p)) = userinfo.split_once(':') {
            Some((u.to_string(), p.to_string()))
        } else {
            Some((userinfo.to_string(), String::new()))
        };
        let effective_auth = auth
            .map(|(u, p)| (u.to_string(), p.to_string()))
            .or(extracted_auth);
        (hostport.to_string(), effective_auth)
    } else {
        let effective_auth = auth.map(|(u, p)| (u.to_string(), p.to_string()));
        (clean.to_string(), effective_auth)
    }
}

/// Dials a target TCP address via a SOCKS5 upstream proxy (RFC 1928).
/// Supports no-auth, username/password auth (RFC 1929), and IPv4/IPv6/Domain target addressing.
pub async fn dial_socks5_proxy(
    proxy_addr: &str,
    target_host: &str,
    target_port: u16,
    auth: Option<(&str, &str)>,
) -> io::Result<TcpStream> {
    let (connect_addr, effective_auth) = parse_socks5_proxy_addr(proxy_addr, auth);
    let mut stream = TcpStream::connect(&connect_addr).await?;

    // Greeting: RFC 1928 Section 3
    if effective_auth.is_some() {
        // Offer 2 methods: 0 (No Auth), 2 (Username/Password)
        stream.write_all(&[5, 2, 0, 2]).await?;
    } else {
        // Offer 1 method: 0 (No Auth)
        stream.write_all(&[5, 1, 0]).await?;
    }

    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await?;
    if resp[0] != 5 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid SOCKS5 version",
        ));
    }

    // Subnegotiation: RFC 1929
    if resp[1] == 2 {
        if let Some((ref user, ref pass)) = effective_auth {
            if user.len() > 255 || pass.len() > 255 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "SOCKS5 credentials exceed 255 bytes",
                ));
            }
            let mut auth_req = Vec::with_capacity(3 + user.len() + pass.len());
            auth_req.push(1); // Auth subnegotiation version 1
            auth_req.push(user.len() as u8);
            auth_req.extend_from_slice(user.as_bytes());
            auth_req.push(pass.len() as u8);
            auth_req.extend_from_slice(pass.as_bytes());
            stream.write_all(&auth_req).await?;

            let mut auth_resp = [0u8; 2];
            stream.read_exact(&mut auth_resp).await?;
            if auth_resp[1] != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "SOCKS5 auth rejected",
                ));
            }
        } else {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "SOCKS5 requires auth",
            ));
        }
    } else if resp[1] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "SOCKS5 method not accepted",
        ));
    }

    // Connect request: RFC 1928 Section 4
    let mut req = vec![5, 1, 0]; // VER=5, CMD=1 (CONNECT), RSV=0
    if let Ok(ip) = target_host.parse::<std::net::IpAddr>() {
        match ip {
            std::net::IpAddr::V4(v4) => {
                req.push(1); // ATYP 1 = IPv4
                req.extend_from_slice(&v4.octets());
            }
            std::net::IpAddr::V6(v6) => {
                req.push(4); // ATYP 4 = IPv6
                req.extend_from_slice(&v6.octets());
            }
        }
    } else {
        if target_host.len() > 255 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Target host length exceeds 255 bytes",
            ));
        }
        req.push(3); // ATYP 3 = Domain Name
        req.push(target_host.len() as u8);
        req.extend_from_slice(target_host.as_bytes());
    }
    req.extend_from_slice(&target_port.to_be_bytes());
    stream.write_all(&req).await?;

    let mut hdr = [0u8; 4];
    stream.read_exact(&mut hdr).await?;
    if hdr[0] != 5 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid SOCKS5 version in reply",
        ));
    }
    if hdr[1] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("SOCKS5 error code {}", hdr[1]),
        ));
    }

    // Discard bind address bytes
    match hdr[3] {
        1 => {
            let mut skip = [0u8; 4 + 2];
            stream.read_exact(&mut skip).await?;
        }
        4 => {
            let mut skip = [0u8; 16 + 2];
            stream.read_exact(&mut skip).await?;
        }
        3 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut skip = vec![0u8; len[0] as usize + 2];
            stream.read_exact(&mut skip).await?;
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Unknown SOCKS5 address type",
            ))
        }
    }

    Ok(stream)
}
