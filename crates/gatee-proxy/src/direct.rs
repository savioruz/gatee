use std::io;
use tokio::net::TcpStream;

/// Dials a target TCP address directly.
pub async fn dial_direct(addr: &str) -> io::Result<TcpStream> {
    TcpStream::connect(addr).await
}
