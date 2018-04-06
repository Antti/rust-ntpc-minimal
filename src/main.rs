extern crate byteorder;
extern crate chrono;
extern crate tokio;
extern crate tokio_dns;

use std::env;
use std::io::Cursor;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use byteorder::{BigEndian, ReadBytesExt};
use chrono::{TimeZone, Utc};
use tokio::io;
use tokio::net::UdpSocket;
use tokio::prelude::future::*;
use tokio::prelude::*;

// From page 18 of https://www.ietf.org/rfc/rfc5905.txt:
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |LI | VN  |Mode |    Stratum     |     Poll      |  Precision   | 4B
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                         Root Delay                            | 4B
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                         Root Dispersion                       | 4B
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                          Reference ID                         | 4B
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// +                     Reference Timestamp (64)                  + 8B
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// +                      Origin Timestamp (64)                    + 8B
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// +                      Receive Timestamp (64)                   + 8B
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ <- 40B
// |                                                               |
// +                      Transmit Timestamp (64)                  + 8B
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
const TRANSMIT_TS_OFFSET: u64 = 40;

// | LI | VN | Mode | .....
// where: LI = 0; VN, Mode = 3
// altogether: 000011011 -> 1b (base 16)
// padding the rest with zeros
const REQUEST_HEADER: &[u8] = &[
    0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

// Unix epoch is 1970-01-01T00:00:00Z
// NTP epoch is 1900-01-01T00:00:00Z
// with 17 leap years in between
// (70 * 365 + 17) * 86400 = 2208988800
const UNIX_EPOCH_OFFSET: u32 = 2_208_988_800;

const BIND_ADDRESS: &str = "0.0.0.0:0";

const BUFFER_SIZE: usize = 1024;

const DEFAULT_NTP_PORT: u16 = 123;
const DEFAULT_NTP_HOST: &str = "pool.ntp.org";

const SOCKET_TIMEOUT: u64 = 2500;

// Custom error type to wrap other errors
#[derive(Debug)]
pub enum NtpError {
    IoError(io::Error),
    AddrParseError(std::net::AddrParseError),
}

fn parse_timestamp(buf: &[u8]) -> Result<chrono::DateTime<Utc>, NtpError> {
    let mut reader = Cursor::new(&buf);
    reader.set_position(TRANSMIT_TS_OFFSET);
    // TODO: extract milliseconds
    reader
        .read_u32::<BigEndian>()
        .map(|val| Utc.timestamp(i64::from(val - UNIX_EPOCH_OFFSET), 0))
        .map_err(NtpError::IoError)
}

pub fn receive_timestamp(
    ntp_host: &str,
    ntp_port: u16,
) -> impl Future<Item = chrono::DateTime<Utc>, Error = NtpError> {
    let bind_address = result(BIND_ADDRESS.parse().map_err(NtpError::AddrParseError));

    let socket = bind_address
        .and_then(|bind_address| result(UdpSocket::bind(&bind_address).map_err(NtpError::IoError)));

    // just take the first IP address
    let sock_addr = tokio_dns::resolve::<&str>(ntp_host)
        .map(move |ips| SocketAddr::new(ips[0], ntp_port))
        .map_err(NtpError::IoError);

    // join will wait for both futures to resolve and then yield two results in a tuple
    socket
        .join(sock_addr)
        .and_then(|(socket, addr)| {
            socket
                .send_dgram(REQUEST_HEADER, &addr)
                .map_err(NtpError::IoError)
        })
        .and_then(|(socket, _buf)| {
            let buffer = vec![0u8; BUFFER_SIZE];
            socket.recv_dgram(buffer).map_err(NtpError::IoError)
        })
        .and_then(|(_socket, buf, _len, _sock_addr)| result(parse_timestamp(&buf)))
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let ntp_host = ntp_host_from_args(&args);

    let when = Instant::now() + Duration::from_millis(SOCKET_TIMEOUT);
    let timestamp_future = receive_timestamp(ntp_host, DEFAULT_NTP_PORT)
        .deadline(when)
        .map(|timestamp| {
            println!("{}", timestamp);
        })
        .map_err(|e| {
            println!("Error receiving timestamp: {:?}", e);
        });
    tokio::run(timestamp_future);
}

fn ntp_host_from_args(args: &[String]) -> &str {
    if args.len() >= 2 {
        &args[1]
    } else {
        DEFAULT_NTP_HOST
    }
}

#[test]
fn test() {
    use std::{thread, time};

    let t1 = receive_timestamp("pool.ntp.org", DEFAULT_NTP_PORT).wait().unwrap();
    thread::sleep(time::Duration::from_millis(1000));
    let t2 = receive_timestamp("time.nist.gov", DEFAULT_NTP_PORT).wait().unwrap();

    assert!(t2 > t1);
}
