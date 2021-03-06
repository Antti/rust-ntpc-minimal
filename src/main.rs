extern crate byteorder;

use byteorder::{BigEndian, ReadBytesExt};
use std::env;
use std::io::Cursor;
use std::net::UdpSocket;
use std::time::Duration;

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
const REQUEST_HEADER: &'static [u8] = &[
    0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
];

// Unix epoch is 1970-01-01T00:00:00Z
// NTP epoch is 1900-01-01T00:00:00Z
// with 17 leap years in between
// (70 * 365 + 17) * 86400 = 2208988800
const UNIX_EPOCH_OFFSET: u32 = 2208988800;

const BIND_ADDRESS: &'static str = "0.0.0.0:0";

const BUFFER_SIZE: usize = 1024;

const DEFAULT_NTP_PORT: u32 = 123;
const DEFAULT_NTP_HOST: &'static str = "pool.ntp.org";

const SOCKET_TIMEOUT: u64 = 2500;

fn receive_timestamp(ntp_host: &str) -> u32 {
    let mut buffer = vec![0u8; BUFFER_SIZE];
    let socket = UdpSocket::bind(BIND_ADDRESS).expect("couldn't bind to address");
    let ntp_address = format!("{}:{}", ntp_host, DEFAULT_NTP_PORT);
    let socket_timeout = Some(Duration::from_millis(SOCKET_TIMEOUT));

    socket.set_write_timeout(socket_timeout).expect("set_write_timeout call failed");
    socket.set_read_timeout(socket_timeout).expect("set_read_timeout call failed");

    socket.send_to(REQUEST_HEADER, ntp_address).expect("couldn't send data");
    socket.recv_from(&mut buffer).expect("didn't receive data");

    let mut reader = Cursor::new(&buffer);

    reader.set_position(TRANSMIT_TS_OFFSET);
    reader.read_u32::<BigEndian>().unwrap() - UNIX_EPOCH_OFFSET
    // TODO: extract milliseconds
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let ntp_host = ntp_host_from_args(&args);

    println!("{}", receive_timestamp(ntp_host));
}

fn ntp_host_from_args(args: &Vec<String>) -> &str {
    let mut ntp_host: &str = &DEFAULT_NTP_HOST;

    if args.len() >= 2 {
        ntp_host = &args[1];
    }

    ntp_host
}

#[test]
fn test() {
    use std::{thread, time};

    let t1 = receive_timestamp("pool.ntp.org");
    thread::sleep(time::Duration::from_millis(1000));
    let t2 = receive_timestamp("time.nist.gov");

    assert!(t2 > t1);
    assert_eq!(t2 - t1, 1);
}
