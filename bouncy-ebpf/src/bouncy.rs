#![no_std]
#![no_main]

use core::net::Ipv4Addr;

use aya_ebpf::maps::HashMap;

// #[derive(Clone, Debug)]
// pub struct Bouncy {
//     targets: Vec<Ipv4Addr>,
//     services: HashMap<u16, Service>,
//     conns: HashMap<ConnectionID, Ipv4Addr>,
//     last_target: usize,
// }
