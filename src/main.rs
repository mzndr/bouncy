#![forbid(unsafe_code)]
#![deny(nonstandard_style)]
#![warn(clippy::pedantic, clippy::unwrap_used)]
#![allow(clippy::similar_names, clippy::unused_async)]

use std::{
    env,
    net::{Ipv4Addr, SocketAddr, ToSocketAddrs},
};

use bouncy::Service;
use clap::Parser;
use pnet::datalink::{self, NetworkInterface};

mod bouncy;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long, required = true, env = "INTERFACE")]
    interface: String,
}

fn main() {
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    let Some(interface) = interface_by_name(&args.interface) else {
        tracing::info!("Cannot find interface {}", args.interface);
        return;
    };
    tracing::info!("Binding to interface {}", interface.name);
    let targets = &[resolve_hostname("whoami1"), resolve_hostname("whoami2")];
    let services = &[Service::new(8080, 80), Service::new(443, 443)];

    let mut b = bouncy::Bouncy::new(targets, services);
    b.listen(&interface);
}

fn resolve_hostname(hostname: &str) -> Ipv4Addr {
    tracing::trace!("resolving hostname {}", hostname);
    let addr_str = format!("{}:{}", hostname, 0);
    match addr_str.to_socket_addrs() {
        Ok(mut addrs) => {
            if let Some(SocketAddr::V4(socket_addr)) = addrs.next() {
                socket_addr.ip().to_owned()
            } else {
                panic!("cannot resolve hostname")
            }
        }
        Err(e) => panic!("cannot resolve hostname"),
    }
}

fn interface_by_name(name: &str) -> Option<NetworkInterface> {
    datalink::interfaces()
        .into_iter()
        .filter(|iface: &NetworkInterface| iface.name == name)
        .next()
}
