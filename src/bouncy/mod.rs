extern crate pnet;

mod service;

use pnet::datalink::{self, NetworkInterface};

use pnet::packet::Packet;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::tcp::{MutableTcpPacket, TcpPacket};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tracing::{instrument, trace_span};

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

pub use service::Service;

const IPPROTO_RAW_VALUE: i32 = 255;

#[derive(Clone, Debug)]
pub struct Bouncy {
    targets: Vec<Ipv4Addr>,
    services: HashMap<u16, Service>,
    conns: HashMap<ConnectionID, Ipv4Addr>,
    last_target: usize,
}

#[derive(Clone, Debug, Hash, Eq, PartialEq)]
pub struct ConnectionID {
    port_src: u16,
    ip_src: IpAddr,
}

impl ConnectionID {
    pub fn new(port_src: u16, ip_src: IpAddr) -> Self {
        Self { port_src, ip_src }
    }
}

impl Bouncy {
    pub fn new(targets: &[Ipv4Addr], services: &[Service]) -> Self {
        let mut s = HashMap::new();
        services.iter().for_each(|srvc| {
            s.insert(srvc.port_src(), srvc.clone());
        });

        Self {
            targets: Vec::from(targets),
            services: s,
            conns: HashMap::new(),
            last_target: 0,
        }
    }

    #[instrument(skip_all, fields(source_ip=?source))]
    fn handle_tcp_packet<'a>(
        &mut self,
        source: IpAddr,
        packet: &'a mut [u8],
    ) -> Option<(TcpPacket<'a>, Ipv4Addr)> {
        let span = trace_span!("handle_tcp_package");
        let _guard = span.enter();

        tracing::trace!("handling tcp package.");
        let tcp_packet = TcpPacket::new(packet);
        let Some(tcp_packet) = tcp_packet else {
            return None;
        };
        let source_port = tcp_packet.get_source();
        let dest_port = tcp_packet.get_destination();
        let own = self.to_owned();
        let Some(service) = own.services.get(&source_port) else {
            tracing::debug!("Port {source_port} not a target port, dropping.");
            return None;
        };

        let connection_id = ConnectionID::new(dest_port, source.clone());
        let target_ip = match self.conns.get(&connection_id) {
            Some(ip) => {
                tracing::debug!("found connection state for {connection_id:?} found.");
                *ip
            }
            None => {
                let target_ip = self.round_robin();
                tracing::debug!("connection state for {connection_id:?} not found, creating new.");
                self.conns.insert(connection_id, target_ip);
                target_ip
            }
        };

        tracing::debug!(
            "rewriting package destination to service port {}",
            service.port_dst()
        );
        let mut forward = MutableTcpPacket::new(packet).expect("valid packet data");
        forward.set_destination(service.port_dst());
        Some((forward.consume_to_immutable(), target_ip))
    }

    fn round_robin(&mut self) -> Ipv4Addr {
        let idx = (self.last_target + 1) % self.targets.len();
        let ret = self
            .targets
            .get(idx)
            .expect("should have at least one target");
        self.last_target = idx;
        *ret
    }

    #[instrument(skip_all)]
    fn handle_ipv4_packet(&mut self, ethernet: EthernetPacket) {
        let span = trace_span!("handle_ipv4_package");
        let _guard = span.enter();
        tracing::trace!("handling ipv4 package.");
        let Some(header) = Ipv4Packet::new(ethernet.payload()) else {
            return;
        };
        let source = IpAddr::V4(header.get_source());
        let mut header_data = Vec::from(header.payload());
        let tcp_packet_opt = match header.get_next_level_protocol() {
            IpNextHeaderProtocols::Tcp => self.handle_tcp_packet(source, &mut header_data),
            _ => return,
        };

        let Some((tcp_packet, target_ip)) = tcp_packet_opt else {
            return;
        };

        let mut d = Vec::from(ethernet.payload());
        let mut forward = MutableIpv4Packet::new(&mut d).expect("valid packet data");

        tracing::debug!("rewriting package destination to target ip {target_ip}",);
        forward.set_payload(tcp_packet.packet());
        forward.set_destination(target_ip);
        let socket = Socket::new(Domain::IPV4, Type::RAW, Some(IPPROTO_RAW_VALUE.into()))
            .expect("can create socket");
        let dest_sock_addr = SockAddr::from(SocketAddr::new(
            target_ip.into(),
            tcp_packet.get_destination(),
        ));
        socket
            .send_to(forward.packet(), &dest_sock_addr)
            .expect("can send packet");
    }

    #[instrument(skip_all, fields(iface=interface.name))]
    fn handle_ethernet_frame(&mut self, interface: &NetworkInterface, ethernet: EthernetPacket) {
        let span = trace_span!("handle_ethernet_frame");
        let _guard = span.enter();
        let ether_type = ethernet.get_ethertype();
        span.record("Type", ether_type.to_string());
        match ether_type {
            EtherTypes::Ipv4 => self.handle_ipv4_packet(ethernet),
            _ => return,
        };
    }

    #[instrument(skip_all)]
    pub fn listen(&mut self, interface: &NetworkInterface) {
        tracing::info!("listening to incoming packets...");
        use pnet::datalink::Channel::Ethernet;
        // Create a channel to receive on
        let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
            Ok(Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => panic!("packetdump: unhandled channel type"),
            Err(e) => panic!("packetdump: unable to create channel: {}", e),
        };
        loop {
            match rx.next() {
                Ok(packet) => {
                    self.handle_ethernet_frame(&interface, EthernetPacket::new(packet).unwrap());
                }
                Err(e) => panic!("packetdump: unable to receive packet: {}", e),
            }
        }
    }
}
