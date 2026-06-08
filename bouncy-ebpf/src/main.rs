#![no_std]
#![no_main]
#![allow(static_mut_refs)]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};
use aya_log_ebpf::{debug, error, trace};
use bouncy_common::{
    config::{CONFIG_MAX_SERVICES, CONFIG_MAX_TARGETS, Service, Target},
    net_types::{IpV4, Port},
};
use net_types::{ETHER_HEADER_LEN, EtherType, EthernetHeader, IpV4Header, ProtocolType, TCPHeader};

mod bouncy;
mod net_types;

#[xdp]
pub fn bouncy(ctx: XdpContext) -> u32 {
    match try_bouncy(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

struct ConnectionIdentifier {
    pub dest_ip: bouncy_common::net_types::IpV4,
    pub source_port: Port,
}

impl ConnectionIdentifier {
    pub fn new(dest_ip: bouncy_common::net_types::IpV4, source_port: u16) -> Self {
        Self {
            dest_ip,
            source_port,
        }
    }
}

struct ConnectionState {}

// #[map]
// static mut CONNECTIONS: HashMap<ConnectionIdentifier, ConnectionState> =
//     HashMap::<ConnectionIdentifier, ConnectionState>::with_max_entries(1024, 0);

#[map]
static mut CONFIG_TARGETS: HashMap<IpV4, Target> =
    HashMap::<IpV4, Target>::with_max_entries(CONFIG_MAX_TARGETS as u32, 0);

#[map]
static mut CONFIG_SERVICES: HashMap<Port, Service> =
    HashMap::<Port, Service>::with_max_entries(CONFIG_MAX_SERVICES as u32, 0);

fn try_bouncy(ctx: XdpContext) -> Result<u32, u32> {
    trace!(ctx, "parsing ethernet header");
    let Ok(ethernet_header) = read_ethernet_header(&ctx).inspect_err(|e| e.log(&ctx)) else {
        return Ok(xdp_action::XDP_PASS);
    };

    trace!(ctx, "getting ether type");
    if ethernet_header.get_ether_type() != EtherType::IpV4 {
        trace!(ctx, "payload not of type ipv4");
        return Ok(xdp_action::XDP_PASS);
    };

    trace!(ctx, "parsing ipv4 header");
    let Ok(ipv4_header) = read_ipv4_header(&ctx).inspect_err(|e| e.log(&ctx)) else {
        return Ok(xdp_action::XDP_PASS);
    };

    trace!(ctx, "checking ipv4 payload protocol");
    if ipv4_header.protocol_type() != ProtocolType::TCP {
        trace!(ctx, "payload not of type TCP");
        return Ok(xdp_action::XDP_PASS);
    }

    trace!(ctx, "reading TCP header");
    let Ok(tcp_header) = read_tcp_header(&ctx, &ipv4_header).inspect_err(|e| e.log(&ctx)) else {
        return Ok(xdp_action::XDP_PASS);
    };

    let ret = route_packet(&ctx, ipv4_header, tcp_header);
    trace!(ctx, "done handling packet");
    ret
}

fn route_packet<'a>(
    ctx: &'a XdpContext,
    ipv4_header: &'a mut IpV4Header,
    tcp_header: &'a mut TCPHeader,
) -> Result<u32, u32> {
    net_types::log_tcp_header(&ctx, &ipv4_header, &tcp_header);
    // The packet is an outbound packet, if the source IP is one of the targets.
    let is_outbound = unsafe { CONFIG_TARGETS.get(&ipv4_header.source) }.is_some();
    if is_outbound {
        return route_outbound(ctx, ipv4_header, tcp_header);
    }
    return route_inbound(ctx, ipv4_header, tcp_header);
}

fn route_outbound<'a>(
    ctx: &'a XdpContext,
    ipv4_header: &'a mut IpV4Header,
    tcp_header: &'a mut TCPHeader,
) -> Result<u32, u32> {
    let service = match unsafe { CONFIG_SERVICES.get(&tcp_header.dest_port()) } {
        Some(svc) => {
            trace!(ctx, "service for request found");
            svc
        }
        None => {
            trace!(ctx, "no service for request found");
            return Ok(xdp_action::XDP_PASS);
        }
    };

    tcp_header.set_source_port(service.dest_port);

    Ok(xdp_action::XDP_PASS)
}

fn route_inbound<'a>(
    ctx: &'a XdpContext,
    ipv4_header: &'a mut IpV4Header,
    tcp_header: &'a mut TCPHeader,
) -> Result<u32, u32> {
    let service = match unsafe { CONFIG_SERVICES.get(&tcp_header.dest_port()) } {
        Some(svc) => {
            trace!(ctx, "service for request found");
            svc
        }
        None => {
            trace!(ctx, "no service for request found");
            return Ok(xdp_action::XDP_PASS);
        }
    };

    tcp_header.set_dest_port(service.source_port);

    Ok(xdp_action::XDP_PASS)
}

const ERR_CODE_READ_OUT_OF_BOUNDS: u32 = 2;
enum ReadError {
    OutOfBounds(usize),
}

impl From<ReadError> for u32 {
    fn from(value: ReadError) -> Self {
        match value {
            ReadError::OutOfBounds(_) => ERR_CODE_READ_OUT_OF_BOUNDS,
        }
    }
}

impl ReadError {
    pub fn log(&self, ctx: &XdpContext) {
        match self {
            ReadError::OutOfBounds(_) => {
                error!(ctx, "Illegal read at ");
            }
        };
    }
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<&'static mut T, ReadError> {
    let addr = ctx.data() + offset;
    let end = ctx.data_end();
    if core::mem::size_of::<T>() + addr > end {
        return Err(ReadError::OutOfBounds(addr));
    };

    let a = addr as *const T as *mut T;
    let b = unsafe { core::mem::transmute(a) };

    Ok(b)
}

fn read_ethernet_header(ctx: &XdpContext) -> Result<&'static EthernetHeader, ReadError> {
    Ok(ptr_at(&ctx, 0)?)
}

fn read_ipv4_header(ctx: &XdpContext) -> Result<&'static mut IpV4Header, ReadError> {
    Ok(ptr_at(&ctx, ETHER_HEADER_LEN)?)
}

fn read_tcp_header(
    ctx: &XdpContext,
    ipv4_header: &IpV4Header,
) -> Result<&'static mut TCPHeader, ReadError> {
    Ok(ptr_at(
        &ctx,
        ETHER_HEADER_LEN + ipv4_header.payload_offset(),
    )?)
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
