#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};
use aya_log_ebpf::{debug, error, trace};
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
    pub dest_ip: net_types::IpV4,
    pub source_port: u16,
}

impl ConnectionIdentifier {
    pub fn new(dest_ip: net_types::IpV4, source_port: u16) -> Self {
        Self {
            dest_ip,
            source_port,
        }
    }
}

struct ConnectionState {}

#[map]
static mut CONNECTIONS: HashMap<ConnectionIdentifier, ConnectionState> =
    HashMap::<ConnectionIdentifier, ConnectionState>::with_max_entries(1024, 0);

fn try_bouncy(ctx: XdpContext) -> Result<u32, u32> {
    debug!(ctx, "parsing ethernet header");
    let Ok(ethernet_header) = read_ethernet_header(&ctx).inspect_err(|e| e.log(&ctx)) else {
        return Ok(xdp_action::XDP_PASS);
    };

    debug!(ctx, "getting ether type");
    if ethernet_header.get_ether_type() != EtherType::IpV4 {
        debug!(ctx, "payload not of type ipv4");
        return Ok(xdp_action::XDP_PASS);
    };

    debug!(ctx, "parsing ipv4 header");
    let Ok(ipv4_header) = read_ipv4_header(&ctx).inspect_err(|e| e.log(&ctx)) else {
        return Ok(xdp_action::XDP_PASS);
    };

    debug!(ctx, "checking ipv4 payload protocol");
    if ipv4_header.protocol_type() != ProtocolType::TCP {
        debug!(ctx, "payload not of type TCP");
        return Ok(xdp_action::XDP_PASS);
    }

    debug!(ctx, "reading TCP header");
    let Ok(tcp_header) = read_tcp_header(&ctx, &ipv4_header).inspect_err(|e| e.log(&ctx)) else {
        return Ok(xdp_action::XDP_PASS);
    };

    log_tcp_header(&ctx, &ipv4_header, &tcp_header);

    if tcp_header.source_port() != 1337 {
        tcp_header.set_dest_port(1337);
    } else {
        tcp_header.set_source_port(1336);
    }

    log_tcp_header(&ctx, &ipv4_header, &tcp_header);

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

fn read_ipv4_header(ctx: &XdpContext) -> Result<&'static IpV4Header, ReadError> {
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

fn log_tcp_header(ctx: &XdpContext, ipv4_header: &IpV4Header, tcp_header: &TCPHeader) {
    trace!(
        &ctx,
        "{}.{}.{}.{}:{}->{}.{}.{}.{}:{}",
        ipv4_header.source[0],
        ipv4_header.source[1],
        ipv4_header.source[2],
        ipv4_header.source[3],
        tcp_header.source_port(),
        ipv4_header.dest[0],
        ipv4_header.dest[1],
        ipv4_header.dest[2],
        ipv4_header.dest[3],
        tcp_header.dest_port(),
    );
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
