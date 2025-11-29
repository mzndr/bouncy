pub const ETHER_TYPE_IPV4: u16 = 0x0800;
pub const ETHER_HEADER_LEN: usize = 14;

pub const PROTOCOL_TYPE_TCP: u8 = 6;

pub type IpV4 = [u8; 4];
pub type Mac = [u8; 6];
pub type Port = u16;

#[derive(Eq, PartialEq, PartialOrd)]
pub enum EtherType {
    IpV4,
    Unknown(u16),
}

#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
pub struct EthernetHeader {
    pub dest: Mac,
    pub source: Mac,
    ether_type: u16,
}

impl EthernetHeader {
    // Get the type of the ethernet.
    pub fn get_ether_type(&self) -> EtherType {
        match u16::from_be(self.ether_type) {
            ETHER_TYPE_IPV4 => EtherType::IpV4,
            code => EtherType::Unknown(code),
        }
    }
}

#[derive(Eq, PartialEq, PartialOrd)]
pub enum ProtocolType {
    TCP,
    Unknown(u8),
}

#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
pub struct IpV4Header {
    pub version_ihl: u8,
    pub dscp_ecn: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags_fragment_offset: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub checksum: u16,
    pub source: IpV4,
    pub dest: IpV4,
}

impl IpV4Header {
    #[inline(always)]
    pub fn ihl(&self) -> usize {
        usize::from(self.version_ihl & 0b0000_1111)
    }

    #[inline(always)]
    pub fn protocol_type(&self) -> ProtocolType {
        match self.protocol {
            PROTOCOL_TYPE_TCP => ProtocolType::TCP,
            _ => ProtocolType::Unknown(self.protocol),
        }
    }

    #[inline(always)]
    pub fn payload_offset(&self) -> usize {
        self.ihl() * 4
    }
}

#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
pub struct TCPHeader {
    pub source_port_be: Port,
    pub dest_port_be: Port,
    pub seq: u32,
    pub ack: u32,
    pub data_offset: u8,
    pub flags: u8,
    pub window: u16,
    pub checksum: u16,
    pub urgent_ptr: u16,
}

impl TCPHeader {
    pub fn source_port(&self) -> Port {
        u16::from_be(self.source_port_be)
    }

    pub fn dest_port(&self) -> Port {
        u16::from_be(self.dest_port_be)
    }

    pub fn set_dest_port(&mut self, val: u16) {
        self.dest_port_be = u16::to_be(val)
    }

    pub fn set_source_port(&mut self, val: u16) {
        self.source_port_be = u16::to_be(val)
    }
}
