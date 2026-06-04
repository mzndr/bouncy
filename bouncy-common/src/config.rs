use crate::net_types::{IpV4, Port};

#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct Target {
    pub ip: IpV4,
}

impl Target {
    pub fn new(ip: IpV4) -> Self {
        Self { ip }
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Target {}

#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct Service {
    pub source_port: Port,
    pub dest_port: Port,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Service {}

impl Service {
    pub fn new(source_port: Port, dest_port: Port) -> Self {
        Self {
            source_port,
            dest_port,
        }
    }
}

pub const CONFIG_MAX_TARGETS: usize = 64;
pub const CONFIG_MAX_SERVICES: usize = 64;
pub struct Config {
    pub targets: [Target; CONFIG_MAX_TARGETS],
    pub services: [Service; CONFIG_MAX_SERVICES],
}

impl Config {
    pub fn new(targets: &[Target], services: &[Service]) -> Self {
        let mut new_targets = [Target::default(); CONFIG_MAX_TARGETS];
        let len_to_copy = targets.len().min(CONFIG_MAX_TARGETS);
        new_targets[..len_to_copy].copy_from_slice(&targets[..len_to_copy]);

        let mut new_services = [Service::default(); CONFIG_MAX_SERVICES];
        let len_to_copy = services.len().min(CONFIG_MAX_SERVICES);
        new_services[..len_to_copy].copy_from_slice(&services[..len_to_copy]);

        Self {
            targets: new_targets,
            services: new_services,
        }
    }
}
