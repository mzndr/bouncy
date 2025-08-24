#[derive(Clone, Copy, Debug)]
pub struct Service {
    port_src: u16,
    port_dst: u16,
}

impl Service {
    pub fn new(port_src: u16, port_dst: u16) -> Self {
        Self { port_src, port_dst }
    }

    pub fn port_src(&self) -> u16 {
        self.port_src
    }

    pub fn port_dst(&self) -> u16 {
        self.port_dst
    }
}
