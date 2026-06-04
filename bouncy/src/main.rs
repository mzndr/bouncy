use anyhow::Context as _;
use aya::{
    maps::{Map, MapData},
    programs::{Xdp, XdpFlags},
};
use bouncy_common::{
    config::{Config, Service, Target},
    net_types::{IpV4, Port},
};
use clap::Parser;
#[rustfmt::skip]
use log::{debug, warn};
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "lo")]
    iface: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("Running...");
    let opt = Opt::parse();

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/bouncy"
    )))?;
    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }
    let Opt { iface } = opt;
    println!("Listening on {iface}");
    let program: &mut Xdp = ebpf.program_mut("bouncy").unwrap().try_into()?;
    program.load()?;
    program.attach(&iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    let config = Config::new(
        &[Target::new([127, 0, 0, 1])],
        &[
            Service::new(1337, 1337),
            Service::new(1336, 1337),
            Service::new(42069, 1337),
        ],
    );

    let mut services =
        aya::maps::HashMap::<_, Port, Service>::try_from(ebpf.map_mut("CONFIG_SERVICES").unwrap())?;
    for s in config.services {
        services.insert(s.source_port, s, 0)?;
    }

    let mut targets: aya::maps::HashMap<_, IpV4, Target> =
        aya::maps::HashMap::try_from(ebpf.map_mut("CONFIG_TARGETS").unwrap())?;

    for t in config.targets {
        targets.insert(t.ip, t, 0).unwrap();
    }

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}
