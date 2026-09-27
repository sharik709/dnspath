use std::env;
use std::net::{IpAddr, SocketAddr};
use std::time::Instant;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::Command;

use hickory_proto::op::{Message, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};

use serde::Deserialize;

use std::net::UdpSocket;
use std::time::Duration;

#[derive(Debug, Default)]
struct Resolver {
    domain: Option<String>,
    nameservers: Vec<String>,
    iface: Option<String>
}


#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Account {
    name: String,
    id: String,
    tenant_id: String,
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 3 {
        eprintln!("Usage: {} <name> <dns-server-ip>", args[0]);
        std::process::exit(2);
    }

    let json = az(&["account", "show"]).unwrap_or_default();
    match serde_json::from_str::<Account>(&json) {
        Ok(acc) => println!("azure: {} ({})", acc.name, acc.id),
        Err(e) => println!("azure: could not parse account: {e}"),
    }

    let name: &str = &args[1];

    let ip: IpAddr = match args[2].parse() {
        Ok(ip) => ip,
        Err(e) => {
            eprintln!("Invalid ip: '{}': {e}", args[2]);
            std::process::exit(2)
        }
    };

    let server: SocketAddr = SocketAddr::new(ip, 53);
    let public: SocketAddr = SocketAddr::new(IpAddr::from([1, 1, 1, 1]), 53);

    let qname: Name = Name::from_ascii(name).expect("invalid domain name");

    let mut msg: Message = Message::new();
    (&mut msg).set_id(0x4242);
    (&mut msg).set_recursion_desired(true);
    (&mut msg).add_query(Query::query(qname, RecordType::A));

    let packet: Vec<u8> = msg.to_vec().expect("failed to encode");

    for target in [server, public] {
        println!("-----{target}-----");
        if let Some(resp) = query_udp(&packet, target) {
            println!("rcode {}", resp.response_code());
            for rec in resp.answers() {
                match rec.data() {
                    Some(RData::A(a)) => println!("   A {a} {}   ttl {}", label(a.0), rec.ttl()),
                    _ => println!("    {rec}")
                }
            }
        }
    }

    println!("------- OS resolver -------\n");

    if !run("os resolver", check_resolver(name, ip)) { return; }
    if !run("tunnel", check_tunnel(ip)) { return; }
    let udp_ok = run("dns udp", check_dns_udp(&packet, server));
    let tcp_ok = run("dns tcp", check_dns_tcp(&packet, server));

    if !(udp_ok && tcp_ok) { return; }
}

fn az(args: &[&str]) -> Option<String> {
    let out = Command::new("az")
        .args(args)
        .args(["-o", "json"])
        .output()
        .ok()?;

    if !out.status.success() {
        eprintln!("az {} failed: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim());
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn check_dns_udp(packet: &[u8], server: SocketAddr) -> Status {
    judge(query_udp(packet, server), server)
}

fn check_dns_tcp(packet: &[u8], server: SocketAddr) -> Status {
    judge(query_tcp(packet, server), server)
}

fn judge(resp: Option<Message>, server: SocketAddr) -> Status {
    let Some(resp) = resp else {
        return Status::Fail(format!("no reply from {server}"))
    };

    if resp.response_code() != ResponseCode::NoError {
        return Status::Fail(format!("{server} answered {}", resp.response_code()));
    }

    let ips: Vec<_> = resp
        .answers()
        .iter()
        .filter_map(|r| match r.data() {
            Some(RData::A(a)) => Some(a.0),
            _ => None,
        })
        .collect();

    if ips.is_empty() {
        Status::Fail("no A record in answer".to_string())
    } else if ips.iter().all(|ip| ip.is_private()) {
        Status::Pass(format!("{ips:?} (private)"))
    } else {
        Status::Fail(format!("{ips:?} includes a public IP"))
    }
}
fn query_tcp(packet: &[u8], server: SocketAddr) -> Option<Message> {
    println!("----TCP-----");
    let mut stream = TcpStream::connect_timeout(&server, Duration::from_secs(2)).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    let len = (packet.len() as u16).to_be_bytes();
    stream.write_all(&len).ok()?;
    stream.write_all(&packet).ok()?;

    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).ok()?;
    let resp_len = u16::from_be_bytes(len_buf) as usize;

    let mut resp_buf = vec![0u8; resp_len];
    stream.read_exact(&mut resp_buf).ok()?;
    Message::from_vec(&resp_buf).ok()
}

fn run(step: &str, status: Status) -> bool {
    report(step, &status);
    matches!(status, Status::Pass(_))
}

fn check_tunnel(ip: IpAddr) -> Status {
    match route_iface(ip) {
        Some(iface) if iface.starts_with("utun") => Status::Pass(format!("{ip} via {iface}")),
        Some(iface) => Status::Fail(format!("{ip} via {iface}, not the VPN")),
        None => Status::Fail(format!("no route info for {ip}"))
    }
}

fn check_resolver(name: &str, expected: IpAddr) -> Status {
    let resolvers = parse_resolver(&os_dns_config());

    match pick_resolver(&resolvers, name) {
        None => Status::Fail("no resolver matched".to_string()),
        Some(r) if r.nameservers.contains(&expected.to_string()) => Status::Pass(format!("uses {expected} via {}", r.iface.as_deref().unwrap_or("?"))),
        Some(r) => Status::Fail(format!("OS uses {:?}, not {expected}", r.nameservers))
    }
}

enum Status {
    Pass(String),
    Fail(String)
}

fn report(step: &str, status: &Status) {
    match status {
        Status::Pass(msg) => println!("[✓] {step:<12} {msg}"),
        Status::Fail(msg) => println!("[✗] {step:<12} {msg}")
    }
}

fn route_iface(ip: IpAddr) -> Option<String> {
    let out = Command::new("route")
        .args(["-n", "get", &ip.to_string()])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);

    text.lines()
        .find_map(|l| l.trim().strip_prefix("interface:"))
        .map(|s| s.trim().to_string())
}


fn pick_resolver<'a>(list: &'a [Resolver], name: &str) -> Option<&'a Resolver> {
    let name = name.trim_end_matches('.');

    let matched  = list
        .iter()
        .filter(|r| match &r.domain {
            Some(d) => name == d || name.ends_with(&format!(".{d}")),
            None => false
        })
        .max_by_key(|r| r.domain.as_ref().map(|d| d.len()).unwrap_or(0));

    matched.or_else(|| list.iter().find(|r| r.domain.is_none()))
}

fn parse_resolver(text: &str) -> Vec<Resolver> {
    let mut list: Vec<Resolver> = Vec::new();

    for line in text.lines() {
        let line = line.trim();
        if line.starts_with("resolver #") {
            list.push(Resolver::default());
            continue;
        }

        let Some(cur) = list.last_mut() else { continue };
        let Some((key, value)) = line.split_once(" : ") else { continue };
        let (key, value) = (key.trim(), value.trim());

        if key == "domain" {
            cur.domain = Some(value.to_string());
        } else if key.starts_with("nameserver[") {
            cur.nameservers.push(value.to_string());
        } else if key == "if_index" {
            cur.iface = value.split('(').nth(1).map(|s| s.trim_end_matches(')').to_string());
        }
    }

    list
}

fn os_dns_config() -> String {
    let out = Command::new("scutil")
        .arg("--dns")
        .output()
        .expect("failed to run scutil");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn query_udp(packet: &[u8], server: SocketAddr) -> Option<Message> {
    let sock : UdpSocket = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.set_read_timeout(Some(Duration::from_secs(2))).ok()?;

    let start : Instant = Instant::now();
    sock.send_to(&packet, server).ok()?;

    let mut buf: [u8; 512] = [0u8; 512];
    match sock.recv_from(&mut buf) {
        Ok((n, _)) => {
            println!("[{server}] latency {} ms", start.elapsed().as_millis());
            Message::from_vec(&buf[..n]).ok()
        },
        Err(e) => {
            println!("no reply: {e}");
            None
        }
    }
}

fn label(ip: std::net::Ipv4Addr) -> &'static str {
    if ip.is_private() {
        "PRIVATE"
    } else if ip.is_loopback() {
        "LOOPBACK"
    } else {
        "PUBLIC"
    }
}