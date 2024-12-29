use std::{collections::HashSet, fmt::Display, str::FromStr};

use clap::{Parser, ValueEnum};
use hickory_client::{
    client::{Client, SyncClient},
    error::ClientResult,
    op::DnsResponse,
    rr::{DNSClass, Name, Record, RecordType},
    tcp::TcpClientConnection,
    udp::UdpClientConnection,
};
#[cfg(not(windows))]
extern crate termion;
#[cfg(not(windows))]
use termion::color::{AnsiValue, Fg, Reset};

/// Simple dns resolve tool
#[derive(Parser)]
#[command(version, about)]
struct Cli {
    /// domain name to resolve
    name: String,

    /// record types to check separated by space
    #[arg(default_values_t=vec![String::from("A")], value_delimiter = ' ', num_args=1..)]
    record_types: Vec<String>,

    /// dns server to use
    #[arg(short, long, default_value_t = String::from("1.1.1.1:53"))]
    server: String,

    /// disable ansi-colored output
    #[arg(long, default_value_t = false)]
    no_ansi: bool,

    /// do not format ttl
    #[arg(long, default_value_t = false)]
    seconds: bool,

    // Connection type
    #[arg(long, short, default_value_t=ConnectionType::Udp)]
    connection: ConnectionType,
}

#[derive(ValueEnum, Clone, Debug)]
#[clap(rename_all = "kebab_case")]
enum ConnectionType {
    Udp,
    Tcp,
}

impl Display for ConnectionType {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        let s = match self {
            Self::Udp => "udp",
            Self::Tcp => "tcp",
        };
        write!(f, "{}", s)?;
        Ok(())
    }
}

fn main() {
    let cli = Cli::parse();

    let client = DnsClient::new(cli.connection, &cli.server);
    let name = parse_domain_name(&cli.name);

    let record_types = parse_record_types(cli.record_types);

    let mut results: Vec<Record> = vec![];

    for record_type in record_types {
        let response: DnsResponse = client.query(&name, DNSClass::IN, record_type).unwrap();
        let answers: &[Record] = response.answers();
        results.extend_from_slice(answers);
    }

    for result in results {
        let record_type = result.record_type();
        let name = result.name().to_string();
        let ttl = if cli.seconds {
            result.ttl().to_string()
        } else {
            format_duration(result.ttl())
        };

        let payload = {
            if let Some(result_data) = result.data() {
                result_data.to_string()
            } else {
                String::default()
            }
        };

        RecordOutput {
            record_type,
            name,
            ttl,
            payload,
        }
        .render(!cli.no_ansi);
    }
}

struct RecordOutput {
    record_type: RecordType,
    name: String,
    ttl: String,
    payload: String,
}

impl RecordOutput {
    #[cfg(not(windows))]
    fn render(
        &self,
        ansi: bool,
    ) {
        if !ansi {
            println!(
                "{:>5} {} {:>12} {}",
                self.record_type.to_string(),
                self.name,
                self.ttl,
                self.payload,
            )
        } else {
            let color = Fg(record_type_to_ansi(self.record_type));
            let reset_color = Fg(Reset);

            let name_color = Fg(AnsiValue(75));

            println!(
                "{color}{:>5}{reset_color} {name_color}{}{reset_color} {:>12} {}",
                self.record_type.to_string(),
                self.name,
                self.ttl,
                self.payload,
            )
        }
    }

    #[cfg(windows)]
    fn render(
        &self,
        _ansi: bool,
    ) {
        println!(
            "{:>5} {} {:>12} {}",
            self.record_type.to_string(),
            self.name,
            self.ttl,
            self.payload,
        )
    }
}

fn parse_domain_name(name: &str) -> Name {
    Name::from_str(name).expect("invalid name")
}

enum DnsClient {
    Tcp(SyncClient<TcpClientConnection>),
    Udp(SyncClient<UdpClientConnection>),
}

impl DnsClient {
    fn new(
        connection_type: ConnectionType,
        raw_addr: &str,
    ) -> Self {
        {
            let socket_addr = raw_addr
                .parse()
                .unwrap_or_else(|_| panic!("Cannot parse dns server address: {:?}", raw_addr));

            match connection_type {
                ConnectionType::Udp => {
                    Self::Udp(SyncClient::new(
                        UdpClientConnection::new(socket_addr).unwrap_or_else(|_| {
                            panic!("Cannot establish udp connection with {:?}", raw_addr)
                        }),
                    ))
                },
                ConnectionType::Tcp => {
                    Self::Tcp(SyncClient::new(
                        TcpClientConnection::new(socket_addr).unwrap_or_else(|_| {
                            panic!("Cannot establish tcp connection with {:?}", raw_addr)
                        }),
                    ))
                },
            }
        }
    }

    fn query(
        &self,
        name: &Name,
        query_class: DNSClass,
        query_type: RecordType,
    ) -> ClientResult<DnsResponse> {
        match self {
            Self::Tcp(client) => client.query(name, query_class, query_type),
            Self::Udp(client) => client.query(name, query_class, query_type),
        }
    }
}

fn parse_record_types(raw: Vec<String>) -> Vec<RecordType> {
    let unique: HashSet<String> = HashSet::from_iter(raw);

    unique
        .iter()
        .map(|value| {
            RecordType::from_str(value)
                .unwrap_or_else(|_| panic!("Unknown record type: {:?}", value))
        })
        .collect()
}

#[cfg(not(windows))]
fn record_type_to_ansi(rt: RecordType) -> AnsiValue {
    use RecordType::*;
    match rt {
        A => AnsiValue(1),           // Red
        AAAA => AnsiValue(2),        // Green
        ANAME => AnsiValue(3),       // Yellow
        ANY => AnsiValue(4),         // Blue
        AXFR => AnsiValue(5),        // Magenta
        CAA => AnsiValue(6),         // Cyan
        CDS => AnsiValue(7),         // Light gray
        CDNSKEY => AnsiValue(8),     // Dark gray
        CSYNC => AnsiValue(9),       // Light red
        DNSKEY => AnsiValue(10),     // Light green
        DS => AnsiValue(11),         // Light yellow
        HINFO => AnsiValue(12),      // Light blue
        HTTPS => AnsiValue(13),      // Light magenta
        IXFR => AnsiValue(14),       // Light cyan
        KEY => AnsiValue(15),        // White
        MX => AnsiValue(38),         // Bright red
        NAPTR => AnsiValue(17),      // Bright green
        NS => AnsiValue(18),         // Bright yellow
        NSEC => AnsiValue(19),       // Bright blue
        NSEC3 => AnsiValue(20),      // Bright magenta
        NSEC3PARAM => AnsiValue(21), // Bright cyan
        NULL => AnsiValue(22),       // Bright white
        OPENPGPKEY => AnsiValue(23), // Default color
        OPT => AnsiValue(24),        // Default color
        PTR => AnsiValue(25),        // Default color
        RRSIG => AnsiValue(26),      // Default color
        SIG => AnsiValue(27),        // Default color
        SOA => AnsiValue(28),        // Default color
        SRV => AnsiValue(29),        // Default color
        SSHFP => AnsiValue(30),      // Default color
        SVCB => AnsiValue(31),       // Default color
        TLSA => AnsiValue(32),       // Default color
        TSIG => AnsiValue(33),       // Default color
        TXT => AnsiValue(34),        // Default color
        Unknown(_) => AnsiValue(35), // Default color
        ZERO => AnsiValue(36),       // Default color
        _ => AnsiValue(37),
    }
}

fn format_duration(seconds: u32) -> String {
    if seconds < 60 {
        format!("{}s", seconds)
    } else if seconds < 60 * 60 {
        format!("{}m{:02}s", seconds / 60, seconds % 60)
    } else if seconds < 60 * 60 * 24 {
        format!(
            "{}h{:02}m{:02}s",
            seconds / 3600,
            (seconds % 3600) / 60,
            seconds % 60
        )
    } else {
        format!(
            "{}d{}h{:02}m{:02}s",
            seconds / 86400,
            (seconds % 86400) / 3600,
            (seconds % 3600) / 60,
            seconds % 60
        )
    }
}
