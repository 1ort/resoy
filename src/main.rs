mod format;

use std::{collections::HashSet, fmt::Display, str::FromStr};

use clap::{Parser, ValueEnum};
use format::{OutputConfig, RecordFormatter};
use hickory_client::{
    client::{Client, SyncClient},
    error::ClientResult,
    op::DnsResponse,
    rr::{DNSClass, Name, Record, RecordType},
    tcp::TcpClientConnection,
    udp::UdpClientConnection,
};

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

    let output_config = OutputConfig::new(!cli.seconds, !cli.no_ansi);

    for result in results {
        println!("{}", RecordFormatter::new(result, &output_config).format())
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
