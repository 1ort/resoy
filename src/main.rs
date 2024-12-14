use std::{collections::HashSet, str::FromStr};

use clap::Parser;
use hickory_client::{
    client::{Client, SyncClient},
    op::DnsResponse,
    rr::{DNSClass, Name, Record, RecordType},
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
}

fn main() {
    let cli = Cli::parse();

    let client = make_dns_client(&cli.server);
    let name = parse_domain_name(&cli.name);

    let record_types = parse_record_types(cli.record_types);

    let mut results: Vec<Record> = vec![];

    for record_type in record_types {
        let response: DnsResponse = client.query(&name, DNSClass::IN, record_type).unwrap();
        let answers: &[Record] = response.answers();
        results.extend_from_slice(answers);
    }

    for result in results {
        let record_type = result.record_type().to_string();
        let name = result.name().to_string();
        let ttl = format_duration(result.ttl());

        let payload = {
            if let Some(result_data) = result.data() {
                result_data.to_string()
            } else {
                String::default()
            }
        };

        println!("{record_type:>5} {name} {ttl:>12} {payload}")
    }
}

fn parse_domain_name(name: &str) -> Name {
    Name::from_str(name).expect("invalid name")
}

fn make_dns_client(raw_addr: &str) -> SyncClient<UdpClientConnection> {
    let socket_addr = raw_addr
        .parse()
        .unwrap_or_else(|_| panic!("Cannot parse dns server address: {:?}", raw_addr));
    let conn = UdpClientConnection::new(socket_addr)
        .unwrap_or_else(|_| panic!("Cannot establish udp connection with {:?}", raw_addr));
    SyncClient::new(conn)
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
