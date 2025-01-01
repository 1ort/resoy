mod format;

use std::{
    collections::HashSet,
    fmt::{Debug, Display},
    str::FromStr,
};

use clap::{Parser, ValueEnum};
use format::{OutputConfig, RecordFormatter};
use hickory_client::{
    client::{AsyncClient, Client, ClientHandle, ClientStreamingResponse, SyncClient},
    error::{ClientError, ClientResult},
    op::DnsResponse,
    proto::{iocompat::AsyncIoTokioAsStd, xfer::DnsHandle},
    rr::{DNSClass, Name, Record, RecordType},
    tcp::{TcpClientConnection, TcpClientStream},
    udp::{UdpClientConnection, UdpClientStream},
};
use tokio::{self, net::TcpStream as TokioTcpStream};
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

impl Cli {
    fn parse_record_types(&self) -> Result<Vec<RecordType>, AppError> {
        self.record_types
            .iter()
            .collect::<HashSet<_>>()
            .into_iter()
            .map(|value| {
                RecordType::from_str(value).map_err(|_| AppError::UnknownRecordType(value.clone()))
            })
            .collect()
    }

    fn parse_domain_name(&self) -> Result<Name, AppError> {
        Name::from_str(&self.name).map_err(|_| AppError::InvalidDomainName(self.name.clone()))
    }

    fn parse_output_config(&self) -> OutputConfig {
        OutputConfig::new(!self.seconds, !self.no_ansi)
    }
}

#[derive(ValueEnum, Clone, Debug, Copy)]
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

enum AppError {
    InvalidDomainName(String),
    UnknownRecordType(String),
    InvalidDnsServer(String),
    DNSServerUnreachable(ConnectionType, String),
    QueryError(ClientError),
}

impl Debug for AppError {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        match self {
            Self::InvalidDomainName(domain) => write!(f, "Invalid name: {:?}", domain),
            Self::UnknownRecordType(record_type) => {
                write!(f, "Cannot parse record type: {:?}", record_type)
            },
            Self::InvalidDnsServer(host) => {
                write!(f, "Cannot parse DNS server address: {:?}", host)
            },
            Self::DNSServerUnreachable(connection_type, host) => {
                write!(
                    f,
                    "Cannot establish {} connection with {:?}",
                    connection_type, host
                )
            },
            Self::QueryError(client_error) => {
                write!(f, "Cannot send DNS query: {}", client_error)
            },
        }
    }
}
#[tokio::main]
async fn main() -> Result<(), AppError> {
    let cli = Cli::parse();

    let client = DnsClient::new(cli.connection, &cli.server).await?;
    let name = cli.parse_domain_name()?;
    let record_types = cli.parse_record_types()?;
    let output_config = cli.parse_output_config();

    let mut results: Vec<Record> = Vec::with_capacity(record_types.len());

    tokio::join!();

    for record_type in record_types {
        let response: DnsResponse = client
            .query(&name, DNSClass::IN, record_type)
            .map_err(AppError::QueryError)?;
        let answers: &[Record] = response.answers();
        results.extend_from_slice(answers);
    }

    for result in results {
        println!("{}", RecordFormatter::new(result, &output_config).format())
    }
    Ok(())
}

// enum DnsClient {
//     Tcp(AsyncClient<TcpClientConnection>),
//     Udp(AsyncClient<UdpClientConnection>),
// }

struct DnsClient(AsyncClient);

impl DnsClient {
    async fn new(
        connection_type: ConnectionType,
        raw_addr: &str,
    ) -> Result<Self, AppError> {
        let socket_addr = raw_addr
            .parse()
            .map_err(|_| AppError::InvalidDnsServer(raw_addr.to_owned()))?;

        match connection_type {
            ConnectionType::Tcp => {
                let (stream, sender) =
                    TcpClientStream::<AsyncIoTokioAsStd<TokioTcpStream>>::new(socket_addr);
                let (client, bg) = AsyncClient::new(stream, sender, None).await.map_err(|_| {
                    AppError::DNSServerUnreachable(connection_type, raw_addr.to_owned())
                })?;
                tokio::spawn(bg);
                return Ok(DnsClient(client));
            },
            ConnectionType::Udp => {
                unimplemented!();
            },
        };
    }

    fn query(
        &self,
        name: Name,
        query_class: DNSClass,
        query_type: RecordType,
    ) -> ClientResponse<<AsyncClient as DnsHandle>::Response> {
        self.0.query(name, query_class, query_type)
    }
}
