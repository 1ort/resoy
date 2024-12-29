#[cfg(not(windows))]
extern crate termion;
use hickory_client::rr::{Record, RecordType};
#[cfg(not(windows))]
use termion::color::{AnsiValue, Fg, Reset};

pub struct OutputConfig {
    format_seconds: bool,
    ansi: bool,
}

impl OutputConfig {
    pub fn new(
        format_seconds: bool,
        ansi: bool,
    ) -> Self {
        Self {
            format_seconds,
            ansi,
        }
    }
}
pub struct RecordFormatter<'a> {
    result: Record,
    config: &'a OutputConfig,
}

impl<'a> RecordFormatter<'a> {
    pub fn new(
        result: Record,
        config: &'a OutputConfig,
    ) -> Self {
        Self {
            result,
            config,
        }
    }

    #[cfg(not(windows))]
    pub fn format(&self) -> String {
        if !self.config.ansi {
            format!(
                "{:>5} {} {:>12} {}",
                self.rormat_record_type(),
                self.format_name(),
                self.format_duration(),
                self.format_payload(),
            )
        } else {
            let color = Fg(self.get_record_color());
            let reset_color = Fg(Reset);

            let name_color = Fg(AnsiValue(75));

            format!(
                "{color}{:>5}{reset_color} {name_color}{}{reset_color} {:>12} {}",
                self.rormat_record_type(),
                self.format_name(),
                self.format_duration(),
                self.format_payload(),
            )
        }
    }

    #[cfg(windows)]
    pub fn format(
        &self,
        config: OutputConfig,
    ) {
        println!(
            "{:>5} {} {:>12} {}",
            self.record_type.to_string(),
            self.name,
            Self::format_duration(self.ttl_secods, &self.config),
            self.payload,
        )
    }

    fn rormat_record_type(&self) -> String {
        self.result.record_type().to_string()
    }

    fn format_name(&self) -> String {
        self.result.name().to_string()
    }

    fn format_payload(&self) -> String {
        if let Some(result_data) = self.result.data() {
            result_data.to_string()
        } else {
            String::default()
        }
    }

    fn format_duration(&self) -> String {
        let seconds = self.result.ttl();

        if !self.config.format_seconds {
            return format!("{}", seconds);
        }

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

    #[cfg(not(windows))]
    fn get_record_color(&self) -> AnsiValue {
        use RecordType::*;
        match self.result.record_type() {
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
}
