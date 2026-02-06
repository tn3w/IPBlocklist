use flate2::read::GzDecoder;
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};

#[derive(Debug)]
struct AsnRecord {
    range_start: u128,
    range_end: u128,
    asn: u32,
    country: String,
    description: String,
}

fn parse_ip(ip_str: &str) -> Option<u128> {
    if let Ok(addr) = ip_str.parse::<std::net::Ipv4Addr>() {
        return Some(u32::from(addr) as u128);
    }
    if let Ok(addr) = ip_str.parse::<std::net::Ipv6Addr>() {
        return Some(u128::from(addr));
    }
    None
}

pub fn process_asn_database(input_path: &str, output_path: &str) -> std::io::Result<()> {
    println!("Processing ASN database from {}...", input_path);

    let file = File::open(input_path)?;
    let decoder = GzDecoder::new(file);
    let reader = BufReader::new(decoder);

    let mut records = Vec::new();
    let mut line_count = 0;

    for line in reader.lines() {
        let line = line?;
        line_count += 1;

        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() < 5 {
            continue;
        }

        let range_start = match parse_ip(parts[0]) {
            Some(ip) => ip,
            None => continue,
        };

        let range_end = match parse_ip(parts[1]) {
            Some(ip) => ip,
            None => continue,
        };

        let asn = match parts[2].parse::<u32>() {
            Ok(n) => n,
            Err(_) => continue,
        };

        let country = parts[3].to_string();
        let description = parts[4].to_string();

        records.push(AsnRecord {
            range_start,
            range_end,
            asn,
            country,
            description,
        });

        if line_count % 100000 == 0 {
            println!("Processed {} lines, {} valid records", line_count, records.len());
        }
    }

    println!("Total records: {}", records.len());
    println!("Writing output to {}...", output_path);

    let file = File::create(output_path)?;
    let mut writer = BufWriter::new(file);

    write!(writer, "{{\"records\":[")?;

    for (index, record) in records.iter().enumerate() {
        if index > 0 {
            writer.write_all(b",")?;
        }

        write!(
            writer,
            "[{},{},{},\"{}\",\"{}\"]",
            record.range_start,
            record.range_end,
            record.asn,
            record.country.replace('"', "\\\""),
            record.description.replace('"', "\\\"")
        )?;
    }

    writer.write_all(b"]}}")?;
    writer.flush()?;

    println!("Successfully wrote {} ASN records", records.len());
    Ok(())
}

fn main() -> std::io::Result<()> {
    let input = "ip2asn-combined.tsv.gz";
    let output = "asn-data.json";

    process_asn_database(input, output)?;

    println!("ASN database processing complete!");
    Ok(())
}
