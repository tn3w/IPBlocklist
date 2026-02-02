use memmap2::Mmap;
use rayon::prelude::*;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufWriter, Write};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

const CHUNK_SIZE: usize = 10000;
const PROGRESS_INTERVAL: usize = 10;
const PROXY_POSITION: [usize; 13] = [0, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2];
const USAGE_POSITION: [usize; 13] = [0, 0, 0, 0, 0, 0, 8, 8, 8, 8, 8, 8, 8];
const THREAT_POSITION: [usize; 13] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 12, 12, 12, 12];

const CATEGORIES: &[(&str, &str)] = &[
    ("VPN", "ip2proxy_vpn"),
    ("TOR", "ip2proxy_tor"),
    ("PUB", "ip2proxy_pub"),
    ("WEB", "ip2proxy_web"),
    ("RES", "ip2proxy_res"),
    ("DCH", "ip2proxy_dch"),
    ("COM", "ip2proxy_com"),
    ("EDU", "ip2proxy_edu"),
    ("GOV", "ip2proxy_gov"),
    ("ISP", "ip2proxy_isp"),
    ("MOB", "ip2proxy_mob"),
    ("SPAM", "ip2proxy_spam"),
    ("SCANNER", "ip2proxy_scanner"),
    ("BOTNET", "ip2proxy_botnet"),
    ("MALWARE", "ip2proxy_malware"),
    ("PHISHING", "ip2proxy_phishing"),
];

#[derive(Debug)]
struct DatabaseHeader {
    database_type: u8,
    column_count: u8,
    ipv4_count: u32,
    ipv4_base_address: u32,
}

struct ListData {
    addresses: Vec<u64>,
    networks: Vec<[u64; 2]>,
}

struct Output {
    timestamp: u64,
    feeds: HashMap<String, ListData>,
}

struct Database {
    memory: Mmap,
    header: DatabaseHeader,
}

impl Database {
    fn open(path: &str) -> std::io::Result<Self> {
        let file = File::open(path)?;
        let memory = unsafe { Mmap::map(&file)? };

        let header = DatabaseHeader {
            database_type: memory[0],
            column_count: memory[1],
            ipv4_count: u32::from_le_bytes([memory[5], memory[6], memory[7], memory[8]]),
            ipv4_base_address: u32::from_le_bytes([memory[9], memory[10], memory[11], memory[12]]),
        };

        Ok(Self { memory, header })
    }

    fn read_u32(&self, offset: usize) -> u32 {
        if offset == 0 || offset + 3 > self.memory.len() {
            return 0;
        }
        let position = offset - 1;
        u32::from_le_bytes([
            self.memory[position],
            self.memory[position + 1],
            self.memory[position + 2],
            self.memory[position + 3],
        ])
    }

    fn read_string(&self, offset: usize) -> &str {
        if offset == 0 || offset > self.memory.len() {
            return "-";
        }
        let position = offset - 1;
        if position >= self.memory.len() {
            return "-";
        }
        let length = self.memory[position] as usize;
        if position + 1 + length > self.memory.len() {
            return "-";
        }
        let start = position + 1;
        let end = start + length;
        std::str::from_utf8(&self.memory[start..end]).unwrap_or("-")
    }

    fn read_row(&self, index: u32) -> Option<(u32, u32)> {
        let row_size = self.header.column_count as usize * 4;
        let base = self.header.ipv4_base_address as usize;
        let offset = base + index as usize * row_size;

        if offset + row_size > self.memory.len() {
            return None;
        }

        let ip_from = u32::from_le_bytes([
            self.memory[offset],
            self.memory[offset + 1],
            self.memory[offset + 2],
            self.memory[offset + 3],
        ]);
        let ip_to = u32::from_le_bytes([
            self.memory[offset + row_size - 4],
            self.memory[offset + row_size - 3],
            self.memory[offset + row_size - 2],
            self.memory[offset + row_size - 1],
        ]);

        Some((ip_from, ip_to))
    }

    fn read_field(&self, base: usize, position: usize) -> String {
        if position == 0 {
            return String::from("-");
        }
        let pointer_offset = base + 4 * (position - 1);
        let string_pointer = self.read_u32(pointer_offset) as usize;
        if string_pointer > 0 && string_pointer < self.memory.len() {
            self.read_string(string_pointer + 1).to_uppercase()
        } else {
            String::from("-")
        }
    }

    fn read_record(&self, index: u32) -> (String, String, String) {
        let row_size = self.header.column_count as usize * 4;
        let base = self.header.ipv4_base_address as usize;
        let offset = base + index as usize * row_size;

        let database_type = self.header.database_type;
        let proxy_pos = field_position(&PROXY_POSITION, database_type);
        let usage_pos = field_position(&USAGE_POSITION, database_type);
        let threat_pos = field_position(&THREAT_POSITION, database_type);

        let proxy = self.read_field(offset, proxy_pos);
        let usage = self.read_field(offset, usage_pos);
        let threat = self.read_field(offset, threat_pos);

        (proxy, usage, threat)
    }
}

fn field_position(positions: &[usize; 13], database_type: u8) -> usize {
    positions.get(database_type as usize).copied().unwrap_or(0)
}

fn create_empty_feeds() -> HashMap<String, (Vec<u64>, Vec<[u64; 2]>)> {
    CATEGORIES
        .iter()
        .map(|(_, name)| (name.to_string(), (Vec::new(), Vec::new())))
        .collect()
}

fn create_empty_sets() -> HashMap<String, (HashSet<u64>, HashSet<[u64; 2]>)> {
    CATEGORIES
        .iter()
        .map(|(_, name)| (name.to_string(), (HashSet::new(), HashSet::new())))
        .collect()
}

fn categorize(
    feeds: &mut HashMap<String, (Vec<u64>, Vec<[u64; 2]>)>,
    from: u32,
    to: u32,
    fields: &[&str],
) {
    let range = if from == to - 1 {
        (Some(from as u64), None)
    } else {
        (None, Some([from as u64, (to - 1) as u64]))
    };

    for (pattern, name) in CATEGORIES {
        if fields.iter().any(|field| field.contains(pattern)) {
            let entry = feeds.get_mut(*name).unwrap();
            if let Some(addr) = range.0 {
                entry.0.push(addr);
            }
            if let Some(net) = range.1 {
                entry.1.push(net);
            }
        }
    }
}

fn extract_proxy_ips(path: &str) -> std::io::Result<HashMap<String, ListData>> {
    let database = Database::open(path)?;
    let total = database.header.ipv4_count;

    println!("Database info:");
    println!("  DB Type: {}", database.header.database_type);
    println!("  DB Column: {}", database.header.column_count);
    println!("  IPv4 Count: {}", total);
    println!("\nExtracting {} IPv4 records...", total);

    let shared_feeds = Mutex::new(create_empty_sets());
    let chunks: Vec<_> = (0..total).step_by(CHUNK_SIZE).collect();
    let chunk_count = chunks.len();

    println!("Processing {} chunks...", chunk_count);

    chunks.par_iter().enumerate().for_each(|(index, &start)| {
        let end = (start + CHUNK_SIZE as u32).min(total);
        let mut local_feeds = create_empty_feeds();

        for record_index in start..end {
            let Some((from, to)) = database.read_row(record_index) else {
                continue;
            };
            let (proxy, usage, threat) = database.read_record(record_index);
            categorize(&mut local_feeds, from, to, &[&proxy, &usage, &threat]);
        }

        let mut shared = shared_feeds.lock().unwrap();
        for (key, (addresses, networks)) in local_feeds {
            let entry = shared.get_mut(&key).unwrap();
            entry.0.extend(addresses);
            entry.1.extend(networks);
        }

        if (index + 1) % PROGRESS_INTERVAL == 0 || index + 1 == chunk_count {
            let percent = ((index + 1) as f64 / chunk_count as f64) * 100.0;
            println!(
                "Progress: {}/{} chunks ({:.1}%)",
                index + 1,
                chunk_count,
                percent
            );
        }
    });

    println!("Extraction complete! Processing feeds...");

    let feeds = shared_feeds.into_inner().unwrap();
    let mut result = HashMap::new();

    for (name, (address_set, network_set)) in feeds {
        let mut addresses: Vec<u64> = address_set.into_iter().collect();
        addresses.sort_unstable();

        let mut networks: Vec<[u64; 2]> = network_set.into_iter().collect();
        networks.sort_unstable();

        if !addresses.is_empty() || !networks.is_empty() {
            println!(
                "{}: {} IPs, {} ranges",
                name,
                addresses.len(),
                networks.len()
            );
            result.insert(
                name,
                ListData {
                    addresses,
                    networks,
                },
            );
        }
    }

    Ok(result)
}

fn write_json(output: &Output) -> std::io::Result<()> {
    let file = File::create("data-ip2proxy.json")?;
    let mut writer = BufWriter::new(file);

    write!(writer, "{{\"timestamp\":{},\"feeds\":{{", output.timestamp)?;

    for (index, (name, data)) in output.feeds.iter().enumerate() {
        if index > 0 {
            writer.write_all(b",")?;
        }

        write!(writer, "\"{}\":{{\"addresses\":[", name)?;

        for (i, addr) in data.addresses.iter().enumerate() {
            if i > 0 {
                writer.write_all(b",")?;
            }
            write!(writer, "{}", addr)?;
        }

        writer.write_all(b"],\"networks\":[")?;

        for (i, net) in data.networks.iter().enumerate() {
            if i > 0 {
                writer.write_all(b",")?;
            }
            write!(writer, "[{},{}]", net[0], net[1])?;
        }

        writer.write_all(b"]}")?;
    }

    writer.write_all(b"}}")?;
    writer.flush()?;
    Ok(())
}

fn main() -> std::io::Result<()> {
    let path = "IP2PROXY-LITE-PX10.BIN";
    let feeds = extract_proxy_ips(path)?;

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let output = Output { timestamp, feeds };

    write_json(&output)?;

    println!("Saved data-ip2proxy.json with {} feeds", output.feeds.len());

    Ok(())
}