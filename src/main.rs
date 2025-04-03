use clap::Parser;
use csv::ReaderBuilder;
use regex::Regex;
use serde_json::Value;
use std::error::Error;
use std::fs::File;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to the CSV file to process
    file: PathBuf,
}

/// Transform values inside tdx_tdg_vp_enter_exit_info to hex format
fn transform_tdx_exit_info(text: &str) -> String {
    let tdx_exit_regex = Regex::new(r"(rax|rcx|rdx|rsi|rdi|r\d+): (\d+)").unwrap();

    tdx_exit_regex
        .replace_all(text, |caps: &regex::Captures| {
            let reg = &caps[1];
            let num = caps[2].parse::<u64>().unwrap_or(0);
            format!("{}: 0x{:x}", reg, num)
        })
        .to_string()
}

/// Transform TdxL2EnterGuestState contents to hex format
fn transform_tdx_guest_state(text: &str) -> String {
    let tdx_gpr_array_regex = Regex::new(r"\[([0-9, ]+)\]").unwrap();
    let tdx_gpr_field_regex = Regex::new(r"(rflags|rip|ssp|rvi|svi): (\d+)").unwrap();

    // Transform the array values to hex
    let transformed = tdx_gpr_array_regex.replace_all(text, |caps: &regex::Captures| {
        let numbers_str = &caps[1];
        let numbers: Vec<String> = numbers_str
            .split(',')
            .map(|s| match s.trim().parse::<u64>() {
                Ok(num) => format!("0x{:x}", num),
                Err(_) => s.trim().to_string(),
            })
            .collect();
        format!("[{}]", numbers.join(", "))
    });

    // Transform individual field values to hex
    tdx_gpr_field_regex
        .replace_all(&transformed, |caps: &regex::Captures| {
            let field = &caps[1];
            let num = caps[2].parse::<u64>().unwrap_or(0);
            format!("{}: 0x{:x}", field, num)
        })
        .to_string()
}

/// Transform SegmentRegister values to hex format
fn transform_segment_register(text: &str) -> String {
    let segment_register_regex = Regex::new(r"(base|limit|selector|attributes): (\d+)").unwrap();

    segment_register_regex
        .replace_all(text, |caps: &regex::Captures| {
            let field = &caps[1];
            let num = caps[2].parse::<u64>().unwrap_or(0);
            format!("{}: 0x{:x}", field, num)
        })
        .to_string()
}

/// Format a numerical value as hex if possible
fn format_value_as_hex(key: &str, value: &Value) -> String {
    if value.is_number() {
        // Handle unsigned integers
        if let Some(num) = value.as_u64() {
            format!(" {}=0x{:x}", key, num)
        }
        // Handle signed integers
        else if let Some(num) = value.as_i64() {
            format!(" {}=0x{:x}", key, num)
        }
        // Fall back to default for floats or other numeric types
        else {
            format!(" {}={}", key, value)
        }
    } else {
        // Non-numeric values
        format!(" {}={}", key, value)
    }
}

/// Process a single message field and convert it to the desired output format
fn process_message(message_field: &str) -> String {
    // Skip empty fields
    if message_field.is_empty() {
        return String::new();
    }

    // Parse the JSON message, return raw message on failure
    let json: Value = match serde_json::from_str(message_field) {
        Ok(json) => json,
        Err(_) => return message_field.to_string(),
    };

    // Extract required fields
    let timestamp = json.get("timestamp").and_then(Value::as_str);
    let level = json.get("level").and_then(Value::as_str);
    let target = json.get("target").and_then(Value::as_str);
    let fields = json.get("fields");

    // Ensure all required fields are present
    let (timestamp, level, target, fields) = match (timestamp, level, target, fields) {
        (Some(ts), Some(lvl), Some(tgt), Some(flds)) => (ts, lvl, tgt, flds),
        _ => return message_field.to_string(),
    };

    // Default output format
    let mut output = format!("[{}][{}][{}] {}", timestamp, level, target, fields);

    // Extract message and other fields if possible
    let obj = match fields.as_object() {
        Some(o) => o,
        None => return output,
    };

    let message = match obj.get("message").and_then(Value::as_str) {
        Some(msg) => msg,
        None => return output,
    };

    // Start with the timestamp, level, target, and message
    output = format!("[{}][{}][{}] {}", timestamp, level, target, message);

    // Add remaining fields
    for (key, value) in obj {
        if key == "message" {
            continue;
        }

        // Special case: tdx_tdg_vp_enter_exit_info
        if key == "raw_exit" && value.is_string() {
            if let Some(raw_exit_str) = value.as_str() {
                if raw_exit_str.contains("tdx_tdg_vp_enter_exit_info") {
                    let transformed = transform_tdx_exit_info(raw_exit_str);
                    output.push_str(&format!(" {}=\"{}\"", key, transformed));
                    continue;
                }
            }
        }
        // Special case: TdxL2EnterGuestState
        else if key == "gprs" && value.is_string() {
            if let Some(gprs_str) = value.as_str() {
                if gprs_str.contains("TdxL2EnterGuestState") {
                    let transformed = transform_tdx_guest_state(gprs_str);
                    output.push_str(&format!(" {}=\"{}\"", key, transformed));
                    continue;
                }
            }
        }
        // Special case: SegmentRegister
        else if value.is_string() && value.as_str().unwrap().contains("SegmentRegister") {
            if let Some(str_val) = value.as_str() {
                let transformed = transform_segment_register(str_val);
                output.push_str(&format!(" {}=\"{}\"", key, transformed));
                continue;
            }
        }

        // Format regular values
        output.push_str(&format_value_as_hex(key, value));
    }

    output
}

fn main() -> Result<(), Box<dyn Error>> {
    // Parse command line arguments
    let args = Args::parse();

    // Open the CSV file
    let file = File::open(&args.file)?;

    // Create a CSV reader with more flexible parsing options
    let mut rdr = ReaderBuilder::new()
        .flexible(true)
        .double_quote(true)
        .from_reader(file);

    // Skip the header row
    let headers = rdr.headers()?.clone();

    // Find the index of the ExtractedMessage column
    let message_idx = headers
        .iter()
        .position(|h| h == "ExtractedMessage")
        .ok_or("No 'ExtractedMessage' column found in CSV")?;

    // Process each record
    for result in rdr.records() {
        let record = result?;

        if let Some(message_field) = record.get(message_idx) {
            let output = process_message(message_field);
            if !output.is_empty() {
                println!("{}", output);
            }
        }
    }

    Ok(())
}
