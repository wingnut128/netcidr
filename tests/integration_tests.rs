use std::io::Write;
use std::process::{Command, Stdio};

fn run_netcidr(args: &[&str]) -> (String, String, bool) {
    let output = Command::new("cargo")
        .args(["run", "--quiet", "--"])
        .args(args)
        .output()
        .expect("Failed to run netcidr");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    (stdout, stderr, output.status.success())
}

fn run_netcidr_stdin(args: &[&str], input: &str) -> (String, String, bool) {
    let mut child = Command::new("cargo")
        .args(["run", "--quiet", "--"])
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn netcidr");

    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();

    let output = child
        .wait_with_output()
        .expect("Failed to wait for netcidr");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    (stdout, stderr, output.status.success())
}

#[test]
fn test_ipv4_json_output() {
    let (stdout, _, success) = run_netcidr(&["192.168.1.0/24"]);
    assert!(success);

    let json: serde_json::Value = serde_json::from_str(&stdout).expect("Invalid JSON");
    assert_eq!(json["network_address"], "192.168.1.0");
    assert_eq!(json["broadcast_address"], "192.168.1.255");
    assert_eq!(json["prefix_length"], 24);
    assert_eq!(json["usable_hosts"], 254);
    assert_eq!(json["address_type"], "Private (RFC 1918)");
}

#[test]
fn test_ipv4_text_output() {
    let (stdout, _, success) = run_netcidr(&["10.0.0.0/8", "--format", "text"]);
    assert!(success);
    assert!(stdout.contains("IPv4 Subnet Calculator"));
    assert!(stdout.contains("Network Address:   10.0.0.0"));
    assert!(stdout.contains("Broadcast Address: 10.255.255.255"));
    assert!(stdout.contains("Address Type:      Private (RFC 1918)"));
}

#[test]
fn test_ipv6_json_output() {
    let (stdout, _, success) = run_netcidr(&["2001:db8::/32"]);
    assert!(success);

    let json: serde_json::Value = serde_json::from_str(&stdout).expect("Invalid JSON");
    assert_eq!(json["network_address"], "2001:db8::");
    assert_eq!(json["prefix_length"], 32);
    assert_eq!(json["address_type"], "Documentation (RFC 3849)");
}

#[test]
fn test_ipv6_text_output() {
    let (stdout, _, success) = run_netcidr(&["fe80::1/64", "--format", "text"]);
    assert!(success);
    assert!(stdout.contains("IPv6 Subnet Calculator"));
    assert!(stdout.contains("Link-Local Unicast (RFC 4291)"));
}

#[test]
fn test_split_ipv4() {
    let (stdout, _, success) = run_netcidr(&["split", "192.168.0.0/22", "-p", "27", "-n", "5"]);
    assert!(success);

    let json: serde_json::Value = serde_json::from_str(&stdout).expect("Invalid JSON");
    assert_eq!(json["new_prefix"], 27);
    assert_eq!(json["requested_count"], 5);
    assert_eq!(json["subnets"].as_array().unwrap().len(), 5);
    assert_eq!(json["subnets"][0]["network_address"], "192.168.0.0");
    assert_eq!(json["subnets"][1]["network_address"], "192.168.0.32");
}

#[test]
fn test_split_ipv6() {
    let (stdout, _, success) = run_netcidr(&["split", "2001:db8::/32", "-p", "48", "-n", "3"]);
    assert!(success);

    let json: serde_json::Value = serde_json::from_str(&stdout).expect("Invalid JSON");
    assert_eq!(json["new_prefix"], 48);
    assert_eq!(json["subnets"].as_array().unwrap().len(), 3);
}

#[test]
fn test_invalid_ipv4() {
    let (_, stderr, success) = run_netcidr(&["999.999.999.999/24"]);
    assert!(!success);
    assert!(stderr.contains("Error"));
}

#[test]
fn test_invalid_prefix() {
    let (_, stderr, success) = run_netcidr(&["192.168.1.0/33"]);
    assert!(!success);
    assert!(stderr.contains("Error"));
}

#[test]
fn test_file_output() {
    let temp_file = "/tmp/netcidr_test_output.json";
    let (_, _, success) = run_netcidr(&["172.16.0.0/12", "-o", temp_file]);
    assert!(success);

    let content = std::fs::read_to_string(temp_file).expect("Failed to read output file");
    let json: serde_json::Value = serde_json::from_str(&content).expect("Invalid JSON in file");
    assert_eq!(json["network_address"], "172.16.0.0");

    std::fs::remove_file(temp_file).ok();
}

#[test]
fn test_split_too_many_subnets() {
    // /22 can only fit 32 /27 subnets, requesting 100 should fail
    let (_, stderr, success) = run_netcidr(&["split", "192.168.0.0/22", "-p", "27", "-n", "100"]);
    assert!(!success);
    assert!(stderr.contains("Error"));
}

#[test]
fn test_split_ipv4_max() {
    // Test --max option generates all possible subnets
    let (stdout, _, success) = run_netcidr(&["split", "192.168.0.0/22", "-p", "27", "--max"]);
    assert!(success);

    let json: serde_json::Value = serde_json::from_str(&stdout).expect("Invalid JSON");
    // /22 to /27 is 5 bits difference, so 32 subnets
    assert_eq!(json["requested_count"], 32);
    assert_eq!(json["subnets"].as_array().unwrap().len(), 32);
}

#[test]
fn test_split_ipv6_max() {
    // Test --max option for IPv6
    let (stdout, _, success) = run_netcidr(&["split", "2001:db8:abcd::/48", "-p", "52", "--max"]);
    assert!(success);

    let json: serde_json::Value = serde_json::from_str(&stdout).expect("Invalid JSON");
    // /48 to /52 is 4 bits difference, so 16 subnets
    assert_eq!(json["requested_count"], 16);
    assert_eq!(json["subnets"].as_array().unwrap().len(), 16);
}

#[test]
fn test_split_requires_count_or_max() {
    // Neither --count nor --max should fail
    let (_, stderr, success) = run_netcidr(&["split", "192.168.0.0/22", "-p", "27"]);
    assert!(!success);
    assert!(stderr.contains("Error"));
}

#[test]
fn test_direct_ipv4() {
    let (stdout, _, success) = run_netcidr(&["192.168.1.0/24"]);
    assert!(success);

    let json: serde_json::Value = serde_json::from_str(&stdout).expect("Invalid JSON");
    assert_eq!(json["network_address"], "192.168.1.0");
    assert_eq!(json["broadcast_address"], "192.168.1.255");
    assert_eq!(json["prefix_length"], 24);
}

#[test]
fn test_direct_ipv6() {
    let (stdout, _, success) = run_netcidr(&["2001:db8::/32"]);
    assert!(success);

    let json: serde_json::Value = serde_json::from_str(&stdout).expect("Invalid JSON");
    assert_eq!(json["network_address"], "2001:db8::");
    assert_eq!(json["prefix_length"], 32);
    assert_eq!(json["address_type"], "Documentation (RFC 3849)");
}

#[test]
fn test_direct_ipv4_text_format() {
    let (stdout, _, success) = run_netcidr(&["10.0.0.0/8", "--format", "text"]);
    assert!(success);
    assert!(stdout.contains("IPv4 Subnet Calculator"));
    assert!(stdout.contains("Network Address:   10.0.0.0"));
}

#[test]
fn test_contains_ipv4_json() {
    let (stdout, _, success) = run_netcidr(&["contains", "192.168.1.0/24", "192.168.1.100"]);
    assert!(success);

    let json: serde_json::Value = serde_json::from_str(&stdout).expect("Invalid JSON");
    assert_eq!(json["cidr"], "192.168.1.0/24");
    assert_eq!(json["address"], "192.168.1.100");
    assert_eq!(json["contained"], true);
    assert_eq!(json["network_address"], "192.168.1.0");
    assert_eq!(json["broadcast_address"], "192.168.1.255");
}

#[test]
fn test_contains_ipv4_not_contained() {
    let (stdout, _, success) = run_netcidr(&["contains", "192.168.1.0/24", "10.0.0.1"]);
    assert!(success);

    let json: serde_json::Value = serde_json::from_str(&stdout).expect("Invalid JSON");
    assert_eq!(json["contained"], false);
}

#[test]
fn test_contains_ipv6_json() {
    let (stdout, _, success) = run_netcidr(&["contains", "2001:db8::/32", "2001:db8::1"]);
    assert!(success);

    let json: serde_json::Value = serde_json::from_str(&stdout).expect("Invalid JSON");
    assert_eq!(json["contained"], true);
    assert_eq!(json["address"], "2001:db8::1");
}

#[test]
fn test_contains_ipv4_text() {
    let (stdout, _, success) = run_netcidr(&[
        "contains",
        "192.168.1.0/24",
        "192.168.1.100",
        "--format",
        "text",
    ]);
    assert!(success);
    assert!(stdout.contains("Address Containment Check"));
    assert!(stdout.contains("Contained:         Yes"));
    assert!(stdout.contains("Network Address:   192.168.1.0"));
}

#[test]
fn test_contains_invalid_address() {
    let (_, stderr, success) = run_netcidr(&["contains", "192.168.1.0/24", "not-an-ip"]);
    assert!(!success);
    assert!(stderr.contains("Error"));
}

#[test]
fn test_split_count_only_ipv4() {
    let (stdout, _, success) =
        run_netcidr(&["split", "192.168.0.0/22", "-p", "27", "--count-only"]);
    assert!(success);

    let json: serde_json::Value = serde_json::from_str(&stdout).expect("Invalid JSON");
    assert_eq!(json["available_subnets"], "32");
    assert_eq!(json["new_prefix"], 27);
}

#[test]
fn test_split_count_only_ipv6() {
    let (stdout, _, success) = run_netcidr(&["split", "2001:db8::/64", "-p", "96", "--count-only"]);
    assert!(success);

    let json: serde_json::Value = serde_json::from_str(&stdout).expect("Invalid JSON");
    assert_eq!(json["available_subnets"], "4294967296");
    assert_eq!(json["new_prefix"], 96);
}

#[test]
fn test_split_count_only_ipv6_huge() {
    let (stdout, _, success) =
        run_netcidr(&["split", "2001:db8::/32", "-p", "128", "--count-only"]);
    assert!(success);

    let json: serde_json::Value = serde_json::from_str(&stdout).expect("Invalid JSON");
    assert_eq!(json["available_subnets"], "2^96");
}

#[test]
fn test_split_limit_exceeded_ipv4() {
    let (_, stderr, success) = run_netcidr(&["split", "10.0.0.0/8", "-p", "32", "--max"]);
    assert!(!success);
    assert!(stderr.contains("limit"));
}

#[test]
fn test_split_limit_exceeded_ipv6() {
    let (_, stderr, success) = run_netcidr(&["split", "2001:db8::/32", "-p", "64", "--max"]);
    assert!(!success);
    assert!(stderr.contains("limit"));
}

#[test]
fn test_summarize_ipv4_json() {
    let (stdout, _, success) = run_netcidr(&["summarize", "192.168.0.0/24", "192.168.1.0/24"]);
    assert!(success);

    let json: serde_json::Value = serde_json::from_str(&stdout).expect("Invalid JSON");
    assert_eq!(json["input_count"], 2);
    assert_eq!(json["output_count"], 1);
    assert_eq!(json["cidrs"][0]["network_address"], "192.168.0.0");
    assert_eq!(json["cidrs"][0]["prefix_length"], 23);
}

#[test]
fn test_summarize_ipv4_text() {
    let (stdout, _, success) = run_netcidr(&[
        "summarize",
        "192.168.0.0/24",
        "192.168.1.0/24",
        "--format",
        "text",
    ]);
    assert!(success);
    assert!(stdout.contains("CIDR Summarization"));
    assert!(stdout.contains("Input CIDRs:   2"));
    assert!(stdout.contains("Output CIDRs:  1"));
}

#[test]
fn test_summarize_ipv6_json() {
    let (stdout, _, success) = run_netcidr(&["summarize", "2001:db8::/48", "2001:db8:1::/48"]);
    assert!(success);

    let json: serde_json::Value = serde_json::from_str(&stdout).expect("Invalid JSON");
    assert_eq!(json["input_count"], 2);
    assert_eq!(json["output_count"], 1);
    assert_eq!(json["cidrs"][0]["network_address"], "2001:db8::");
    assert_eq!(json["cidrs"][0]["prefix_length"], 47);
}

#[test]
fn test_summarize_empty() {
    let (_, stderr, success) = run_netcidr(&["summarize"]);
    assert!(!success);
    assert!(stderr.contains("required"));
}

#[test]
fn test_from_range_ipv4_json() {
    let (stdout, _, success) = run_netcidr(&["from-range", "192.168.1.10", "192.168.1.20"]);
    assert!(success);

    let json: serde_json::Value = serde_json::from_str(&stdout).expect("Invalid JSON");
    assert_eq!(json["start_address"], "192.168.1.10");
    assert_eq!(json["end_address"], "192.168.1.20");
    assert!(json["cidr_count"].as_u64().unwrap() > 1);
    assert!(json["cidrs"].as_array().unwrap().len() > 1);
    // First CIDR should start at .10
    assert_eq!(json["cidrs"][0]["network_address"], "192.168.1.10");
}

#[test]
fn test_from_range_ipv4_text() {
    let (stdout, _, success) = run_netcidr(&[
        "from-range",
        "192.168.1.10",
        "192.168.1.20",
        "--format",
        "text",
    ]);
    assert!(success);
    assert!(stdout.contains("IP Range to CIDR"));
    assert!(stdout.contains("Start Address: 192.168.1.10"));
    assert!(stdout.contains("End Address:   192.168.1.20"));
}

#[test]
fn test_from_range_ipv4_single_address() {
    let (stdout, _, success) = run_netcidr(&["from-range", "10.0.0.1", "10.0.0.1"]);
    assert!(success);

    let json: serde_json::Value = serde_json::from_str(&stdout).expect("Invalid JSON");
    assert_eq!(json["cidr_count"], 1);
    assert_eq!(json["cidrs"][0]["prefix_length"], 32);
}

#[test]
fn test_from_range_ipv6_json() {
    let (stdout, _, success) = run_netcidr(&["from-range", "2001:db8::1", "2001:db8::ff"]);
    assert!(success);

    let json: serde_json::Value = serde_json::from_str(&stdout).expect("Invalid JSON");
    assert_eq!(json["start_address"], "2001:db8::1");
    assert_eq!(json["end_address"], "2001:db8::ff");
    assert!(json["cidr_count"].as_u64().unwrap() > 0);
}

#[test]
fn test_from_range_invalid_start_gt_end() {
    let (_, stderr, success) = run_netcidr(&["from-range", "192.168.1.20", "192.168.1.10"]);
    assert!(!success);
    assert!(stderr.contains("Error"));
}

#[test]
fn test_from_range_invalid_address() {
    let (_, stderr, success) = run_netcidr(&["from-range", "not-an-ip", "192.168.1.10"]);
    assert!(!success);
    assert!(stderr.contains("Error"));
}

// ── Batch CIDR Processing ────────────────────────────────────────────

#[test]
fn test_batch_multiple_cidrs() {
    let (stdout, _, success) = run_netcidr(&["192.168.1.0/24", "10.0.0.0/8"]);
    assert!(success);

    let json: serde_json::Value = serde_json::from_str(&stdout).expect("Invalid JSON");
    assert_eq!(json["count"], 2);
    assert_eq!(json["results"].as_array().unwrap().len(), 2);
}

#[test]
fn test_batch_mixed_v4_v6() {
    let (stdout, _, success) = run_netcidr(&["192.168.1.0/24", "2001:db8::/32"]);
    assert!(success);

    let json: serde_json::Value = serde_json::from_str(&stdout).expect("Invalid JSON");
    assert_eq!(json["count"], 2);
    assert_eq!(json["results"][0]["subnet"]["version"], "v4");
    assert_eq!(json["results"][1]["subnet"]["version"], "v6");
}

#[test]
fn test_batch_with_invalid_cidr() {
    let (stdout, _, success) = run_netcidr(&["192.168.1.0/24", "not-valid", "10.0.0.0/8"]);
    assert!(success);

    let json: serde_json::Value = serde_json::from_str(&stdout).expect("Invalid JSON");
    assert_eq!(json["count"], 3);
    // First and third should succeed, second should have error
    assert!(json["results"][0]["subnet"].is_object());
    assert!(json["results"][1]["error"].is_string());
    assert!(json["results"][2]["subnet"].is_object());
}

#[test]
fn test_batch_text_output() {
    let (stdout, _, success) = run_netcidr(&["192.168.1.0/24", "10.0.0.0/8", "--format", "text"]);
    assert!(success);
    assert!(stdout.contains("Batch CIDR Processing"));
    assert!(stdout.contains("Total CIDRs: 2"));
    assert!(stdout.contains("[1/2]"));
    assert!(stdout.contains("[2/2]"));
}

#[test]
fn test_single_cidr_not_batched() {
    let (stdout, _, success) = run_netcidr(&["192.168.1.0/24"]);
    assert!(success);

    let json: serde_json::Value = serde_json::from_str(&stdout).expect("Invalid JSON");
    // Single CIDR should produce flat output — no "count" or "results" wrapper
    assert!(json.get("count").is_none());
    assert!(json.get("results").is_none());
    assert_eq!(json["network_address"], "192.168.1.0");
}

#[test]
fn test_stdin_batch() {
    let input = "192.168.1.0/24\n# comment\n\n10.0.0.0/8\n2001:db8::/32\n";
    let (stdout, _, success) = run_netcidr_stdin(&["--stdin"], input);
    assert!(success);

    let json: serde_json::Value = serde_json::from_str(&stdout).expect("Invalid JSON");
    assert_eq!(json["count"], 3);
    assert_eq!(json["results"].as_array().unwrap().len(), 3);
}

#[test]
fn test_stdin_single_cidr() {
    let input = "192.168.1.0/24\n";
    let (stdout, _, success) = run_netcidr_stdin(&["--stdin"], input);
    assert!(success);

    let json: serde_json::Value = serde_json::from_str(&stdout).expect("Invalid JSON");
    // Single CIDR via stdin should produce flat output
    assert!(json.get("count").is_none());
    assert_eq!(json["network_address"], "192.168.1.0");
}

// ── CSV Output ───────────────────────────────────────────────────────

#[test]
fn test_ipv4_csv_output() {
    let (stdout, _, success) = run_netcidr(&["192.168.1.0/24", "--format", "csv"]);
    assert!(success);

    let lines: Vec<&str> = stdout.lines().collect();
    assert!(lines.len() >= 2, "CSV should have header + data row");
    assert!(lines[0].contains("network_address"));
    assert!(lines[0].contains("prefix_length"));
    assert!(lines[1].contains("192.168.1.0"));
    assert!(lines[1].contains("24"));
}

#[test]
fn test_ipv6_csv_output() {
    let (stdout, _, success) = run_netcidr(&["2001:db8::/32", "--format", "csv"]);
    assert!(success);

    let lines: Vec<&str> = stdout.lines().collect();
    assert!(lines.len() >= 2);
    assert!(lines[0].contains("network_address"));
    assert!(lines[1].contains("2001:db8::"));
}

#[test]
fn test_split_csv_output() {
    let (stdout, _, success) = run_netcidr(&[
        "split",
        "192.168.0.0/24",
        "-p",
        "26",
        "--max",
        "--format",
        "csv",
    ]);
    assert!(success);

    let lines: Vec<&str> = stdout.lines().collect();
    // Should have comment lines, header, and 4 data rows (/24 -> /26 = 4)
    let comment_lines: Vec<&&str> = lines.iter().filter(|l| l.starts_with('#')).collect();
    assert!(
        !comment_lines.is_empty(),
        "CSV list should have comment metadata"
    );
    let data_lines: Vec<&&str> = lines
        .iter()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .collect();
    // header + 4 data rows = 5
    assert_eq!(data_lines.len(), 5);
}

#[test]
fn test_contains_csv_output() {
    let (stdout, _, success) = run_netcidr(&[
        "contains",
        "192.168.1.0/24",
        "192.168.1.100",
        "--format",
        "csv",
    ]);
    assert!(success);

    let lines: Vec<&str> = stdout.lines().collect();
    assert!(lines[0].contains("contained"));
    assert!(lines[1].contains("true"));
}

#[test]
fn test_batch_csv_output() {
    let (stdout, _, success) = run_netcidr(&["192.168.1.0/24", "10.0.0.0/8", "--format", "csv"]);
    assert!(success);

    let lines: Vec<&str> = stdout.lines().collect();
    let comment_lines: Vec<&&str> = lines.iter().filter(|l| l.starts_with('#')).collect();
    assert!(!comment_lines.is_empty());
    let data_lines: Vec<&&str> = lines
        .iter()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .collect();
    // header + 2 data rows = 3
    assert_eq!(data_lines.len(), 3);
}

// ── YAML Output ──────────────────────────────────────────────────────

#[test]
fn test_ipv4_yaml_output() {
    let (stdout, _, success) = run_netcidr(&["192.168.1.0/24", "--format", "yaml"]);
    assert!(success);
    assert!(stdout.contains("network_address:"));
    assert!(stdout.contains("192.168.1.0"));
    assert!(stdout.contains("prefix_length:"));
}

#[test]
fn test_ipv6_yaml_output() {
    let (stdout, _, success) = run_netcidr(&["2001:db8::/32", "--format", "yaml"]);
    assert!(success);
    assert!(stdout.contains("network_address:"));
    assert!(stdout.contains("prefix_length:"));
}

#[test]
fn test_split_yaml_output() {
    let (stdout, _, success) = run_netcidr(&[
        "split",
        "192.168.0.0/24",
        "-p",
        "26",
        "-n",
        "2",
        "--format",
        "yaml",
    ]);
    assert!(success);
    assert!(stdout.contains("subnets:"));
    assert!(stdout.contains("new_prefix:"));
}

#[test]
fn test_contains_yaml_output() {
    let (stdout, _, success) = run_netcidr(&[
        "contains",
        "192.168.1.0/24",
        "192.168.1.100",
        "--format",
        "yaml",
    ]);
    assert!(success);
    assert!(stdout.contains("contained:"));
    assert!(stdout.contains("true"));
}

// ── IPAM CLI Integration ────────────────────────────────────────────

/// Helper to run IPAM commands against a temporary database.
fn run_ipam(db: &str, args: &[&str]) -> (String, String, bool) {
    let mut full_args = vec!["ipam", "--db", db];
    full_args.extend_from_slice(args);
    run_netcidr(&full_args)
}

#[test]
fn test_ipam_cidr_block_lifecycle() {
    let db = "/tmp/netcidr-test-lifecycle.db";
    let _ = std::fs::remove_file(db);

    // Create CIDR block
    let (stdout, _, success) = run_ipam(
        db,
        &["cidr-block", "create", "10.0.0.0/16", "--name", "Test"],
    );
    assert!(success);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("Invalid JSON");
    assert_eq!(json["cidr"], "10.0.0.0/16");
    assert_eq!(json["name"], "Test");
    let sn_id = json["id"].as_str().unwrap().to_string();

    // List CIDR blocks
    let (stdout, _, success) = run_ipam(db, &["cidr-block", "list"]);
    assert!(success);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("Invalid JSON");
    assert_eq!(json["count"], 1);

    // Get CIDR block
    let (stdout, _, success) = run_ipam(db, &["cidr-block", "get", &sn_id]);
    assert!(success);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("Invalid JSON");
    assert_eq!(json["cidr"], "10.0.0.0/16");

    // Delete CIDR block
    let (_, stderr, success) = run_ipam(db, &["cidr-block", "delete", &sn_id]);
    assert!(success);
    assert!(stderr.contains("deleted"));

    let _ = std::fs::remove_file(db);
}

#[test]
fn test_ipam_allocation_workflow() {
    let db = "/tmp/netcidr-test-alloc.db";
    let _ = std::fs::remove_file(db);

    // Create CIDR block
    let (stdout, _, _) = run_ipam(db, &["cidr-block", "create", "10.0.0.0/16"]);
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let sn_id = json["id"].as_str().unwrap().to_string();

    // Allocate specific
    let (stdout, _, success) = run_ipam(
        db,
        &[
            "allocate",
            &sn_id,
            "10.0.1.0/24",
            "--name",
            "Web",
            "--environment",
            "prod",
        ],
    );
    assert!(success);
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(json["cidr"], "10.0.1.0/24");
    assert_eq!(json["status"], "active");
    let alloc_id = json["id"].as_str().unwrap().to_string();

    // Auto-allocate
    let (stdout, _, success) = run_ipam(db, &["auto-allocate", &sn_id, "-p", "24", "-n", "2"]);
    assert!(success);
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(json["count"], 2);

    // Update allocation
    let (stdout, _, success) = run_ipam(
        db,
        &[
            "allocation",
            "update",
            &alloc_id,
            "--owner",
            "team-infra",
            "--resource-id",
            "vpc-123",
        ],
    );
    assert!(success);
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(json["owner"], "team-infra");
    assert_eq!(json["resource_id"], "vpc-123");

    // Release
    let (stdout, _, success) = run_ipam(db, &["release", &alloc_id]);
    assert!(success);
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(json["status"], "released");

    let _ = std::fs::remove_file(db);
}

#[test]
fn test_ipam_utilization_and_free_blocks() {
    let db = "/tmp/netcidr-test-util.db";
    let _ = std::fs::remove_file(db);

    let (stdout, _, _) = run_ipam(db, &["cidr-block", "create", "10.0.0.0/24"]);
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let sn_id = json["id"].as_str().unwrap().to_string();

    run_ipam(db, &["allocate", &sn_id, "10.0.0.0/25"]);

    // Utilization — text format
    let (stdout, _, success) = run_ipam(db, &["utilization", &sn_id, "--format", "text"]);
    assert!(success);
    assert!(stdout.contains("50.00%"));

    // Free blocks
    let (stdout, _, success) = run_ipam(db, &["free-blocks", &sn_id]);
    assert!(success);
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(json["blocks"][0]["cidr"], "10.0.0.128/25");

    let _ = std::fs::remove_file(db);
}

#[test]
fn test_ipam_find_ip() {
    let db = "/tmp/netcidr-test-findip.db";
    let _ = std::fs::remove_file(db);

    let (stdout, _, _) = run_ipam(db, &["cidr-block", "create", "10.0.0.0/8"]);
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let sn_id = json["id"].as_str().unwrap().to_string();

    run_ipam(db, &["allocate", &sn_id, "10.0.1.0/24", "--name", "Web"]);

    let (stdout, _, success) = run_ipam(db, &["find-ip", "10.0.1.50"]);
    assert!(success);
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(json["count"], 1);
    assert_eq!(json["allocations"][0]["cidr"], "10.0.1.0/24");

    // IP not in any allocation
    let (stdout, _, success) = run_ipam(db, &["find-ip", "10.0.2.50"]);
    assert!(success);
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(json["count"], 0);

    let _ = std::fs::remove_file(db);
}

#[test]
fn test_ipam_audit_log() {
    let db = "/tmp/netcidr-test-audit.db";
    let _ = std::fs::remove_file(db);

    let (stdout, _, _) = run_ipam(db, &["cidr-block", "create", "10.0.0.0/8"]);
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let sn_id = json["id"].as_str().unwrap().to_string();

    run_ipam(db, &["allocate", &sn_id, "10.0.0.0/24"]);

    let (stdout, _, success) = run_ipam(db, &["audit", "--limit", "10"]);
    assert!(success);
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(json["count"].as_u64().unwrap() >= 2); // at least create_cidr_block + allocate

    let _ = std::fs::remove_file(db);
}

#[test]
fn test_ipam_tags() {
    let db = "/tmp/netcidr-test-tags.db";
    let _ = std::fs::remove_file(db);

    let (stdout, _, _) = run_ipam(db, &["cidr-block", "create", "10.0.0.0/8"]);
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let sn_id = json["id"].as_str().unwrap().to_string();

    let (stdout, _, _) = run_ipam(db, &["allocate", &sn_id, "10.0.0.0/24"]);
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let alloc_id = json["id"].as_str().unwrap().to_string();

    // Set tags
    let (stdout, _, success) = run_ipam(
        db,
        &["tags", "set", &alloc_id, "team=infra", "cost-center=12345"],
    );
    assert!(success);
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(json["tags"].as_array().unwrap().len(), 2);

    // Get tags
    let (stdout, _, success) = run_ipam(db, &["tags", "get", &alloc_id]);
    assert!(success);
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(json["tags"].as_array().unwrap().len(), 2);

    let _ = std::fs::remove_file(db);
}

#[test]
fn test_ipam_overlap_rejected() {
    let db = "/tmp/netcidr-test-overlap.db";
    let _ = std::fs::remove_file(db);

    let (stdout, _, _) = run_ipam(db, &["cidr-block", "create", "10.0.0.0/16"]);
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let sn_id = json["id"].as_str().unwrap().to_string();

    run_ipam(db, &["allocate", &sn_id, "10.0.0.0/24"]);

    // Overlapping allocation should fail
    let (_, stderr, success) = run_ipam(db, &["allocate", &sn_id, "10.0.0.128/25"]);
    assert!(!success);
    assert!(
        stderr.contains("overlap") || stderr.contains("conflict") || stderr.contains("Conflict")
    );

    let _ = std::fs::remove_file(db);
}

#[test]
fn test_ipam_csv_output() {
    let db = "/tmp/netcidr-test-csv.db";
    let _ = std::fs::remove_file(db);

    let (stdout, _, _) = run_ipam(db, &["cidr-block", "create", "10.0.0.0/16"]);
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let sn_id = json["id"].as_str().unwrap().to_string();

    run_ipam(db, &["allocate", &sn_id, "10.0.0.0/24"]);
    run_ipam(db, &["allocate", &sn_id, "10.0.1.0/24"]);

    let (stdout, _, success) = run_ipam(
        db,
        &[
            "allocation",
            "list",
            "--cidr-block-id",
            &sn_id,
            "--format",
            "csv",
        ],
    );
    assert!(success);
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
    // header + 2 data rows
    assert_eq!(lines.len(), 3);
    assert!(lines[0].contains("cidr"));

    let _ = std::fs::remove_file(db);
}

// ── IPv6 IPAM CLI Integration ─────────────────────────────────────────

#[test]
fn test_ipam_ipv6_cidr_block_lifecycle() {
    let db = "/tmp/netcidr-test-v6-lifecycle.db";
    let _ = std::fs::remove_file(db);

    // Create IPv6 CIDR block
    let (stdout, _, success) = run_ipam(
        db,
        &[
            "cidr-block",
            "create",
            "2001:db8::/32",
            "--name",
            "IPv6Corp",
        ],
    );
    assert!(success, "create failed");
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("Invalid JSON");
    assert_eq!(json["cidr"], "2001:db8::/32");
    assert_eq!(json["ip_version"], 6);
    let sn_id = json["id"].as_str().unwrap().to_string();

    // Allocate specific IPv6 block
    let (stdout, _, success) = run_ipam(
        db,
        &["allocate", &sn_id, "2001:db8:1::/48", "--name", "WebV6"],
    );
    assert!(success, "allocate failed");
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(json["cidr"], "2001:db8:1::/48");
    let alloc_id = json["id"].as_str().unwrap().to_string();

    // Auto-allocate
    let (stdout, _, success) = run_ipam(db, &["auto-allocate", &sn_id, "-p", "48", "-n", "2"]);
    assert!(success, "auto-allocate failed");
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let allocs = json["allocations"].as_array().unwrap();
    assert_eq!(allocs.len(), 2);

    // Utilization
    let (stdout, _, success) = run_ipam(db, &["utilization", &sn_id]);
    assert!(success, "utilization failed");
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(json["allocation_count"], 3);

    // Free blocks
    let (stdout, _, success) = run_ipam(db, &["free-blocks", &sn_id, "-p", "48"]);
    assert!(success, "free-blocks failed");
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(!json["blocks"].as_array().unwrap().is_empty());

    // Find by IPv6 address
    let (stdout, _, success) = run_ipam(db, &["find-ip", "2001:db8:1::50"]);
    assert!(success, "find-ip failed");
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let found = json["allocations"].as_array().unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0]["cidr"], "2001:db8:1::/48");

    // Release
    let (stdout, _, success) = run_ipam(db, &["release", &alloc_id]);
    assert!(success, "release failed");
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(json["status"], "released");

    // Delete CIDR block (need to release remaining allocations first)
    // Just verify the data is consistent
    let (stdout, _, success) = run_ipam(db, &["utilization", &sn_id]);
    assert!(success);
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(json["by_status"]["released_count"], 1);

    let _ = std::fs::remove_file(db);
}

// ==================== Reactivation Tests ====================

#[test]
fn test_ipam_release_and_reactivate_via_update() {
    let db = "/tmp/netcidr-test-reactivate.db";
    let _ = std::fs::remove_file(db);

    // Create CIDR block and allocate
    let (stdout, _, _) = run_ipam(db, &["cidr-block", "create", "10.0.0.0/16"]);
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let sn_id = json["id"].as_str().unwrap().to_string();

    let (stdout, _, success) = run_ipam(db, &["allocate", &sn_id, "10.0.1.0/24", "--name", "Web"]);
    assert!(success);
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let alloc_id = json["id"].as_str().unwrap().to_string();

    // Release it
    let (stdout, _, success) = run_ipam(db, &["release", &alloc_id]);
    assert!(success);
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(json["status"], "released");
    assert!(json["released_at"].is_string());

    // Re-activate via allocation update --status active
    let (stdout, _, success) = run_ipam(
        db,
        &["allocation", "update", &alloc_id, "--status", "active"],
    );
    assert!(success);
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(json["status"], "active");
    assert!(
        json["released_at"].is_null(),
        "released_at should be cleared"
    );

    let _ = std::fs::remove_file(db);
}

#[test]
fn test_ipam_reallocate_released_cidr_reuses_record() {
    let db = "/tmp/netcidr-test-realloc-dedup.db";
    let _ = std::fs::remove_file(db);

    // Create CIDR block and allocate
    let (stdout, _, _) = run_ipam(db, &["cidr-block", "create", "10.0.0.0/16"]);
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let sn_id = json["id"].as_str().unwrap().to_string();

    let (stdout, _, success) = run_ipam(db, &["allocate", &sn_id, "10.0.1.0/24", "--name", "Web"]);
    assert!(success);
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let original_id = json["id"].as_str().unwrap().to_string();

    // Release
    let (_, _, success) = run_ipam(db, &["release", &original_id]);
    assert!(success);

    // Re-allocate the same CIDR — should reactivate the existing record
    let (stdout, _, success) =
        run_ipam(db, &["allocate", &sn_id, "10.0.1.0/24", "--name", "Web-v2"]);
    assert!(success);
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(json["status"], "active");
    assert_eq!(json["name"], "Web-v2");
    // Same record reused — ID should match
    assert_eq!(json["id"].as_str().unwrap(), original_id);

    // Verify no duplicate — listing should show only 1 allocation
    let (stdout, _, success) = run_ipam(db, &["allocation", "list", "--cidr-block-id", &sn_id]);
    assert!(success);
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(
        json["count"], 1,
        "should have 1 allocation, not a duplicate"
    );

    let _ = std::fs::remove_file(db);
}

// ==================== Shell Completions Tests ====================

#[test]
fn test_completions_bash() {
    let (stdout, _, success) = run_netcidr(&["completions", "bash"]);
    assert!(success);
    assert!(stdout.contains("_netcidr"));
}

#[test]
fn test_completions_zsh() {
    let (stdout, _, success) = run_netcidr(&["completions", "zsh"]);
    assert!(success);
    assert!(stdout.contains("#compdef netcidr"));
}

#[test]
fn test_completions_fish() {
    let (stdout, _, success) = run_netcidr(&["completions", "fish"]);
    assert!(success);
    assert!(stdout.contains("complete -c netcidr"));
}

#[test]
fn test_completions_invalid_shell() {
    let (_, stderr, success) = run_netcidr(&["completions", "nushell"]);
    assert!(!success);
    assert!(stderr.contains("invalid value"));
}
