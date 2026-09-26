# Data Lineage Deployment Guide (SEC-C01)

## Document Overview

This guide provides step-by-step deployment procedures, operational guidelines, and troubleshooting for the SEC-C01 Privileged Data Boundary system with emphasis on data lineage tracking.

**Status:** Sprint 2 Complete  
**Audience:** DevOps, Security Engineers, Operations  
**Scope:** Deployment, monitoring, maintenance  

---

## Table of Contents

1. [Pre-Deployment Checklist](#pre-deployment-checklist)
2. [Deployment Steps](#deployment-steps)
3. [Configuration](#configuration)
4. [Operational Procedures](#operational-procedures)
5. [Monitoring and Alerting](#monitoring-and-alerting)
6. [Troubleshooting Guide](#troubleshooting-guide)
7. [Backup and Recovery](#backup-and-recovery)
8. [Security Considerations](#security-considerations)

---

## Pre-Deployment Checklist

### Environment Verification (11 items)

**Infrastructure:**
- [ ] Linux kernel 6.0+ or equivalent
- [ ] At least 4GB RAM available for Geometry Dash process
- [ ] 100GB+ disk space for ledger logs (plan for ~1 GB per 1M events)
- [ ] File system supports atomic writes (ext4, XFS, or similar)
- [ ] Network isolation verified (no direct internet required)

**Security:**
- [ ] HSM available and accessible (for production Ed25519 signing)
- [ ] TLS certificates configured for inter-principal communication
- [ ] Access controls set on ledger directories (0700 preferred)
- [ ] Audit logging enabled at OS level
- [ ] User/service accounts configured with minimal privileges

**Operations:**
- [ ] Backup storage configured and tested
- [ ] Log aggregation system ready
- [ ] Monitoring infrastructure in place
- [ ] Incident response procedures documented
- [ ] Key rotation schedule established

### Dependencies Verification

**Rust Build:**
```bash
$ rustc --version
rustc 1.xx.x

$ cargo --version
cargo 1.xx.x
```

**Required Crates:**
- serde (serialization)
- sha2 (SHA-256 hashing)
- tempfile (testing)
- hex (hex encoding for debug output)

**System Libraries:**
```bash
$ ldd /path/to/geometry-dash | grep "not found"
# Should output nothing
```

### Configuration Files

**Required configuration sections:**
- [ ] Principal definitions (Policy, Audit, Learner, etc.)
- [ ] Classification level definitions
- [ ] Initial access control matrix
- [ ] Declassification policy templates
- [ ] SecurityLedger path and retention policy
- [ ] Logging configuration
- [ ] HSM client configuration (production only)

---

## Deployment Steps

### Phase 1: Build and Prepare (30 minutes)

**Step 1.1: Build Geometry Dash**
```bash
cd /opt/geometry-dash
cargo build --release

# Verify build succeeded
ls -lh target/release/geometry-dash
# Should show executable, typically 10-20MB
```

**Step 1.2: Verify Test Suite**
```bash
# Run unit tests
cargo test --lib 2>&1 | tee test-results.log

# Check for failures
grep "FAILED\|test result:" test-results.log
# Expected: "test result: ok. ... passed; ... ignored"
```

**Step 1.3: Prepare Directories**
```bash
# Create ledger directory
mkdir -p /var/lib/geometry-dash/ledger
chmod 700 /var/lib/geometry-dash/ledger

# Create configuration directory
mkdir -p /etc/geometry-dash
chmod 700 /etc/geometry-dash

# Create log directory
mkdir -p /var/log/geometry-dash
chmod 755 /var/log/geometry-dash
```

**Step 1.4: Copy Artifacts**
```bash
cp target/release/geometry-dash /opt/geometry-dash/bin/
cp -r docs/ /opt/geometry-dash/docs/
cp config.example.toml /etc/geometry-dash/config.toml
```

### Phase 2: Configuration (1 hour)

**Step 2.1: Ledger Configuration**
```toml
[ledger]
# Path to SecurityLedger file
path = "/var/lib/geometry-dash/ledger/events.jsonl"

# Maximum ledger size before rotation (GB)
max_size_gb = 50

# Retention policy (days)
retention_days = 365

# Backup location
backup_path = "/mnt/backups/geometry-dash-ledger/"
```

**Step 2.2: Classification Configuration**
```toml
[classification]
# Default classification level for untagged data
default_level = "UNRESTRICTED"

# Require explicit classification for this data
require_classification = ["reward_signal", "physics_probe"]

# Enable strict classification enforcement
strict_mode = true
```

**Step 2.3: Access Control Configuration**
```toml
[access_control]
# Principal clearances
[access_control.Policy]
clearance = ["UNRESTRICTED"]

[access_control.Learner]
clearance = ["UNRESTRICTED", "SENSITIVE_REWARD"]

[access_control.Audit]
clearance = ["UNRESTRICTED", "SENSITIVE_REWARD", "PRIVILEGED_TELEMETRY", "INTERNAL"]

# Audit log settings
audit_log_path = "/var/log/geometry-dash/audit.jsonl"
audit_retention_days = 180
```

**Step 2.4: Declassification Policies**
```toml
# Pre-approved policies
[[declassification_policies]]
policy_id = "reward_hash_01"
field_name = "reward_signal"
source_level = "PRIVILEGED_TELEMETRY"
target_level = "SENSITIVE_REWARD"
transformation = "hash_sha256"
approved_by = ["Audit", "Learner"]
effective_date = "2026-01-01"
expires_date = "2026-12-31"

[[declassification_policies]]
policy_id = "probe_summary_01"
field_name = "physics_probe"
source_level = "PRIVILEGED_TELEMETRY"
target_level = "UNRESTRICTED"
transformation = "passthrough"  # After aggregation
approved_by = ["Audit", "Developer"]
effective_date = "2026-01-01"
```

**Step 2.5: HSM Configuration** (Production Only)
```toml
[hsm]
enabled = true
hsm_type = "hardware"
hsm_connector = "pkcs11"
hsm_library_path = "/usr/lib/softhsm/libsofthsm2.so"
hsm_slot_id = 0
hsm_pin = "${HSM_PIN}"  # Load from environment
key_id = "ed25519-sealer-001"
```

### Phase 3: Initialization (30 minutes)

**Step 3.1: Initialize SecurityLedger**
```bash
# Create empty ledger file
touch /var/lib/geometry-dash/ledger/events.jsonl
chmod 600 /var/lib/geometry-dash/ledger/events.jsonl

# Write initialization event
geometry-dash --init-ledger \
  --run-id "init-$(date +%s)" \
  --principal "Supervisor" \
  --message "Ledger initialized for production"

# Verify initialization
geometry-dash --ledger-stats
# Expected output shows: count: 1, last_hash: <hash>, root_hash: <hash>
```

**Step 3.2: Initialize Access Control**
```bash
# Load initial access control from config
geometry-dash --init-access-control \
  --config /etc/geometry-dash/config.toml

# Verify clearances loaded
geometry-dash --list-clearances

# Expected output:
# Policy: [UNRESTRICTED]
# Learner: [UNRESTRICTED, SENSITIVE_REWARD]
# ...
```

**Step 3.3: Register Initial Policies**
```bash
# Register declassification policies from config
geometry-dash --register-policies \
  --config /etc/geometry-dash/config.toml

# Verify policies registered
geometry-dash --list-policies

# Expected output shows all policies with status "ACTIVE"
```

**Step 3.4: Create HSM Keys** (Production)
```bash
# Generate Ed25519 key pair in HSM
geometry-dash --hsm-init \
  --key-id "ed25519-sealer-001" \
  --algorithm "ed25519"

# Verify key creation
geometry-dash --hsm-list-keys

# Test signing
echo "test" | geometry-dash --hsm-sign \
  --key-id "ed25519-sealer-001"
```

### Phase 4: Testing (1 hour)

**Step 4.1: Functional Testing**
```bash
# Test classification
geometry-dash --test-classify \
  --field "test_physics_probe" \
  --level "PRIVILEGED_TELEMETRY"
# Expected: Classification created, label_id returned

# Test declassification
geometry-dash --test-declassify \
  --policy "reward_hash_01" \
  --value "0.95"
# Expected: Hash returned, record created

# Test lineage retrieval
geometry-dash --test-lineage \
  --record-id "decl-001"
# Expected: Complete lineage chain returned
```

**Step 4.2: Load Testing**
```bash
# Simulate realistic load
geometry-dash --load-test \
  --operations 10000 \
  --concurrent 4 \
  --operation-type "declassify"

# Monitor performance
# Expected: <100ms per operation, <10% CPU utilization
```

**Step 4.3: Security Testing**
```bash
# Test authorization enforcement
geometry-dash --security-test \
  --test-unauthorized-access \
  --principal "Policy" \
  --level "PRIVILEGED_TELEMETRY"
# Expected: Access denied

# Test policy expiration
geometry-dash --security-test \
  --test-expired-policy \
  --policy "expired_policy"
# Expected: Operation rejected
```

**Step 4.4: Disaster Recovery Testing**
```bash
# Test backup/restore
geometry-dash --test-backup-restore \
  --backup-path "/tmp/test-backup"

# Test ledger recovery
geometry-dash --verify-ledger \
  --repair-if-needed

# Expected: Ledger integrity verified or repaired
```

### Phase 5: Production Deployment (1 hour)

**Step 5.1: Start Service**
```bash
# Start with systemd
systemctl start geometry-dash

# Verify running
systemctl status geometry-dash
systemctl is-active geometry-dash
# Expected: "active (running)"

# Check service logs
journalctl -u geometry-dash -n 50
```

**Step 5.2: Verify Connectivity**
```bash
# Test IPC communication
geometry-dash --test-ipc \
  --interface "IF-001" \
  --source "Policy" \
  --target "Audit"
# Expected: Message sent/received successfully

# Test classification message transport
geometry-dash --test-classified-ipc \
  --level "SENSITIVE_REWARD" \
  --clearance "SENSITIVE_REWARD"
# Expected: Authorization granted
```

**Step 5.3: Enable Monitoring**
```bash
# Start metrics exporter
geometry-dash --metrics-exporter \
  --port 9090 \
  --interval 30s

# Verify metrics available
curl http://localhost:9090/metrics | head -20
```

**Step 5.4: Log Aggregation**
```bash
# Test log collection
tail -f /var/log/geometry-dash/audit.jsonl | head -10

# Verify structured logs
jq . /var/log/geometry-dash/audit.jsonl | head -5
# Expected: Valid JSON with all required fields
```

---

## Operational Procedures

### Daily Operations

**Morning Routine (5 minutes):**
```bash
#!/bin/bash
# daily-checks.sh

# Check service health
systemctl is-active geometry-dash || systemctl start geometry-dash

# Check disk space
df -h /var/lib/geometry-dash | tail -1
# Alert if >80% full

# Check ledger integrity
geometry-dash --verify-ledger
# Should complete with "Integrity: OK"

# Monitor for errors
journalctl -u geometry-dash --since "6 hours ago" | grep -i error
```

**Backup Verification (Weekly):**
```bash
#!/bin/bash
# weekly-backup-check.sh

# Backup ledger
cp /var/lib/geometry-dash/ledger/events.jsonl \
   /mnt/backups/geometry-dash-ledger/events-$(date +%Y%m%d).jsonl

# Verify backup integrity
geometry-dash --verify-backup \
  /mnt/backups/geometry-dash-ledger/events-*.jsonl

# Cleanup old backups (keep 90 days)
find /mnt/backups/geometry-dash-ledger/ -mtime +90 -delete
```

### Routine Maintenance

**Monthly Policy Review:**
```bash
# List all active policies
geometry-dash --list-policies --filter "status:ACTIVE"

# Check for policies expiring in next 30 days
geometry-dash --list-policies --filter "expires_in:30d"

# Schedule policy renewal or replacement
geometry-dash --update-policy \
  --policy "reward_hash_01" \
  --expires-date "2026-12-31"
```

**Quarterly Ledger Maintenance:**
```bash
# Check ledger size
ls -lh /var/lib/geometry-dash/ledger/events.jsonl
# Alert if >50GB

# Archive old events (older than 90 days)
geometry-dash --archive-events \
  --before "2026-06-01" \
  --output "/mnt/archives/geometry-dash-ledger/"

# Verify archive integrity
geometry-dash --verify-archive \
  /mnt/archives/geometry-dash-ledger/*.jsonl
```

**Annual Security Audit:**
```bash
# Export audit trail for review
geometry-dash --export-audit-trail \
  --start-date "2025-01-01" \
  --end-date "2025-12-31" \
  --output "/tmp/audit-2025.csv"

# Analyze declassification operations
geometry-dash --analyze-declassifications \
  --year 2025 \
  --report /tmp/declassification-report.txt

# Review unauthorized access attempts
grep '"allowed":false' /var/log/geometry-dash/audit.jsonl | \
  jq -r '[.timestamp_ns, .principal, .resource] | @csv' > \
  /tmp/denied-access-2025.csv
```

---

## Monitoring and Alerting

### Key Metrics to Monitor

**Performance Metrics:**
```
geometry_dash_declassify_latency_ms (histogram)
  Alert: p99 > 100ms
  Action: Check CPU, disk I/O, ledger size

geometry_dash_ledger_write_latency_ms (histogram)
  Alert: p99 > 50ms
  Action: Check disk performance, seek times

geometry_dash_policy_request_latency_ms (histogram)
  Alert: p99 > 10ms
  Action: Check policy cache hit rate
```

**Capacity Metrics:**
```
geometry_dash_ledger_size_bytes (gauge)
  Alert: > 50GB
  Action: Plan ledger archival

geometry_dash_ledger_event_count (counter)
  Alert: Growing >1000 events/hour
  Action: Check for misconfiguration

geometry_dash_policy_count (gauge)
  Alert: > 1000 policies
  Action: Review policy consolidation
```

**Security Metrics:**
```
geometry_dash_access_denied_total (counter)
  Alert: > 10 denied accesses in 5 minutes
  Action: Investigate potential attack

geometry_dash_authorization_failures_total (counter)
  Alert: > 5 failures in 5 minutes
  Action: Check principal clearance config

geometry_dash_ledger_integrity_failures (counter)
  Alert: Any value > 0
  Action: Immediate investigation required
```

### Alert Rules (Prometheus)

```yaml
# High declassification latency
- alert: HighDeclassifyLatency
  expr: histogram_quantile(0.99, geometry_dash_declassify_latency_ms) > 100
  for: 5m
  action: page

# Ledger size critical
- alert: LedgerSizeCritical
  expr: geometry_dash_ledger_size_bytes > 50e9
  for: 1m
  action: page

# Repeated authorization failures
- alert: RepeatedAuthFailures
  expr: rate(geometry_dash_authorization_failures_total[5m]) > 1
  for: 5m
  action: page

# Ledger integrity failure
- alert: LedgerIntegrityFailure
  expr: geometry_dash_ledger_integrity_failures > 0
  for: 1m
  action: page-immediate
```

### Logging Configuration

**Structured Logging (JSON):**
```json
{
  "timestamp": "2026-09-26T12:34:56Z",
  "level": "INFO",
  "component": "declassifier",
  "operation": "declassify",
  "principal": "Audit",
  "policy_id": "reward_hash_01",
  "record_id": "decl-001",
  "latency_ms": 2.5,
  "status": "success"
}
```

**Log Retention:**
```toml
[logging]
# Audit logs (all access/declassification)
audit_retention_days = 365
audit_log_path = "/var/log/geometry-dash/audit.jsonl"

# Application logs (system events)
app_retention_days = 90
app_log_path = "/var/log/geometry-dash/app.jsonl"

# Debug logs (development only)
debug_enabled = false  # Set to false in production
debug_retention_days = 7
debug_log_path = "/var/log/geometry-dash/debug.jsonl"
```

---

## Troubleshooting Guide

### Issue 1: Declassification Latency High

**Symptom:** Declassification operations slow (>100ms)

**Diagnosis Steps:**
```bash
# Check system resources
top -bn1 | grep "Cpu\|Mem"
# Alert if CPU >80% or Memory >80%

# Check disk I/O
iostat -x 1 5
# Alert if util >90% or await >20ms

# Check ledger size
du -h /var/lib/geometry-dash/ledger/
# If >10GB, consider archival

# Check policy count
geometry-dash --list-policies | wc -l
# If >1000, optimize policy structure
```

**Resolution:**
```bash
# Option 1: Archive old events
geometry-dash --archive-events \
  --before "2026-06-01" \
  --output "/mnt/archives/"

# Option 2: Consolidate policies
geometry-dash --consolidate-policies \
  --output "/tmp/consolidated-policies.json"

# Option 3: Add more CPU/Memory (if system-wide)
# Contact infrastructure team
```

### Issue 2: Authorization Failures

**Symptom:** Repeated "Access denied" errors for valid principals

**Diagnosis Steps:**
```bash
# Check clearance configuration
geometry-dash --show-clearances --principal "Audit"

# Check access log for pattern
grep '"allowed":false' /var/log/geometry-dash/audit.jsonl | \
  jq -r '.principal, .resource, .reason'

# Verify principal exists
geometry-dash --list-principals

# Check policy approvers
geometry-dash --show-policy --policy-id "reward_hash_01" | \
  grep approved_by
```

**Resolution:**
```bash
# Update clearance if incorrect
geometry-dash --update-clearance \
  --principal "Policy" \
  --level "SENSITIVE_REWARD"

# Verify with test
geometry-dash --test-access \
  --principal "Policy" \
  --level "SENSITIVE_REWARD"
```

### Issue 3: Ledger Integrity Failure

**Symptom:** `verify_ledger` reports hash chain broken

**Diagnosis Steps:**
```bash
# Verify file corruption
file /var/lib/geometry-dash/ledger/events.jsonl
# Should show "ASCII text"

# Check file size sanity
ls -l /var/lib/geometry-dash/ledger/events.jsonl
# Should be > 0 bytes

# Try to read last event
tail -1 /var/lib/geometry-dash/ledger/events.jsonl | jq .

# Check recent writes
tail -100 /var/lib/geometry-dash/ledger/events.jsonl | jq .event_type | sort | uniq -c
```

**Resolution:**
```bash
# CRITICAL: Stop application immediately
systemctl stop geometry-dash

# Create backup
cp /var/lib/geometry-dash/ledger/events.jsonl \
   /var/lib/geometry-dash/ledger/events.jsonl.corrupted

# Attempt repair (removes last incomplete event if needed)
geometry-dash --repair-ledger \
  --ledger-path /var/lib/geometry-dash/ledger/events.jsonl \
  --backup

# Verify repair
geometry-dash --verify-ledger

# If repair fails, restore from backup
# And open incident investigation
```

### Issue 4: Out of Disk Space

**Symptom:** `No space left on device` errors

**Diagnosis Steps:**
```bash
# Check all mounts
df -h

# Find largest files
du -h /var/lib/geometry-dash/* | sort -rh | head -10

# Check ledger growth rate
ls -l /var/lib/geometry-dash/ledger/ | tail -5
```

**Resolution - Immediate:**
```bash
# Archive and compress old events
geometry-dash --archive-events \
  --before "2026-06-01" \
  --output "/mnt/backups/" \
  --compress gzip

# Delete non-critical logs
rm /var/log/geometry-dash/debug.jsonl*

# Cleanup temporary files
rm /tmp/geometry-dash-*
```

**Resolution - Long-term:**
```bash
# Increase disk allocation
# Contact infrastructure team with:
# - Current ledger growth rate (events/day)
# - Projected size in 12 months
# - Desired retention period

# Example calculation:
# 1000 events/day * 1KB/event * 365 days = 365 MB/year
# Plus overhead: ~1 GB/year total
# Retention 5 years → 5 GB minimum
```

### Issue 5: Declining Test Coverage

**Symptom:** New code changes don't have associated tests

**Diagnosis Steps:**
```bash
# Run test coverage
cargo tarpaulin --out Html --output-dir /tmp/coverage

# Open coverage report
firefox /tmp/coverage/tarpaulin-report.html

# Check specific module coverage
cargo tarpaulin --lib principals::declassifier
```

**Resolution:**
```bash
# Write comprehensive tests
# 1. Unit tests for each function
# 2. Integration tests for workflows
# 3. Property-based tests for invariants
# 4. Security tests for authorization

# Run full test suite
cargo test --lib --verbose

# Ensure coverage > 90%
```

---

## Backup and Recovery

### Backup Strategy

**Backup Scope:**
```
- SecurityLedger (events.jsonl)
- Configuration files (/etc/geometry-dash/)
- HSM keys (if using HSM - requires special handling)
- Access control database (if persistent)
```

**Backup Schedule:**
```
Hourly:   Last 24 hours
Daily:    Last 30 days
Weekly:   Last 90 days
Monthly:  Last 2 years
Annual:   Indefinite (archive)
```

**Backup Procedures:**
```bash
#!/bin/bash
# backup-geometry-dash.sh

BACKUP_DIR="/mnt/backups/geometry-dash"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LEDGER="/var/lib/geometry-dash/ledger/events.jsonl"
CONFIG="/etc/geometry-dash/"

# Create hourly backup
mkdir -p "$BACKUP_DIR/hourly"
cp "$LEDGER" "$BACKUP_DIR/hourly/events-$TIMESTAMP.jsonl"

# Rotate hourly backups (keep 24)
find "$BACKUP_DIR/hourly" -mtime +1 -delete

# Create daily backup (at midnight)
if [[ $(date +%H:%M) == "00:00" ]]; then
  mkdir -p "$BACKUP_DIR/daily"
  gzip < "$LEDGER" > "$BACKUP_DIR/daily/events-$(date +%Y%m%d).jsonl.gz"
fi

# Verify backup integrity
geometry-dash --verify-backup "$BACKUP_DIR/hourly/events-$TIMESTAMP.jsonl"
if [ $? -ne 0 ]; then
  echo "ERROR: Backup verification failed!" | mail -s "Backup failure" ops@example.com
  exit 1
fi

echo "Backup completed successfully at $TIMESTAMP"
```

### Recovery Procedures

**Scenario 1: Corrupted Ledger**
```bash
# 1. Stop application
systemctl stop geometry-dash

# 2. Restore from most recent backup
BACKUP=$(ls -t /mnt/backups/geometry-dash/hourly/*.jsonl | head -1)
cp "$BACKUP" /var/lib/geometry-dash/ledger/events.jsonl

# 3. Verify restoration
geometry-dash --verify-ledger

# 4. Restart application
systemctl start geometry-dash

# 5. Monitor for errors
journalctl -u geometry-dash -f | head -50
```

**Scenario 2: Complete System Failure**
```bash
# 1. Restore full system from backup
# 2. Install geometry-dash binary
# 3. Restore configuration
cp /mnt/backups/geometry-dash/config.tar.gz /etc/geometry-dash/
cd /etc/geometry-dash && tar xzf config.tar.gz

# 4. Restore ledger
cp /mnt/backups/geometry-dash/daily/events-2026-09-26.jsonl.gz \
   /var/lib/geometry-dash/ledger/
gunzip /var/lib/geometry-dash/ledger/events-*.gz

# 5. Verify and restart
geometry-dash --verify-ledger
systemctl start geometry-dash
```

**Recovery Time Objectives (RTO):**
```
Single file corruption: 5 minutes
Partial data loss: 15 minutes
Complete system failure: 1 hour
```

---

## Security Considerations

### Access Control

**File Permissions:**
```bash
# Ledger files (read/write restricted)
chmod 600 /var/lib/geometry-dash/ledger/events.jsonl

# Configuration files (containing policies)
chmod 600 /etc/geometry-dash/config.toml

# Log files (readable by monitoring)
chmod 644 /var/log/geometry-dash/audit.jsonl
```

**Service Account:**
```bash
# Create dedicated service user
useradd -r -s /bin/false -d /var/lib/geometry-dash geometry-dash

# Set ownership
chown -R geometry-dash:geometry-dash /var/lib/geometry-dash
chown -R geometry-dash:geometry-dash /etc/geometry-dash

# Limit sudo privileges (if needed at all)
echo "geometry-dash ALL=(root) NOPASSWD: /bin/systemctl restart geometry-dash" \
  >> /etc/sudoers.d/geometry-dash
```

### Cryptographic Material

**HSM Key Management:**
```bash
# Keys stored only in HSM, never in software
# No private key material on disk

# Key backup procedure (HSM-specific):
# 1. Export key from HSM (if supported)
# 2. Encrypt with master key
# 3. Store in secure facility
# 4. Document key ID and usage
```

**Hash Verification:**
```bash
# Verify ledger cryptographic integrity
geometry-dash --verify-hash-chain \
  --ledger /var/lib/geometry-dash/ledger/events.jsonl

# All events should verify against expected hash
# Any failure indicates tampering
```

### Audit Trail Protection

**Immutability:**
```bash
# Ledger is append-only (no deletion)
# Configuration changes logged separately
# Access attempts all recorded

# Prevent accidental corruption
chattr +a /var/lib/geometry-dash/ledger/events.jsonl
# Now only appends allowed, even by root
```

**Retention Policy:**
```bash
# Keep audit logs for compliance period
# Minimum: 1 year
# Recommended: 3-5 years
# Checked quarterly for integrity

# Archive older logs to secure storage
geometry-dash --archive-and-compress \
  --before "2025-01-01" \
  --output "/mnt/secure-archive/"
```

---

## Checklist for Go-Live

- [ ] All tests passing (unit, integration, security)
- [ ] Stress testing complete (10,000+ operations)
- [ ] Disaster recovery tested and documented
- [ ] Monitoring and alerting configured
- [ ] Backup automation working
- [ ] Security review completed
- [ ] Access control policies approved
- [ ] HSM integration verified (if applicable)
- [ ] Runbooks documented and practiced
- [ ] On-call rotation trained
- [ ] Incident response procedures defined
- [ ] Stakeholders notified

---

**Document Version:** 1.0  
**Last Updated:** 2026-09-26  
**Classification:** Internal
