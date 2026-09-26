# WEEK 0 TASK 3: WORM Platform Assignments

**Date:** 2026-09-26  
**Owner:** Lead Architect + Systems Engineers  
**Status:** ⏳ READY FOR ASSIGNMENT

---

## EXECUTIVE SUMMARY

Week 0 Task 3 establishes platform-specific WORM (Write-Once, Read-Many) enforcement across three OS platforms. Each platform has distinct immutability mechanisms; owners must understand and implement per-platform solutions.

**Assignments (To Be Confirmed):**

| Platform | Owner | Contact | Read | Responsibility |
|---|---|---|---|---|
| **Linux** | [TBD] | [TBD] | P1.1-B §2.1 + P1.1 §6.2 | ext4 chattr +i, SELinux policy |
| **Windows** | [TBD] | [TBD] | P1.1-B §3 + Windows ACL docs | NTFS ACL, Integrity Levels |
| **macOS** | [TBD] | [TBD] | P1.1-B §4 + SIP entitlements | APFS chflags uchg, SIP |

---

## PLATFORM-SPECIFIC IMPLEMENTATIONS

### 1. LINUX (ext4 + SELinux)

**Immutability Mechanism:** `chattr +i` (immutable flag)

**Requirements (P1.1-B §2.1):**
- Set immutable flag on all evidence artifacts post-seal
- Prevent modification even by root (until flag removed)
- Log all flag modifications (via audit subsystem)
- SELinux policy denies flag removal without special privilege

**Implementation Tasks (Week 7-8):**
```bash
# Set immutable flag on artifact directory
chattr +i /var/lib/geometry-dash/evidence/artifacts/

# Verify flag
lsattr -d /var/lib/geometry-dash/evidence/artifacts/
# Output: ----i---------- /var/lib/geometry-dash/evidence/artifacts/

# Attempt to modify (should fail with EACCES)
echo "test" > /var/lib/geometry-dash/evidence/artifacts/file.txt
# bash: file.txt: Permission denied
```

**SELinux Policy:**
- Create `geometry_dash.te` with immutable enforcement
- Deny file write to `geometry_dash_evidence_t` contexts
- Deny attribute changes (chattr -i) from policy principals

**Testing (Week 7-8):**
- Test 1: Set flag → modification rejected
- Test 2: Attempt flag removal → SELinux denial logged
- Test 3: Root bypass prevention (even sudo cannot modify)
- Test 4: Audit logging captures all flag operations

**Owner Responsibilities:**
- [ ] Write SELinux policy for geometry_dash contexts
- [ ] Test chattr enforcement on ext4 filesystem
- [ ] Implement audit logging for flag changes
- [ ] Document Linux-specific deployment steps

---

### 2. WINDOWS (NTFS ACL + Integrity Levels)

**Immutability Mechanism:** NTFS ACL + Integrity Levels (IL)

**Requirements (P1.1-B §3):**
- Set NTFS ACL to deny write/modify to all principals except Sealer
- Set file Integrity Level (IL) to "System" (highest level)
- Policy principals cannot write even with elevated privileges
- Audit all write attempts to evidence directory

**Implementation Tasks (Week 7-8):**
```powershell
# Set NTFS ACL (deny write for everyone except gd_sealer)
icacls "C:\ProgramData\GeometryDash\evidence\artifacts" /inheritance:r /grant:r "SYSTEM:(OI)(CI)(F)" /grant:r "gd_sealer:(OI)(CI)(F)" /deny "gd_policy:(OI)(CI)(W)" /deny "gd_actuator:(OI)(CI)(W)"

# Set Integrity Level to System (highest)
Get-Item "C:\ProgramData\GeometryDash\evidence\artifacts" | Set-IntegrityLevel -Level System

# Verify ACL
icacls "C:\ProgramData\GeometryDash\evidence\artifacts"

# Attempt to modify (should fail)
Add-Content "C:\ProgramData\GeometryDash\evidence\artifacts\file.txt" "test"
# Access denied
```

**Integrity Level Enforcement:**
- Set evidence artifact IL = System (highest, read-only to lower IL processes)
- Policy/Actuator processes run at Medium IL (cannot write System IL files)
- Sealer runs at System IL (can read/write System IL files)

**Testing (Week 7-8):**
- Test 1: Set ACL → modify as Policy denied
- Test 2: Set IL to System → Actuator write rejected
- Test 3: Sealer write allowed (System IL process)
- Test 4: Audit logging captures all denials

**Owner Responsibilities:**
- [ ] Design NTFS ACL policy for geometry_dash principals
- [ ] Implement Integrity Level elevation for Sealer
- [ ] Test ACL enforcement on Windows NTFS
- [ ] Document Windows deployment (group policy, ACL scripts)

---

### 3. MACOS (APFS + System Integrity Protection)

**Immutability Mechanism:** APFS chflags + System Integrity Protection (SIP)

**Requirements (P1.1-B §4):**
- Set `uchg` (user changeable) and `schg` (system changeable) flags on artifacts
- Enable SIP entitlements for Sealer process
- Prevent modification by policy/actuator even with sudo
- Audit via OS audit subsystem

**Implementation Tasks (Week 7-8):**
```bash
# Set immutable flags on artifact file
chflags uchg /var/lib/geometry-dash/evidence/artifacts/artifact.json
# Or for even stronger protection:
sudo chflags schg /var/lib/geometry-dash/evidence/artifacts/artifact.json

# Verify flags
ls -lO /var/lib/geometry-dash/evidence/artifacts/artifact.json
# Output: -rw-r--r-- uchg root wheel ...

# Attempt to modify (should fail with "Operation not permitted")
rm /var/lib/geometry-dash/evidence/artifacts/artifact.json
# rm: /var/lib/geometry-dash/evidence/artifacts/artifact.json: Operation not permitted
```

**SIP Entitlements:**
- Create entitlements for Sealer binary (can remove schg flag if needed)
- Policy/Actuator binaries run without special entitlements
- SIP prevents unauthorized code modification (binary signing enforcement)

**Testing (Week 7-8):**
- Test 1: Set uchg flag → rm rejected
- Test 2: Set schg flag → even sudo cannot remove
- Test 3: Sealer entitlements allow override (schg removal if needed)
- Test 4: Audit logging via `log show` or security framework

**Owner Responsibilities:**
- [ ] Design APFS chflags strategy (uchg vs schg decision)
- [ ] Create SIP entitlements for Sealer binary
- [ ] Test flag enforcement on APFS filesystem
- [ ] Document macOS deployment (code signing, entitlements)

---

## CROSS-PLATFORM WORM VALIDATION MATRIX (Week 7-8)

| Test Case | Linux (ext4) | Windows (NTFS) | macOS (APFS) | Pass/Fail |
|---|---|---|---|---|
| Immutable flag set post-seal | chattr +i | NTFS ACL + IL System | chflags uchg | ✓/✗ |
| Policy write rejected | EACCES | ACL denial | Operation not permitted | ✓/✗ |
| Actuator write rejected | EACCES | IL denial | Operation not permitted | ✓/✗ |
| Sealer write allowed | chattr ignored | ACL grant | entitlements override | ✓/✗ |
| Root bypass prevented | SELinux denial | IL system | SIP enforcement | ✓/✗ |
| Audit logging enabled | audit subsystem | Event Viewer | log stream | ✓/✗ |
| Recovery procedures documented | -- | -- | -- | ✓/✗ |

---

## PLATFORM OWNER ROLES

### Linux Owner
**Phase 1 Reading:**
- `GEOMETRY_DASH_WORM_IMPLEMENTATION_GUIDE_v1_0.md` §2.1
- `GEOMETRY_DASH_TRUST_BOUNDARY_STANDARD_v1_0.md` §6 (Privilege Escalation Prevention)

**Timeline:**
- Week 0: Understand ext4/SELinux requirements
- Week 7: Implement chattr enforcement
- Week 8: Test & validate recovery procedures

**Deliverables:**
- `linux_worm_implementation.md` (chattr + SELinux policy)
- `geometry_dash.te` (SELinux policy file)
- `tests/worm_linux_test.rs` (7+ test cases)

---

### Windows Owner
**Phase 1 Reading:**
- `GEOMETRY_DASH_WORM_IMPLEMENTATION_GUIDE_v1_0.md` §3
- Windows NTFS ACL documentation
- Integrity Levels (IL) enforcement guide

**Timeline:**
- Week 0: Understand NTFS ACL + IL requirements
- Week 7: Implement ACL policy & IL elevation
- Week 8: Test & validate on Windows Server/10/11

**Deliverables:**
- `windows_worm_implementation.md` (ACL + IL strategy)
- `SetupWormAcl.ps1` (PowerShell ACL configuration)
- `tests/worm_windows_test.rs` (7+ test cases)

---

### macOS Owner
**Phase 1 Reading:**
- `GEOMETRY_DASH_WORM_IMPLEMENTATION_GUIDE_v1_0.md` §4
- APFS chflags documentation
- SIP entitlements reference

**Timeline:**
- Week 0: Understand APFS + SIP requirements
- Week 7: Implement chflags + entitlements
- Week 8: Test on macOS (Intel + Apple Silicon)

**Deliverables:**
- `macos_worm_implementation.md` (chflags + SIP strategy)
- `GeometryDashSealer.entitlements` (SIP entitlements XML)
- `tests/worm_macos_test.rs` (7+ test cases)

---

## SLACK CHANNEL & COORDINATION

**Channel:** `#geometry-dash-worm`

**Weekly Sync (Mondays 10 AM Chicago):**
- Status: Each platform owner reports progress
- Blockers: OS-specific issues (e.g., SIP restrictions)
- Cross-platform: Share learnings, unify test procedures

**Integration Point (Week 7-8):**
- All three platforms tested simultaneously
- Results merged into cross-platform validation matrix
- Deployment scripts generated (Week 9)

---

## SUCCESS CRITERIA (Week 0)

- [ ] Linux owner assigned and reading P1.1-B §2.1
- [ ] Windows owner assigned and reading P1.1-B §3
- [ ] macOS owner assigned and reading P1.1-B §4
- [ ] WORM_PLATFORM_ASSIGNMENTS.md (this document) created and approved
- [ ] #geometry-dash-worm Slack channel created
- [ ] Cross-platform validation matrix designed (above table)
- [ ] Week 7-8 tasks planned for each owner

---

## DOCUMENT CONTROL

| Version | Date | Status |
|---------|------|--------|
| 1.0 | 2026-09-26 | READY FOR ASSIGNMENT |

**Assignment Window:** Week 0 (Sept 26 - Oct 3)  
**Implementation Begins:** Week 7 (Nov 7)  
**Completion Target:** Week 8 (Nov 14)
