# Phase 2 Team Onboarding Guide (Week 0 Task 5)

**Date:** 2026-09-26  
**Timeline:** Week 0 pre-implementation  
**Target Completion:** By end of Week 0 (all team members onboarded)

---

## TEAM STRUCTURE

| Role | FTE | Lead | Reports To | Phase 1 Reading | Phase 2 Responsibility |
|------|-----|------|-----------|---|---|
| **Lead Architect** | 1 | TBD | Project Owner | Trust Boundary + Integration | Architecture decisions, coherence |
| **Crypto Engineer** | 1 | TBD | Lead Architect | Key Lifecycle + Post-Quantum | HSM, signatures, key management |
| **Systems Engineer (Linux)** | 1 | TBD | Lead Architect | WORM §2 + Privilege Escalation | ext4/SELinux, Linux WORM |
| **Systems Engineer (Windows/macOS)** | 1 | TBD | Lead Architect | WORM §3-4 + Privilege Escalation | NTFS/APFS, Windows/macOS WORM |
| **QA Engineer** | 1 | TBD | Lead Architect | Adversarial Testing + Test Harness | 280+ test cases, test framework |
| **Security Auditor** | 1 | TBD | Project Owner | Standards Compliance + Tamper Detection + Leakage Analysis | Independent review, Gate I |

---

## MANDATORY ONBOARDING (All Roles)

**Duration:** 2.5 hours  
**Deadline:** Before Week 1 kickoff  
**Verification:** Each team member completes reading list and attends onboarding meeting

### Reading List (Mandatory for All)

1. **`P1_COMPLETION_SUMMARY.md`** (15 min)
   - Overview of trust boundary architecture
   - 9 security principals and their roles
   - Process isolation and OS-level enforcement
   - **Key takeaway:** Understand why processes are separate, not languages/libs

2. **`GEOMETRY_DASH_INTERFACE_CONTRACT_CATALOG_v1_0.md` §1-4** (30 min)
   - Read: §1 (Executive Summary), §2 (Reference Security Context), §3 (Universal Message Header), §4 (Authorization Matrix)
   - Understand: 22 critical interfaces, message authentication, capability checking
   - Focus on: Universal message header (13 mandatory fields), signature verification order, authorization rules
   - **Key takeaway:** Every cross-principal message has authentication, authorization, and security context

3. **`GEOMETRY_DASH_REQUIREMENT_REGISTRY_v1_0.md` §1-2** (20 min)
   - Read: Executive Summary, Registry Organization, top-level requirement summary
   - Understand: 200+ requirements organized by 10 categories
   - Focus on: CRITICAL vs HIGH priority, gate requirements
   - **Key takeaway:** Phase 2 implements all 200+ requirements; each module has clear acceptance criteria

4. **`P2_0_MASTER_IMPLEMENTATION_PLAN.md` §1-2** (20 min)
   - Read: Executive Summary, Module Overview, Timeline
   - Understand: 5 principal modules (Supervisor, Policy, Actuator, Audit, Sealer), 17-week timeline, team structure
   - Focus on: Dependencies, critical path (Week 1-2 Supervisor blocks everything)
   - **Key takeaway:** Master plan shows how modules interact; your role is one piece of larger system

**Total Time:** 2.5 hours  
**Completion Check:** Quiz on mandatory reading (30 min, Thursday Week 0)

---

## ROLE-SPECIFIC ONBOARDING

### Lead Architect (Additional 2.5 hours)

**Reading List:**

1. **`GEOMETRY_DASH_TRUST_BOUNDARY_STANDARD_v1_0.md`** (1 hour)
   - Read: Entire document (§1-6)
   - Understand: OS-level isolation, privilege escalation prevention, 9 principals with detailed responsibilities
   - Focus on: Why separate processes? Why Unix users? Why named pipes (not shared memory)?
   - Action: Document architecture decisions as design rationale

2. **`P1_2_COMPLETION_SUMMARY.md`** (30 min)
   - Read: Architecture deep dive summary
   - Understand: Interface contracts, cryptographic foundations, evidence authenticity
   - Focus on: IF-001 through IF-022, what each interface does, who calls whom

3. **`P2_PHASE1_INTEGRATION_VERIFICATION.md`** (30 min)
   - Read: All 8 sections (interface ownership, requirement mapping, gate alignment, critical checks, test coverage, dependency analysis, identified gaps)
   - Understand: How Phase 1 specs map to Phase 2 implementation
   - Action: Own the P1 ↔ P2 coherence; escalate any incoherence immediately

4. **`P2_FEASIBILITY_REVIEW.md`** (30 min)
   - Read: Technology stack enhancements, best practices, gap analysis
   - Understand: 10 industry best practices integrated, 5 critical gaps with mitigations
   - Action: Ensure Phase 2 team understands rationale for tech choices

**Responsibilities:**
- Architecture coherence (P1 ↔ P2)
- Week 1-2 Supervisor design & startup sequence
- Module integration points
- Gate A/C/I readiness criteria

---

### Crypto Engineer (Additional 2.5 hours)

**Reading List:**

1. **`GEOMETRY_DASH_KEY_LIFECYCLE_MANAGEMENT_v1_0.md`** (1 hour)
   - Read: Entire document (KLM-001–018)
   - Understand: PBKDF2 master key derivation, HKDF operational key derivation, per-boot rotation, HSM integration
   - Focus on: Key rotation timing (per-boot, per-seal), HSM failover to encrypted filesystem
   - Action: Understand KLM-007 (per-boot rotation) and KLM-008 (per-seal rotation) deeply

2. **`GEOMETRY_DASH_POST_QUANTUM_CRYPTOGRAPHY_v1_0.md`** (45 min)
   - Read: Entire document (PQC-001–018)
   - Understand: 3-phase migration (2026 Ed25519 → 2028-2030 hybrid → 2031+ ML-DSA)
   - Focus on: How Phase 2 fits into PQC roadmap (stay on Ed25519 in Phase 2, design for upgrade in 2028)
   - Action: Ensure Phase 2 crypto is agnostic to algorithm choice

3. **`P1_3_COMPLETION_SUMMARY.md`** (30 min)
   - Read: Cryptographic standards, merkle trees, evidence sealing
   - Understand: How artifacts are hashed, how merkle tree is constructed, how sealer signs
   - Focus on: Ed25519 (runtime), Ed25519-PSS (sealing), SHA-256 (hashing)

**Responsibilities:**
- HSM integration (PKCS#11 wrapper, Week 1.5)
- Key derivation (HKDF, Week 1.4)
- Signature verification (Ed25519, Week 1.3)
- Sealer implementation (Ed25519-PSS, Week 5-6)
- Laplace noise for declassification (Week 3-4, DLA-010 mitigation)

---

### Systems Engineer (Linux) (Additional 2 hours)

**Reading List:**

1. **`GEOMETRY_DASH_WORM_IMPLEMENTATION_GUIDE_v1_0.md` §2.1** (45 min)
   - Read: Linux section (ext4 chattr +i, SELinux policy)
   - Understand: How chattr +i works, SELinux contexts, policy enforcement
   - Focus on: Why ext4 chattr? Why SELinux? How to verify immutability?
   - Action: Design Linux WORM enforcement (Week 0 Task 3)

2. **`GEOMETRY_DASH_TRUST_BOUNDARY_STANDARD_v1_0.md` §6** (45 min)
   - Read: Privilege Escalation Prevention
   - Understand: seccomp filters, AppArmor profiles, Python import restrictions
   - Focus on: How seccomp forbids ptrace/fork/execve, how AppArmor denies /privileged/**, why these matter

**Responsibilities:**
- Linux WORM enforcement (ext4 chattr +i, Week 7-8)
- SELinux policy for geometry_dash contexts (Week 7-8)
- Seccomp filter validation (Week 1, compiler check; Week 7 fuzzing; Week 8 red team)
- Privilege escalation prevention testing (ADV-001–015)

---

### Systems Engineer (Windows/macOS) (Additional 2 hours)

**Reading List:**

1. **`GEOMETRY_DASH_WORM_IMPLEMENTATION_GUIDE_v1_0.md` §3-4** (1 hour)
   - Read: Windows (NTFS ACL, Integrity Levels), macOS (APFS chflags, SIP)
   - Understand: How NTFS ACL works, Integrity Levels, how chflags works, SIP entitlements
   - Focus on: Why NTFS ACL + IL? Why APFS chflags + SIP? Cross-platform consistency
   - Action: Design Windows/macOS WORM enforcement (Week 0 Task 3)

2. **`GEOMETRY_DASH_TRUST_BOUNDARY_STANDARD_v1_0.md` §6.3-6.4** (45 min)
   - Read: Windows AppContainer, macOS system integrity
   - Understand: How AppContainer restricts capabilities, how SIP entitlements work
   - Focus on: Cross-platform privilege escalation prevention

**Responsibilities:**
- Windows WORM enforcement (NTFS ACL + IL, Week 7-8)
- macOS WORM enforcement (APFS chflags + SIP, Week 7-8)
- Cross-platform WORM validation matrix (Week 7-8)
- Privilege escalation prevention testing (ADV-001–015, cross-platform)

---

### QA Engineer (Additional 2 hours)

**Reading List:**

1. **`GEOMETRY_DASH_ADVERSARIAL_TESTING_v1_0.md`** (1 hour)
   - Read: Entire document (ADV-001–072)
   - Understand: 72 attack vectors, red team objectives, expected mitigations
   - Focus on: How each category tests a different security property
   - Action: Design adversarial test framework (Week 0 Task 4)

2. **`P2_0_MASTER_IMPLEMENTATION_PLAN.md` §3** (45 min)
   - Read: Testing Harness (99 unit, 106 integration, 72 adversarial)
   - Understand: How tests map to modules, timeline for test implementation
   - Focus on: Week 1 unit tests (SecurityLedger, IPC), Week 9-10 adversarial tests

**Responsibilities:**
- Test harness design (pytest, Week 0 Task 4)
- Unit tests (SecurityLedger, IPC, Supervisor, HSM, Week 1)
- Integration tests (Week 3-6, as modules complete)
- Adversarial tests (Week 9-10, all 72 attack vectors)
- Test coverage tracking (99 unit + 106 integration + 72 adversarial)

---

### Security Auditor (Additional 2.5 hours)

**Reading List:**

1. **`GEOMETRY_DASH_STANDARDS_COMPLIANCE_v1_0.md`** (1 hour)
   - Read: Entire document (COMP-001–022)
   - Understand: FIPS 140-2, OWASP Top 10, NIST SP 800-53, ISO 27001, CWE coverage
   - Focus on: How Phase 2 verifies compliance, what Gate I audit checks
   - Action: Plan Gate I evidence authenticity audit (Week 13-14)

2. **`GEOMETRY_DASH_TAMPER_DETECTION_v1_0.md`** (45 min)
   - Read: Entire document (TD-001–012)
   - Understand: 3-tier lockdown (WARNING → DEGRADED → LOCKDOWN), forensic data collection
   - Focus on: What triggers lockdown? How to detect tampering? Recovery procedures

3. **`GEOMETRY_DASH_DECLASSIFICATION_LEAKAGE_ANALYSIS_v1_0.md`** (45 min)
   - Read: Entire document (DLA-001–014)
   - Understand: Declassification validation, differential privacy bounds, inference attack analysis
   - Focus on: How to verify declassification is safe? Laplace noise bounds (ε ≤ 0.5)

**Responsibilities:**
- Independent security review (Week 9-14)
- Gate I evidence authenticity audit (Week 13-14)
- Red team scenarios (ADV-068–072, Week 10)
- Compliance verification (FIPS, OWASP, NIST, ISO, CWE)
- Evidence seal sign-off

---

## ONBOARDING MEETING SCHEDULE

### Monday Week 0 (Sept 26): Team Kickoff Meeting
- **Time:** 2 PM Chicago time
- **Duration:** 1 hour
- **Attendees:** All 6 team members + Project Owner + Lead Architect
- **Agenda:**
  1. Welcome & introductions (10 min)
  2. Phase 2 overview (Master Plan §1-2) (10 min)
  3. Team roles & responsibilities (10 min)
  4. Week 0 tasks & assignments (10 min)
  5. Q&A (10 min)
  6. Slack channel setup + calendar invites (10 min)

### Wednesday Week 0 (Sept 28): Role-Specific Deep Dive
- **Time:** 1 PM Chicago time
- **Duration:** 2 hours (breakout sessions)
  - **Lead Architect** (with Project Owner): Architecture coherence, decisions, escalation path
  - **Crypto Engineer** (with Lead Architect): HSM integration, key derivation, sealing
  - **Systems Engineers** (with Lead Architect): WORM platform assignments, privilege escalation prevention
  - **QA Engineer** (with Lead Architect): Test framework, 280+ test cases
  - **Security Auditor** (with Project Owner): Gate I audit, compliance verification

### Friday Week 0 (Sept 30): Onboarding Verification
- **Time:** 10 AM Chicago time
- **Duration:** 1 hour
- **Format:** Onboarding quiz + Q&A
- **Quiz Topics:**
  - Mandatory reading (all roles): 5-question quiz
  - Role-specific: 10-question quiz
  - Pass threshold: 80% (no retakes; 1-hour review slot offered)
- **Outcome:** Team confirmed ready for Week 1

### Monday Week 1 (Oct 7): Week 1 Kickoff
- **Time:** 10 AM Chicago time
- **Duration:** 1 hour
- **Agenda:**
  1. Week 1 Foundation layer overview (10 min)
  2. Task 1.1-1.6 breakdown (20 min)
  3. Team assignments & dependencies (10 min)
  4. Success criteria & blockers (10 min)
  5. Q&A (10 min)

---

## GITHUB & COMMUNICATION

### GitHub Access
- **Repo:** `https://github.com/[ORG]/geometry-dash`
- **Branches:** 
  - `main` — Stable, all tests passing
  - `develop` — Active development
  - `feature/[module]` — Per-module branches (supervisor, policy, actuator, audit, sealer)
- **Issues:** Track Week 0-1 tasks, blockers, Q&A
- **Projects:** Kanban board for task tracking

### Slack Channel: `#geometry-dash-phase2`
- **Daily standup** (async, by 9 AM Chicago time): What you did, what's next, blockers
- **Weekly sync** (Monday 10 AM): Status, integration checks, escalations
- **Threads:** Keep discussions organized (one thread per task, blocker, or decision)

### Communication Norms
- **Response time:** <4 hours for questions (may be async)
- **Blockers:** Escalate immediately to Lead Architect
- **Decisions:** Document in GitHub (ADR: Architecture Decision Record format)
- **Code reviews:** 2 approvals before merge (Lead Architect + peer)

---

## SUCCESS CRITERIA (Week 0)

- [ ] All 6 team members hired/assigned
- [ ] Each team member completed mandatory reading (2.5 hours)
- [ ] Each team member completed role-specific reading (2-2.5 hours additional)
- [ ] Onboarding quiz passed (80%+ score)
- [ ] Week 0 pre-implementation tasks assigned:
  - [ ] Task 1: Provenance schema (COMPLETE)
  - [ ] Task 2: HSM simulator (in progress)
  - [ ] Task 3: WORM assignments (ready for assignment)
  - [ ] Task 4: Adversarial test framework (in progress)
  - [ ] Task 5: Team onboarding (this document)
- [ ] Team ready for Week 1 kickoff (Monday Oct 7)

---

## GLOSSARY (Quick Reference)

| Term | Definition |
|------|-----------|
| **PRN** | Principal (PRN-SUPERVISOR, PRN-POLICY, etc.) |
| **IF-NNN** | Interface (IF-001 through IF-022) |
| **REQ-XXX-NNN** | Requirement (REQ-ARCH-001, REQ-CRYPTO-001, etc.) |
| **ADV-NNN** | Adversarial test (ADV-001 through ADV-072) |
| **Gate A** | Architecture freeze (Week 11-12) |
| **Gate C** | Configuration freeze (Week 11-12) |
| **Gate I** | Evidence sealing & verification (Week 13-14) |
| **WORM** | Write-Once, Read-Many (immutable storage) |
| **HSM** | Hardware Security Module (PKCS#11) |
| **SecurityLedger** | Append-only log of all security events |
| **IPC** | Inter-Process Communication (named pipes) |

---

## DOCUMENT CONTROL

| Version | Date | Status |
|---------|------|--------|
| 1.0 | 2026-09-26 | Ready for Week 0 deployment |

**Next Update:** Week 1 (team feedback incorporated)
