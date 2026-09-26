# Week 0 GitHub Issues (To Create After Repo Push)

## Issue Template: [Week 0] Lead Architect Assignment

**Title:** [Week 0] Lead Architect: Onboarding & Phase 1 Reading  
**Assignee:** [TBD Lead Architect]  
**Due:** Sept 28, 2026 (Wed)  
**Labels:** week-0, lead-architect, onboarding

### Checklist
- [ ] Complete Phase 1 reading (2.5 hours):
  - [ ] P1_COMPLETION_SUMMARY.md
  - [ ] GEOMETRY_DASH_INTERFACE_CONTRACT_CATALOG_v1_0.md §1-4
  - [ ] GEOMETRY_DASH_REQUIREMENT_REGISTRY_v1_0.md §1-2
  - [ ] P2_0_MASTER_IMPLEMENTATION_PLAN.md §1-2
- [ ] Complete role-specific reading (2.5 hours):
  - [ ] GEOMETRY_DASH_TRUST_BOUNDARY_STANDARD_v1_0.md (entire)
  - [ ] P1_2_COMPLETION_SUMMARY.md
  - [ ] P2_PHASE1_INTEGRATION_VERIFICATION.md (all 8 sections)
  - [ ] P2_FEASIBILITY_REVIEW.md
- [ ] Attend Wednesday deep dive (Sept 28, 1 PM Chicago time)
- [ ] Pass onboarding quiz Friday 10 AM (80%+)

**Responsibilities:** Architecture coherence (P1 ↔ P2), Week 1-2 Supervisor design, module integration points, Gate A/C/I readiness

---

## Issue Template: [Week 0] Crypto Engineer Assignment

**Title:** [Week 0] Crypto Engineer: Onboarding & Phase 1 Reading  
**Assignee:** [TBD Crypto Engineer]  
**Due:** Sept 28, 2026 (Wed)  
**Labels:** week-0, crypto-engineer, onboarding, hsm

### Checklist
- [ ] Complete Phase 1 reading (2.5 hours)
- [ ] Complete role-specific reading (2.5 hours):
  - [ ] GEOMETRY_DASH_KEY_LIFECYCLE_MANAGEMENT_v1_0.md (entire, KLM-001–018)
  - [ ] GEOMETRY_DASH_POST_QUANTUM_CRYPTOGRAPHY_v1_0.md (entire, PQC-001–018)
  - [ ] P1_3_COMPLETION_SUMMARY.md
- [ ] Attend Wednesday deep dive (Sept 28, 1 PM Chicago time)
- [ ] Pass onboarding quiz Friday 10 AM (80%+)

**Responsibilities:** HSM integration (PKCS#11 wrapper, Week 1.5), key derivation (HKDF, Week 1.4), signature verification (Ed25519, Week 1.3), sealer implementation (Week 5-6), Laplace noise for declassification (Week 3-4)

---

## Issue Template: [Week 0] Systems Engineer (Linux) Assignment

**Title:** [Week 0] Systems Engineer (Linux): Onboarding & Platform Reading  
**Assignee:** [TBD Linux Engineer]  
**Due:** Sept 28, 2026 (Wed)  
**Labels:** week-0, systems-engineer, linux, worm

### Checklist
- [ ] Complete Phase 1 reading (2.5 hours)
- [ ] Complete role-specific reading (2 hours):
  - [ ] GEOMETRY_DASH_WORM_IMPLEMENTATION_GUIDE_v1_0.md §2.1 (ext4, SELinux)
  - [ ] GEOMETRY_DASH_TRUST_BOUNDARY_STANDARD_v1_0.md §6 (privilege escalation prevention)
- [ ] Attend Wednesday deep dive (Sept 28, 1 PM Chicago time)
- [ ] Pass onboarding quiz Friday 10 AM (80%+)
- [ ] Review WEEK_0_TASK_3_WORM_PLATFORM_ASSIGNMENTS.md (Linux section)

**Responsibilities:** Linux WORM enforcement (ext4 chattr +i, SELinux policy, Week 7-8), seccomp filter validation, privilege escalation prevention testing (ADV-001–015)

---

## Issue Template: [Week 0] Systems Engineer (Windows/macOS) Assignment

**Title:** [Week 0] Systems Engineer (Windows/macOS): Onboarding & Platform Reading  
**Assignee:** [TBD Windows/macOS Engineer]  
**Due:** Sept 28, 2026 (Wed)  
**Labels:** week-0, systems-engineer, windows, macos, worm

### Checklist
- [ ] Complete Phase 1 reading (2.5 hours)
- [ ] Complete role-specific reading (2 hours):
  - [ ] GEOMETRY_DASH_WORM_IMPLEMENTATION_GUIDE_v1_0.md §3-4 (Windows NTFS, macOS APFS)
  - [ ] GEOMETRY_DASH_TRUST_BOUNDARY_STANDARD_v1_0.md §6.3-6.4 (AppContainer, SIP)
- [ ] Attend Wednesday deep dive (Sept 28, 1 PM Chicago time)
- [ ] Pass onboarding quiz Friday 10 AM (80%+)
- [ ] Review WEEK_0_TASK_3_WORM_PLATFORM_ASSIGNMENTS.md (Windows & macOS sections)

**Responsibilities:** Windows WORM enforcement (NTFS ACL + IL, Week 7-8), macOS WORM enforcement (APFS chflags + SIP, Week 7-8), cross-platform WORM validation matrix, privilege escalation prevention testing (ADV-001–015)

---

## Issue Template: [Week 0] QA Engineer Assignment

**Title:** [Week 0] QA Engineer: Onboarding & Test Framework Review  
**Assignee:** [TBD QA Engineer]  
**Due:** Sept 28, 2026 (Wed)  
**Labels:** week-0, qa-engineer, onboarding, testing

### Checklist
- [ ] Complete Phase 1 reading (2.5 hours)
- [ ] Complete role-specific reading (2 hours):
  - [ ] GEOMETRY_DASH_ADVERSARIAL_TESTING_v1_0.md (entire, ADV-001–072)
  - [ ] P2_0_MASTER_IMPLEMENTATION_PLAN.md §3 (Testing Harness)
- [ ] Attend Wednesday deep dive (Sept 28, 1 PM Chicago time)
- [ ] Pass onboarding quiz Friday 10 AM (80%+)
- [ ] Review tests/adversarial/README.md and tests/adversarial/conftest.py

**Responsibilities:** Test harness design (pytest, Week 0), unit tests (SecurityLedger/IPC, Week 1), integration tests (Week 3-6), adversarial tests (Week 9-10, all 72 vectors), test coverage tracking (99 unit + 106 integration + 72 adversarial)

---

## Issue Template: [Week 0] Security Auditor Assignment

**Title:** [Week 0] Security Auditor: Onboarding & Compliance Review  
**Assignee:** [TBD Security Auditor]  
**Due:** Sept 28, 2026 (Wed)  
**Labels:** week-0, security-auditor, onboarding, audit

### Checklist
- [ ] Complete Phase 1 reading (2.5 hours)
- [ ] Complete role-specific reading (2.5 hours):
  - [ ] GEOMETRY_DASH_STANDARDS_COMPLIANCE_v1_0.md (entire, COMP-001–022)
  - [ ] GEOMETRY_DASH_TAMPER_DETECTION_v1_0.md (entire, TD-001–012)
  - [ ] GEOMETRY_DASH_DECLASSIFICATION_LEAKAGE_ANALYSIS_v1_0.md (entire, DLA-001–014)
- [ ] Attend Wednesday deep dive (Sept 28, 1 PM Chicago time)
- [ ] Pass onboarding quiz Friday 10 AM (80%+)

**Responsibilities:** Independent security review (Week 9-14), Gate I evidence authenticity audit (Week 13-14), red team scenarios (ADV-068–072, Week 10), compliance verification (FIPS, OWASP, NIST, ISO, CWE), evidence seal sign-off

---

## Meeting Setup Issues

### Issue: [Week 0] Monday Kickoff Meeting (Sept 26, 2 PM Chicago)

**Title:** [Week 0] Team Kickoff Meeting – Monday Sept 26  
**Description:**  
- **Time:** Monday, Sept 26, 2:00 PM Chicago time
- **Duration:** 1 hour
- **Attendees:** All 6 team members + Project Owner + Lead Architect
- **Agenda:**
  1. Welcome & introductions (10 min)
  2. Phase 2 overview (Master Plan §1-2) (10 min)
  3. Team roles & responsibilities (10 min)
  4. Week 0 tasks & assignments (10 min)
  5. Q&A (10 min)
  6. Slack channel setup + calendar invites (10 min)

---

### Issue: [Week 0] Wednesday Role-Specific Deep Dive (Sept 28, 1 PM Chicago)

**Title:** [Week 0] Role-Specific Deep Dives – Wednesday Sept 28  
**Description:**  
- **Time:** Wednesday, Sept 28, 1:00 PM Chicago time
- **Duration:** 2 hours (breakout sessions)
- **Format:**
  - **Lead Architect** (with Project Owner): Architecture coherence, decisions, escalation path
  - **Crypto Engineer** (with Lead Architect): HSM integration, key derivation, sealing
  - **Systems Engineers** (with Lead Architect): WORM platform assignments, privilege escalation prevention
  - **QA Engineer** (with Lead Architect): Test framework, 280+ test cases
  - **Security Auditor** (with Project Owner): Gate I audit, compliance verification

---

### Issue: [Week 0] Onboarding Verification Quiz (Sept 30, 10 AM Chicago)

**Title:** [Week 0] Onboarding Verification Quiz – Friday Sept 30  
**Description:**  
- **Time:** Friday, Sept 30, 10:00 AM Chicago time
- **Duration:** 1 hour
- **Format:** Onboarding quiz + Q&A
- **Quiz Topics:**
  - Mandatory reading (all roles): 5-question quiz
  - Role-specific: 10-question quiz
  - Pass threshold: 80% (no retakes; 1-hour review slot offered)
- **Outcome:** Team confirmed ready for Week 1

---

### Issue: [Week 1] Kickoff Meeting (Oct 7, 10 AM Chicago)

**Title:** [Week 1] Foundation Layer Kickoff – Monday Oct 7  
**Description:**  
- **Time:** Monday, Oct 7, 10:00 AM Chicago time
- **Duration:** 1 hour
- **Agenda:**
  1. Week 1 Foundation layer overview (10 min)
  2. Task 1.1-1.6 breakdown (20 min)
  3. Team assignments & dependencies (10 min)
  4. Success criteria & blockers (10 min)
  5. Q&A (10 min)

---

## Slack Channel Setup

### Issue: [Week 0] Set Up #geometry-dash-phase2 Slack Channel

**Title:** [Week 0] Slack Channel Setup  
**Description:**  
Create channel `#geometry-dash-phase2` with:
- **Description:** Geometry Dash Phase 2 implementation (Week 0-14)
- **Topic:** Real-time coordination, daily standup, blocker escalation
- **Pinned Messages:**
  - Master Implementation Plan (link)
  - Team Onboarding Guide (link)
  - Phase 1 Interface Contract Catalog (link)
  - Requirement Registry (link)

**Standup Format:**
- **Async standup:** Post by 9 AM Chicago time (daily)
  - What you did yesterday
  - What's next today
  - Any blockers
- **Weekly sync:** Monday 10 AM Chicago time (1 hour, text updates okay)

---

## Document Control

| Document | Created | Status |
|----------|---------|--------|
| TEAM_ONBOARDING.md | Sept 26 | Ready for distribution |
| WEEK_0_TASK_3_WORM_PLATFORM_ASSIGNMENTS.md | Sept 26 | Ready for distribution |
| tests/adversarial/README.md | Sept 26 | Framework complete |
| tests/adversarial/conftest.py | Sept 26 | 72 fixtures ready |

**Next:** Push repo to GitHub, create all above issues, distribute reading lists, schedule meetings.
