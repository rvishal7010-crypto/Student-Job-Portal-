# Firestore Security Specification

This document details the data invariants, threat model payloads ("Dirty Dozen"), and validation requirements for the Campus Recruitment Drive application.

## 1. Data Invariants

- **User Profiles (`/users/{userId}`)**:
  1. A user can only access, create, or update their own profile document.
  2. The `role` field is restricted to `student` or `admin`. 
  3. No student can self-escalate their `role` to `admin`.
  4. Only registered admins can list all student profiles.

- **Job Vacancies (`/jobs/{jobId}`)**:
  1. Anyone authenticated can read/list jobs.
  2. Only authorized admins can create, update, or delete jobs.
  3. Job fields like `id`, `company`, `title`, and `postedDate` must match structural boundaries.

- **Applications (`/applications/{appId}`)**:
  1. A user can only submit an application (`create`) where `userId` matches their authenticated UID.
  2. A user can only view their own applications, while admins can view/list all applications.
  3. A user cannot update application state (`status`) once submitted. Only administrators can transition application states through `Reviewed`, `Shortlisted`, and `Rejected`.
  4. Application IDs and associated foreign IDs must conform to secure string constraints.

---

## 2. The "Dirty Dozen" Threat Payloads

Here are 12 specific payloads attempting to violate identity, integrity, and state boundaries:

### Identity Spoofing & Escalation
1. **Payload 1 (Self-Admin creation)**: A student registration payload attempting to set `role: "admin"` during initial write.
2. **Payload 2 (Admin profile hijack)**: An authenticated student attempting to update another user's profile document (`/users/admin-uid`) to change fields.
3. **Payload 3 (Foreign profile update)**: A user attempting to modify another student's saved bookmarks (`savedJobs`) or skills.

### Security / Integrity Bypass
4. **Payload 4 (Massive ID injection)**: Attempting to create a document with a junk-padded ID string exceeding 256 bytes to over-consume database memory.
5. **Payload 5 (Unchecked custom claims/role update)**: Attempting to update profile status without verified authentication.
6. **Payload 6 (PII scraping)**: Attempting to perform list queries on `/users` collection without proper admin flags.

### Application Integrity & State Shortcutting
7. **Payload 7 (Self-Approve)**: A student submitting or updating their application (`/applications/app-1`) directly to `status: "Shortlisted"`.
8. **Payload 8 (Foreign Application Injection)**: Authenticated user `A` submitting an application with `userId: "B"` to claim user `B`'s profile slot.
9. **Payload 9 (Rogue Job Creation)**: A non-admin user trying to write a job posting directly into `/jobs`.
10. **Payload 10 (Rogue Job Deletion)**: A student attempting to delete a job post document.
11. **Payload 11 (Malicious Payload Size)**: An application document containing extremely large base64 descriptions/payloads exceeding standard document bounds.
12. **Payload 12 (Terminal state tampering)**: Overwriting a reviewed or rejected application status back to "Applied" to restart the evaluation.

---

## 3. Threat Mitigation and Validation Plan

Our ruleset will enforce:
- Authenticated state mapping.
- Document-ID hardening via `isValidId()`.
- Explicit schema mapping helpers.
- Tiered privilege division (`isAdmin()` vs `isOwner()`).
