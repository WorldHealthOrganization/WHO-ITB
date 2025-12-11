# ITB Test Development for SMART Guidelines - Standard Operating Procedure

## Document Purpose
This SOP provides guidance on mapping ITB (Interoperability Test Bed) concepts to WHO SMART Guidelines for conformance testing.

---

## 1. Glossary: ITB to SMART Guidelines Mapping

Reference: [ITB Glossary](https://www.itb.ec.europa.eu/docs/itb-ta/latest/introduction/index.html#glossary)

| ITB Term | SMART Guidelines Equivalent | Description | Example |
|----------|----------------------------|-------------|---------|
| **Community** | SMART Guideline Implementor Ecosystem | Global group implementing SMART Guidelines | WHO Member States, SMART Immunizations implementers |
| **Domain** | Implementation Guide (IG) | One domain per IG | `smart-immunizations`, `smart-hiv`, `smart-anc` |
| **Specification** | Functional & Non Functional Requirements | Testable requirement from the IG | "System SHALL capture patient demographics" |
| **Actor** | System Role/Persona/Actor | Testable capabilities in a system role that a system can implement | `patient-registry`, `immunization-recorder`, `decision-support` |
| **Organisation** | Software Implementor / Member State | Entity implementing the guideline | Ministry of Health Kenya, OpenMRS Foundation |
| **System** | Software Implementation | Specific software being tested | "Kenya EMR v3.2", "OpenMRS SMART Module" |
| **Conformance Statement** | Actor Implementation Declaration | Which actors a system implements | "System implements Patient Registration + Immunization Recording" |

---

## 2. Architecture Overview

### Domain Structure
```
Domain: smart-immunizations (one per IG)
├── Specifications (Requirements from IG)
│   ├── REQ-IMMZ-001: Patient Demographics Capture
│   ├── REQ-IMMZ-002: Vaccine Administration Recording
│   └── REQ-IMMZ-003: Contraindication Checking
│
├── Actors (System Roles)
│   ├── patient-registry
│   ├── immunization-recorder
│   └── decision-support
│
├── Test Suites (one per Actor)
│   ├── TS-patient-registry-v1
│   ├── TS-immunization-recorder-v1
│   └── TS-decision-support-v1
│
└── Organisations (Implementors)
    └── Systems declare which Actors they implement
```

### Key Principles

1. **Requirements are tied to Actors**
   - Each requirement specifies which actors must implement it
   - Example: REQ-IMMZ-002 (Vaccine Recording) → `immunization-recorder` actor

2. **Test Plans are grouped by Actors**
   - Each actor has one test suite
   - Test suite contains test cases for all requirements tied to that actor

3. **Systems declare Actors for conformance**
   - System: "Kenya EMR v3.2"
   - Declares: `patient-registry` (full), `immunization-recorder` (full), `decision-support` (partial)
   - Gets tested against those actors' test suites

---

## 3. Workflow

### For Test Authors

1. **Extract Requirements from IG**
   - Review StructureDefinitions, ActivityDefinitions, CQL Libraries
   - Document as Specifications with SHALL/SHOULD/MAY priority

2. **Define Actors**
   - Group related requirements by capability
   - Create one actor per major capability (e.g., recording, decision support)

3. **Create Test Suites**
   - One test suite per actor
   - Each test case validates one or more requirements

4. **Map to Test Assets**
   ```
   Requirement: REQ-IMMZ-002 "Vaccine Administration Recording"
   → Actor: immunization-recorder
   → Test Suite: TS-immunization-recorder-v1
   → Test Cases: TC-IR-001, TC-IR-002, TC-IR-003
   ```

### For Implementors

1. **Register Organization**
   - Create organization profile (e.g., "Ministry of Health - Kenya")

2. **Register System**
   - Define system (e.g., "Kenya EMR v3.2")
   - Declare which actors the system implements

3. **Run Tests**
   - Select domain (e.g., `smart-immunizations`)
   - Select actors to test (e.g., `immunization-recorder`)
   - Execute test suite
   - Review conformance statement

4. **Receive Conformance Report**
   - If all SHALL requirements pass → Full conformance
   - If ≥90% pass → Substantial conformance
   - If ≥70% pass → Partial conformance

---

## 4. Example: SMART Immunizations


## 5. Best Practices

### Requirement Definition
- Extract directly from IG artifacts (profiles, CQL, ActivityDefinitions)
- Use SHALL/SHOULD/MAY from RFC 2119
- Make requirements atomic and testable
- Map to FHIR canonical URLs

### Actor Design
- Keep actors focused on single capabilities
- Make actors composable (systems can implement multiple)
- Define clear FHIR operations per actor
- Example actors: `patient-registry`, `immunization-recorder`, `decision-support`, `terminology-service`

### Test Suite Organization
```
domain-smart-immunizations/
├── test-suites/
│   ├── patient-registry/
│   │   ├── test-suite.xml
│   │   └── test-cases/
│   ├── immunization-recorder/
│   │   ├── test-suite.xml
│   │   └── test-cases/
│   └── decision-support/
│       ├── test-suite.xml
│       └── test-cases/
└── test-data/
```

### Naming Conventions
- Domain: `{guideline-name}` → `smart-immunizations`
- Actor: `{capability-name}` → `immunization-recorder`
- Test Suite: `TS-{actor-id}-v{version}` → `TS-immunization-recorder-v1`
- Test Case: `TC-{actor-abbrev}-{num}` → `TC-IR-001`
- Requirement: `REQ-{domain-abbrev}-{num}` → `REQ-IMMZ-001`

---

## 6. References

- **ITB Documentation**: https://www.itb.ec.europa.eu/docs/
- **ITB Glossary**: https://www.itb.ec.europa.eu/docs/itb-ta/latest/introduction/index.html#glossary
- **WHO SMART Guidelines**: https://smart.who.int/
- **SMART Immunizations IG**: http://smart.who.int/immunizations

---

**Version**: 1.0  
**Date**: December 2024  
**Contact**: digital-health@who.int