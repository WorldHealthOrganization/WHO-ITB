# Standard Operating Procedure (SOP) for SMART Guidelines Testing

## Table of Contents
- [Introduction](#introduction)
- [Glossary: ITB to SMART Guidelines Mapping](#glossary-itb-to-smart-guidelines-mapping)
- [Architecture Overview](#architecture-overview)
- [Best Practices for Writing Tests](#best-practices-for-writing-tests)
- [Best Practices for Conformance Statements](#best-practices-for-conformance-statements)
- [Test Development Workflow](#test-development-workflow)
- [Examples](#examples)
- [References](#references)

---

## Introduction

This Standard Operating Procedure (SOP) provides guidance on how to develop tests and conformance statements for SMART Guidelines using the Interoperability Test Bed (ITB). It establishes a mapping between ITB concepts and SMART Guidelines concepts to ensure consistent test development and conformance validation.

**Purpose**: To standardize the approach for testing SMART Guidelines implementations and ensure interoperability across different software systems and member states.

**Audience**: 
- SMART Guideline implementors
- Software developers
- Quality assurance teams
- Member state technical teams

---

## Glossary: ITB to SMART Guidelines Mapping

This glossary maps concepts from the [Interoperability Test Bed (ITB) documentation](https://www.itb.ec.europa.eu/docs/itb-ta/latest/introduction/index.html#glossary) to SMART Guidelines concepts.

### Core Concept Mappings

| ITB Concept | SMART Guidelines Concept | Description | Example |
|-------------|--------------------------|-------------|---------|
| **Community** | **SMART Guideline Implementors** | A group of organizations working together to implement a specific SMART Guideline | WHO SMART Guidelines implementors, national health IT teams |
| **Domain** | **Implementation Guide (IG)** | A specific area of health IT standards, typically one per SMART Guidelines IG | `smart-immunizations`, `smart-hiv`, `smart-anc` (Antenatal Care), `smart-fp` (Family Planning) |
| **Specification** | **FHIR Requirements** | Formal requirements defined in FHIR artifacts within an IG | FHIR Requirement artifacts, profiles, value sets, StructureMaps |
| **Organisation** | **Software Implementor / Member State** | An entity implementing or deploying the SMART Guidelines | National health ministries, software vendors, NGO implementors |
| **Actor** | **System Role** | A role that a system plays in the guideline workflow | Patient Management System, Decision Support System, Laboratory System, Immunization Registry |
| **Test Suite** | **Conformance Test Collection** | A collection of test cases grouped by actor or functional area | VHL validation tests, ICVP transformation tests, immunization workflow tests |
| **Test Case** | **Conformance Test Scenario** | A specific test scenario validating one or more requirements | "Validate HCERT with VHL", "Transform ICVP to IPS Bundle" |
| **System** | **Software System Under Test (SUT)** | The software being tested for conformance | Electronic Health Record system, Vaccination registry, Mobile health app |
| **Conformance Statement** | **System Capability Declaration** | A declaration of which actors and requirements a system implements | "System X implements Patient Management Actor with requirements R1-R5" |

### Additional ITB Concepts Relevant to SMART Guidelines

| ITB Concept | SMART Guidelines Usage | Description |
|-------------|------------------------|-------------|
| **Test Session** | **Conformance Validation Run** | An execution of one or more test cases to validate conformance |
| **Test Report** | **Conformance Evidence** | Documentation of test results used to demonstrate conformance |
| **Endpoint** | **FHIR Server Endpoint** | A network location where a system can be accessed for testing |
| **Parameter** | **Test Configuration** | Input values required for test execution (URLs, credentials, test data) |
| **Handler** | **Test Integration Point** | Technical component that connects to the system under test (HTTP, SOAP, etc.) |

---

## Architecture Overview

### How Systems Declare Conformance

In the ITB framework adapted for SMART Guidelines:

1. **Systems** (software implementations) **declare the actors** they want to test against for conformance
2. **Requirements** are tied to **Actors**, defining what capabilities each actor must have
3. **Test plans** are grouped by **Actors**, making it clear which tests apply to which system roles
4. **Conformance statements** link a specific system to the actors it implements and the requirements it must meet

### Example Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    SMART Guidelines IG                          │
│                  (e.g., smart-immunizations)                    │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │ Defines
                              ▼
        ┌──────────────────────────────────────────────┐
        │              Actors (Roles)                  │
        │  • Immunization Registry                     │
        │  • Patient Management System                 │
        │  • Decision Support System                   │
        └──────────────────────────────────────────────┘
                              │
                              │ Each actor has
                              ▼
        ┌──────────────────────────────────────────────┐
        │         Requirements (FHIR artifacts)        │
        │  • Profiles (e.g., Immunization profile)     │
        │  • Value Sets (e.g., Vaccine codes)          │
        │  • StructureMaps (transformations)           │
        └──────────────────────────────────────────────┘
                              │
                              │ Validated by
                              ▼
        ┌──────────────────────────────────────────────┐
        │        Test Suites (by Actor)                │
        │  • Registry Conformance Tests                │
        │  • Patient Management Tests                  │
        │  • Interoperability Tests                    │
        └──────────────────────────────────────────────┘
                              │
                              │ Executed against
                              ▼
        ┌──────────────────────────────────────────────┐
        │      System Under Test (SUT)                 │
        │  Declares: "I implement Immunization         │
        │            Registry Actor"                   │
        └──────────────────────────────────────────────┘
```

---

## Best Practices for Writing Tests

### 1. Structure Tests by Actor

**Principle**: Group test cases by the actor (system role) they validate.

**Rationale**: This makes it easy for systems to identify which tests they need to run based on the actors they implement.

**Example**:
```
smart-immunizations/
  ├── test-suite-immunization-registry.xml
  ├── test-suite-patient-management.xml
  └── test-suite-decision-support.xml
```

### 2. Use Descriptive Test Case IDs and Descriptions

**Principle**: Each test case should have a clear, descriptive ID and human-readable description.

**Example**:
```xml
<testcase id="immunization-registry-01" xmlns="http://www.gitb.com/tdl/v1/">
  <metadata>
    <gitb:name>Validate Immunization Record</gitb:name>
    <gitb:version>1.0</gitb:version>
    <gitb:description>
      Validates that an immunization record conforms to the 
      smart-immunizations IG Immunization profile
    </gitb:description>
  </metadata>
</testcase>
```

### 3. Define Clear Actors

**Principle**: Explicitly define all actors involved in a test case.

**Example**:
```xml
<actors>
  <gitb:actor id="ImmunizationRegistry" name="Immunization Registry" role="SUT"/>
  <gitb:actor id="FHIRValidator" name="FHIR Validator" role="SIMULATED"/>
  <gitb:actor id="SMARTHelper" name="SMART Helper Service" role="SIMULATED"/>
</actors>
```

### 4. Validate FHIR Resources Against Profiles

**Principle**: Always validate FHIR resources against the appropriate profiles defined in the SMART Guidelines IG.

**Example**:
```xml
<send id="validateImmunization" 
      desc="Validate Immunization resource against profile" 
      handler="HttpMessagingV2" 
      from="User" 
      to="FHIRValidator">
  <input name="uri">$MATCHBOX_BASE$/validate</input>
  <input name="method">POST</input>
  <input name="headers">
    [{"Content-Type":"application/fhir+json"}]
  </input>
  <input name="body">{
    "resourceType": "Parameters",
    "parameter": [
      {
        "name": "resource",
        "resource": $immunizationResource$
      },
      {
        "name": "profile",
        "valueString": "http://smart.who.int/immunizations/StructureDefinition/Immunization"
      }
    ]
  }</input>
</send>
```

### 5. Include Test Data

**Principle**: Provide sample test data that covers both positive and negative test scenarios.

**Best Practices**:
- Include valid data that should pass validation
- Include invalid data to test error handling
- Use realistic data that reflects real-world scenarios
- Document any test data requirements (e.g., specific codes, date formats)

### 6. Test Transformations Using StructureMaps

**Principle**: When testing data transformations defined in SMART Guidelines, validate both the transformation process and the output.

**Example**:
```xml
<!-- Step 1: Transform the data -->
<send id="transformData" 
      desc="Transform using StructureMap" 
      handler="HttpMessagingV2" 
      from="User" 
      to="SMARTHelper">
  <input name="uri">$SMART_HELPER_BASE$/transform</input>
  <input name="method">POST</input>
  <input name="body">$inputResource$</input>
</send>

<!-- Step 2: Validate the transformed output -->
<send id="validateTransformed" 
      desc="Validate transformed resource" 
      handler="HttpMessagingV2" 
      from="User" 
      to="FHIRValidator">
  <!-- validation configuration -->
</send>
```

### 7. Use Assertions Effectively

**Principle**: Include clear assertions that verify the expected behavior.

**Example**:
```xml
<verify id="checkStatus" 
        desc="Verify HTTP status is 200" 
        handler="StringValidator">
  <input name="actualstring">$response.status$</input>
  <input name="expectedstring">200</input>
</verify>

<verify id="checkValidation" 
        desc="Verify validation result is successful" 
        handler="JsonValidator">
  <input name="json">$response.body$</input>
  <input name="expression">$.successful</input>
  <input name="expected">true</input>
</verify>
```

### 8. Handle Errors Gracefully

**Principle**: Tests should handle errors appropriately and provide useful error messages.

**Best Practices**:
- Use try-catch blocks when appropriate
- Provide context in error messages
- Log relevant information for debugging
- Distinguish between expected failures (negative tests) and unexpected failures

### 9. Document Prerequisites and Setup

**Principle**: Clearly document any prerequisites, setup steps, or configuration needed for tests.

**Example**:
```xml
<metadata>
  <gitb:description>
    Prerequisites:
    - Matchbox server must have smart-immunizations IG loaded
    - Test data directory must contain sample immunization records
    - FHIR server must be accessible at configured endpoint
  </gitb:description>
</metadata>
```

### 10. Make Tests Maintainable

**Principle**: Write tests that are easy to maintain and update as IGs evolve.

**Best Practices**:
- Use variables for URLs and configuration values
- Parameterize test data where possible
- Keep test cases focused on a single concern
- Use consistent naming conventions
- Document complex logic or business rules

---

## Best Practices for Conformance Statements

### 1. Define Clear Scope

**Principle**: A conformance statement should clearly define which actors and requirements a system implements.

**Example**:
```xml
<conformance-statement>
  <actor>Immunization Registry</actor>
  <requirements>
    <requirement id="REQ-001">Support Immunization profile</requirement>
    <requirement id="REQ-002">Support ImmunizationRecommendation profile</requirement>
    <requirement id="REQ-003">Implement $recommend operation</requirement>
  </requirements>
</conformance-statement>
```

### 2. Link to Implementation Guide

**Principle**: Reference the specific Implementation Guide and version being tested.

**Example**:
```xml
<implementation-guide>
  <name>SMART Guidelines - Immunizations</name>
  <url>http://smart.who.int/immunizations</url>
  <version>1.0.0</version>
</implementation-guide>
```

### 3. Specify Test Coverage

**Principle**: Clearly indicate which test cases must pass for conformance.

**Example**:
```xml
<test-coverage>
  <mandatory>
    <test-case id="immunization-registry-01"/>
    <test-case id="immunization-registry-02"/>
  </mandatory>
  <optional>
    <test-case id="immunization-registry-advanced-01"/>
  </optional>
</test-coverage>
```

### 4. Document Limitations and Exceptions

**Principle**: Be transparent about any limitations or exceptions in the implementation.

**Example**:
```xml
<limitations>
  <limitation>
    Immunization history query limited to past 5 years
  </limitation>
  <exception>
    Recommendation engine does not support custom contraindications
  </exception>
</limitations>
```

### 5. Include Version Information

**Principle**: Track versions of both the system under test and the conformance statement.

**Example**:
```xml
<version-info>
  <system-version>2.1.0</system-version>
  <conformance-statement-version>1.0</conformance-statement-version>
  <last-tested>2024-12-01</last-tested>
</version-info>
```

---

## Test Development Workflow

### Phase 1: Planning

1. **Identify the SMART Guidelines IG** to be tested (e.g., smart-immunizations)
2. **Identify the actors** defined in the IG
3. **Review the requirements** (FHIR profiles, value sets, operations) for each actor
4. **Define test scenarios** that validate each requirement

### Phase 2: Setup

1. **Create the domain** in ITB (one per IG)
2. **Configure the test environment**:
   - FHIR validation server (e.g., Matchbox)
   - Helper services for transformations
   - Test data repositories
3. **Load the Implementation Guide** into the validation server
4. **Prepare test data** covering various scenarios

### Phase 3: Development

1. **Create test suites** grouped by actor
2. **Develop test cases** following best practices
3. **Implement test scripts** using ITB TDL (Test Description Language)
4. **Add validation steps** using appropriate validators

### Phase 4: Validation

1. **Execute test cases** in a development environment
2. **Review test results** and refine tests
3. **Document test coverage** and expected outcomes
4. **Perform peer review** of test cases

### Phase 5: Deployment

1. **Deploy test suites** to the ITB instance
2. **Configure conformance statements** for target systems
3. **Provide documentation** to implementors
4. **Support initial test runs** and address questions

### Phase 6: Maintenance

1. **Monitor test results** and collect feedback
2. **Update tests** when IGs are revised
3. **Address false positives/negatives**
4. **Expand test coverage** based on real-world scenarios

---

## Examples

### Example 1: Simple FHIR Resource Validation Test

This example shows a basic test that validates a FHIR Immunization resource against a profile.

**Test Case**: `validate-immunization-resource.xml`

```xml
<?xml version="1.0" encoding="UTF-8"?>
<testcase id="validate-immunization" xmlns="http://www.gitb.com/tdl/v1/">
  <metadata>
    <gitb:name>Validate Immunization Resource</gitb:name>
    <gitb:version>1.0</gitb:version>
    <gitb:description>
      Validates an Immunization resource against the 
      smart-immunizations IG Immunization profile
    </gitb:description>
  </metadata>
  
  <actors>
    <gitb:actor id="User" name="User" role="SUT"/>
    <gitb:actor id="FHIRValidator" name="FHIR Validator" role="SIMULATED"/>
  </actors>
  
  <steps>
    <!-- Step 1: User provides Immunization resource -->
    <interact id="uploadResource" 
              desc="Upload Immunization resource" 
              with="User">
      <request>
        <var name="immunizationJSON" 
             type="string" 
             desc="FHIR Immunization resource in JSON format"/>
      </request>
    </interact>
    
    <!-- Step 2: Validate against profile -->
    <send id="validateResource" 
          desc="Validate against Immunization profile" 
          handler="HttpMessagingV2" 
          from="User" 
          to="FHIRValidator">
      <input name="uri">$MATCHBOX_BASE$/validate</input>
      <input name="method">POST</input>
      <input name="headers">
        [{"Content-Type":"application/fhir+json"}]
      </input>
      <input name="body">{
        "resourceType": "Parameters",
        "parameter": [
          {
            "name": "resource",
            "resource": $immunizationResource$
          },
          {
            "name": "profile",
            "valueString": "http://smart.who.int/immunizations/StructureDefinition/Immunization"
          }
        ]
      }</input>
      <output name="status">response.statusCode</output>
      <output name="result">response.body</output>
    </send>
    
    <!-- Step 3: Verify validation passed -->
    <verify id="checkStatus" 
            desc="Verify HTTP status is 200" 
            handler="StringValidator">
      <input name="actualstring">$status$</input>
      <input name="expectedstring">200</input>
    </verify>
    
    <verify id="checkValidationSuccess" 
            desc="Verify no validation errors" 
            handler="JsonValidator">
      <input name="json">$result$</input>
      <input name="expression">$.issue[?(@.severity=='error')].length()</input>
      <input name="expected">0</input>
    </verify>
  </steps>
</testcase>
```

### Example 2: Conformance Statement for an Immunization Registry

This example shows how a conformance statement would be structured for a system implementing the Immunization Registry actor.

**Conformance Statement**: `immunization-registry-conformance.xml`

```xml
<?xml version="1.0" encoding="UTF-8"?>
<conformance-statement id="registry-system-v1">
  <system>
    <name>National Immunization Registry</name>
    <vendor>Health IT Solutions Inc.</vendor>
    <version>2.1.0</version>
  </system>
  
  <implementation-guide>
    <name>SMART Guidelines - Immunizations</name>
    <url>http://smart.who.int/immunizations</url>
    <version>1.0.0</version>
  </implementation-guide>
  
  <actor id="ImmunizationRegistry">
    <name>Immunization Registry</name>
    <description>
      Central registry for recording and querying immunization records
    </description>
  </actor>
  
  <requirements>
    <requirement id="REQ-001" status="implemented">
      <description>Support FHIR Immunization profile</description>
      <profile>http://smart.who.int/immunizations/StructureDefinition/Immunization</profile>
    </requirement>
    
    <requirement id="REQ-002" status="implemented">
      <description>Support ImmunizationRecommendation profile</description>
      <profile>http://smart.who.int/immunizations/StructureDefinition/ImmunizationRecommendation</profile>
    </requirement>
    
    <requirement id="REQ-003" status="implemented">
      <description>Implement $recommend operation</description>
      <operation>http://smart.who.int/immunizations/OperationDefinition/recommend</operation>
    </requirement>
    
    <requirement id="REQ-004" status="not-implemented">
      <description>Support ImmunizationEvaluation profile</description>
      <profile>http://smart.who.int/immunizations/StructureDefinition/ImmunizationEvaluation</profile>
      <notes>Planned for version 2.2.0</notes>
    </requirement>
  </requirements>
  
  <test-coverage>
    <mandatory>
      <test-case id="validate-immunization" expected-result="pass"/>
      <test-case id="validate-recommendation" expected-result="pass"/>
      <test-case id="test-recommend-operation" expected-result="pass"/>
    </mandatory>
    
    <optional>
      <test-case id="advanced-query-scenarios" expected-result="pass"/>
    </optional>
  </test-coverage>
  
  <limitations>
    <limitation>Query limited to records from past 10 years</limitation>
    <limitation>Batch operations limited to 100 resources per request</limitation>
  </limitations>
  
  <last-tested>YYYY-MM-DD</last-tested>
  <next-review>YYYY-MM-DD</next-review>
</conformance-statement>
```

### Example 3: Multi-Actor Test Suite Structure

This example shows how to organize test suites for a SMART Guidelines IG with multiple actors.

**Directory Structure**:
```
testsuites/smart-immunizations/
├── test-suite-immunization-registry.xml          # Tests for Registry actor
├── test-suite-patient-management.xml             # Tests for Patient Mgmt actor
├── test-suite-decision-support.xml               # Tests for Decision Support actor
├── test-suite-interoperability.xml               # Cross-actor tests
├── test-cases/
│   ├── registry/
│   │   ├── validate-immunization-record.xml
│   │   ├── query-immunization-history.xml
│   │   └── recommend-vaccinations.xml
│   ├── patient-management/
│   │   ├── register-patient.xml
│   │   └── update-patient-demographics.xml
│   ├── decision-support/
│   │   ├── calculate-recommendation.xml
│   │   └── check-contraindications.xml
│   └── interoperability/
│       ├── end-to-end-vaccination-workflow.xml
│       └── data-synchronization.xml
└── test-data/
    ├── valid-immunization-records/
    ├── invalid-immunization-records/
    └── patient-demographics/
```

---

## References

### ITB Documentation
- **ITB Glossary**: https://www.itb.ec.europa.eu/docs/itb-ta/latest/introduction/index.html#glossary
- **ITB Test Case Development**: https://www.itb.ec.europa.eu/docs/guides/latest/testCases/index.html
- **ITB Conformance Testing**: https://www.itb.ec.europa.eu/docs/guides/latest/conformanceTesting/index.html

### SMART Guidelines
- **WHO SMART Guidelines**: https://www.who.int/teams/digital-health-and-innovation/smart-guidelines
- **SMART Trust Documentation**: https://smart.who.int/trust
- **SMART Immunizations IG**: http://smart.who.int/immunizations
- **FHIR Implementation Guide Registry**: https://registry.fhir.org

### FHIR Resources
- **FHIR Specification**: http://hl7.org/fhir/
- **FHIR Conformance**: http://hl7.org/fhir/conformance-module.html
- **FHIR StructureMap**: http://hl7.org/fhir/structuremap.html
- **FHIR Validation**: http://hl7.org/fhir/validation.html

### WHO-ITB Repository
- **WHO-ITB Repository**: https://github.com/WorldHealthOrganization/WHO-ITB
- **User Guide**: [USER_GUIDE.md](USER_GUIDE.md)
- **README**: [README.md](README.md)

---

## Version History

| Version | Date | Changes | Author |
|---------|------|---------|--------|
| 1.0 | YYYY-MM-DD | Initial SOP creation | WHO-ITB Team |

---

## Feedback and Contributions

This SOP is a living document. Feedback and contributions are welcome through the [WHO-ITB GitHub repository](https://github.com/WorldHealthOrganization/WHO-ITB/issues).

For questions or support, please:
1. Check the [User Guide](USER_GUIDE.md) for operational questions
2. Review the [ITB Documentation](https://www.itb.ec.europa.eu/docs/itb-ta/latest/)
3. Open an issue in the GitHub repository
4. Contact the WHO SMART Guidelines team
