# WHO-ITB with HCERT Validation
This is a shareable, pre-configured instance of the Interoperability Test Bed for WHO purposes, enhanced with HCERT (Health Certificate) validation test cases.

## Quick Start

**New to WHO-ITB?** Check out the **[User Guide](USER_GUIDE.md)** for step-by-step instructions on:
- Running Docker and loading the configuration
- Logging in and changing your password
- Navigating to conformance statements and starting test sessions
- Running HCERT with VHL test cases
- Running ICVP test cases

## Table of Contents
- [Repository contents](#repo-contents)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [HCERT Test Cases](#hcert-test-cases)
- [Building and Deployment](#building-and-deployment)
- [Running Test Cases](#running-test-cases)
- [Users](#users-for-immediate-usage)
- [Architecture](#architecture)
- [Links](#links)

## Repo contents
As a quick overview, this repository contains:
+ A running, empty Interoperability Test Bed instance (GITB) with all required containers (base ITB composition);
+ All helper services with full sourcecode and as containers for the composition;
+ GDHCN validator service for HCERT processing and validation;
+ An initial configuration of the domains with communities, organizations, users and admins, etc., including:
    + Multiple testing domains and conformance statements from WHO in these domains;
    + Testsuites and test-cases for these domains (example: HAJJ Program);
    
## Prerequisites
### Prerequisites for running
- Git
- Docker with compose
- A browser
- Internet connection (for GDHCN validator image)

### Prerequisites for development and testing
- Basic knowledge of ITB test case development

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/szalaierik-tsch/WHO-ITB
   cd WHO-ITB
   ```

2. Start the composition with Docker on your local machine (will build the helper service and pull GDHCN validator):
   ```bash 
   docker-compose up --build
   ```
   This will start:
   - ITB Test Bed UI at http://localhost:10003
   - Helper Services at http://localhost:10005
   - GDHCN Validator at http://localhost:8080
   - MatchBox at  http://localhost:8089

3. Go to http://localhost:10003 in your browser.

4. Log in with a predefined user (see Users section below).

5. If you ever want to drop the instance and start up from scratch again, then just remove the composition together with the volumes and start from point 2:
   ```bash
   docker compose down -v
   ```

## HCERT Test Cases

This repository includes a comprehensive test suite for HCERT (Health Certificate) validation. The test suite covers:

### Test Case Coverage
1. **Valid HCERT QR Code Validation** (`tc-qr-valid-hcert`)
   - Tests QR code format validation
   - Validates HC1: prefix requirement
   - Ensures proper QR code decoding

2. **Invalid HCERT QR Code Rejection** (`tc-qr-invalid-hcert`)
   - Negative test for invalid QR codes
   - Tests proper error handling
   - Validates rejection of non-HCERT codes

3. **CWT Token Extraction** (`tc-cwt-extraction`)
   - Tests Base45 decoding
   - Validates ZLIB decompression
   - Ensures CBOR Web Token structure

4. **CWT Structure Validation** (`tc-cwt-validation`)
   - Validates CWT against FHIR StructureDefinition
   - Tests compliance with http://smart.who.int/trust/StructureDefinition/CWT

5. **Signature Algorithm Validation** (`tc-signature-algorithm-validation`)
   - Tests ES256 (Primary - ECC P-256) support
   - Tests PS256 (Secondary - RSA PSS) support
   - Validates COSE parameter mapping

6. **Key Identifier Validation** (`tc-key-identifier-validation`)
   - Tests 8-byte key ID format
   - Validates ISO 3166-1 alpha-2 country codes
   - Tests trust network key retrieval

7. **Digital Signature Verification** (`tc-signature-verification`)
   - Tests cryptographic signature validation
   - Validates certificate expiration
   - Tests trust chain verification

8. **HCERT Payload Extraction** (`tc-hcert-payload-extraction`)
   - Tests claim key -260 extraction
   - Validates HCERT structure against FHIR StructureDefinition
   - Supports multiple certificate types (EU DCC, DDCC VS, DDCC TR)

### Supported Certificate Types
- **EU DCC**: European Digital COVID Certificate
- **DDCC VS**: WHO DDCC Vaccination Certificate
- **DDCC TR**: WHO DDCC Test Result Certificate
- **Smart Health Links**: URI-based health certificates

## Building and Deployment

### Standard Deployment
For regular use, follow the installation steps above. The system will automatically:
1. Build the WHO helper services from source
2. Pull the GDHCN validator image
3. Initialize the ITB with pre-configured test suites
4. Set up all required services and dependencies

### Development Deployment
If you need to modify the helper services or test cases:

1. **Modify Helper Services**:
   ```bash
   cd who-helper
   # Make your changes to the Java code
   mvn clean package
   cd ..
   docker-compose build who-helper-services
   docker-compose up -d who-helper-services
   ```

2. **Update Test Cases**:
   - Modify files in `test-suites/hcert-validation/`
   - Test cases: `test-suites/hcert-validation/test-cases/`
   - Scriptlets: `test-suites/hcert-validation/scriptlets/`
   - Resources: `test-suites/hcert-validation/resources/`

3. **Deploy Updated Test Suite**:
   ```bash
   # Create test suite package
   cd test-suites/hcert-validation
   zip -r hcert-validation-test-suite.zip .
   
   # Upload via ITB UI at http://localhost:10003
   # Go to Administration > Test Suites > Import
   ```

### Custom Validator Integration
To use a different GDHCN validator instance:

1. Update `docker-compose.override.yml`:
   ```yaml
   services:
     gdhcn-validator:
       image: your-custom-validator:tag
       # or use external service:
       external_links:
         - "your-validator-host:gdhcn-validator"
   ```

2. Update environment variables:
   ```yaml
   services:
     who-helper-services:
       environment:
         - GDHCN_VALIDATOR_ENDPOINT=http://your-validator-host:port
   ```

## Running Test Cases

### Prerequisites for Test Execution
1. Ensure all services are running:
   ```bash
   docker-compose ps
   # Should show all services as "Up"
   ```

2. Verify GDHCN validator health:
   ```bash
   curl http://localhost:8080/actuator/health
   # Should return {"status":"UP"}
   ```

### Executing HCERT Test Cases

1. **Access ITB UI**: http://localhost:10003

2. **Login** with test user:
   - Username: `user@who.itb.test`
   - Password: `change_this_password`

3. **Navigate to Test Sessions**:
   - Go to "Test Sessions" menu
   - Select "HCERT Validation Test Suite"

4. **Run Individual Test Cases**:
   - **Valid QR Code Test**: Select `tc-qr-valid-hcert`
   - **Invalid QR Code Test**: Select `tc-qr-invalid-hcert`
   - **CWT Extraction Test**: Select `tc-cwt-extraction`
   - **Algorithm Validation**: Select `tc-signature-algorithm-validation`
   - **Key Validation**: Select `tc-key-identifier-validation`
   - **Signature Verification**: Select `tc-signature-verification`
   - **Payload Extraction**: Select `tc-hcert-payload-extraction`

5. **Provide Test Inputs**:
   Each test case will prompt for required inputs:
   - **QR Code Content**: Paste HCERT QR code string
   - **CWT Tokens**: Provide extracted CWT data
   - **Configuration**: Set validation parameters

6. **Monitor Test Execution**:
   - Real-time test execution logs
   - Step-by-step validation results
   - Detailed error reporting
   - Comprehensive test reports

### Sample Test Data
The test suite includes sample data in `test-suites/hcert-validation/resources/test-data.json`:

```json
{
  "validHCERTQRCode": "HC1:NCFOXN%TSMAHN-H+XO5XF7:UY%FJ.FK6ZK7...",
  "invalidQRCode": "INVALID:NCFOXN%TSMAHN-H+XO5XF7...",
  "supportedAlgorithms": ["ES256", "PS256"],
  "testCountryCodes": ["DE", "FR", "IT", "ES", "NL", "BE"]
}
```

### Test Execution Modes

#### 1. Interactive Mode
- Manual test execution via ITB UI
- Step-by-step interaction
- Real-time input and validation
- Suitable for development and debugging

#### 2. Automated Mode
- REST API-based execution
- Batch test execution
- CI/CD integration support
- Suitable for continuous validation

Example automated execution:
```bash
# Execute test case via API
curl -X POST http://localhost:10003/api/rest/tests/execute \
  -H "Content-Type: application/json" \
  -d '{
    "testSuite": "ts-hcert-validation",
    "testCase": "tc-qr-valid-hcert",
    "inputs": {
      "qrContent": "HC1:NCFOXN%TSMAHN-H+XO5XF7..."
    }
  }'
```

### Test Reports and Results
After test execution, detailed reports are available:

1. **Test Session Reports**:
   - Overall test results
   - Step-by-step execution details
   - Validation outcomes
   - Error analysis

2. **Export Options**:
   - PDF reports
   - XML test results
   - JSON execution logs
   - CSV summary data

3. **Integration Reports**:
   - Compliance assessment
   - Standards conformance
   - Interoperability validation

## Users for immediate usage
Users are set up with temporary passwords, you need to change it immediately after the first login.

| Username | Password | Role | Purpose |
|----------|----------|------|---------|
| your email id| change_this_password | Tester | Execute validation tests |
| user@who.itb.test | change_this_password | Tester | Execute validation tests |
| admin@who.itb.test | change_this_password | Admin | Configure test suites and manage users |

## Architecture

### Component Overview
```
┌─────────────────┐  ┌──────────────────┐  ┌─────────────────┐
│   ITB Test Bed  │  │  WHO Helper      │  │ GDHCN Validator │
│   (port 10003)  │◄─┤  Services        │◄─┤ (port 8080)     │
│                 │  │  (port 10005)    │  │                 │
└─────────────────┘  └──────────────────┘  └─────────────────┘
         │                       │
         ▼                       ▼
┌─────────────────┐  ┌──────────────────┐
│   Test Cases    │  │   HCERT          │
│   Orchestration │  │   Validation     │
│                 │  │   Logic          │
└─────────────────┘  └──────────────────┘
```

### Service Integration
- **ITB Test Bed**: Orchestrates test execution and provides UI
- **WHO Helper Services**: Custom test service implementations for HCERT validation
- **GDHCN Validator**: Specialized service for HCERT/CWT processing and validation
- **Test Cases**: XML-based test definitions following GITB TDL specifications

### Data Flow
1. **Test Initiation**: User triggers test via ITB UI
2. **Test Orchestration**: ITB processes test case XML and invokes scriptlets
3. **Service Calls**: Helper services call GDHCN validator for HCERT processing
4. **Validation**: GDHCN validator performs cryptographic and structural validation
5. **Result Processing**: Results are processed and formatted for ITB reporting
6. **Report Generation**: Comprehensive test reports with validation outcomes

## Configuration Management

### Environment Variables
Key configuration parameters in `docker-compose.override.yml`:

```yaml
environment:
  - GDHCN_VALIDATOR_ENDPOINT=http://gdhcn-validator:8080
  - ITB_DOMAIN_KEY=WHO_HCERT
  - DATA_ARCHIVE_KEY=WHO_ITB1
  - AUTOMATION_API_ENABLED=true
```

### Domain Configuration
The ITB is configured with HCERT-specific domain settings:
- **Domain**: WHO HCERT Validation
- **Validation Service**: Custom HCERT validation logic
- **Processing Service**: HCERT-aware processing operations
- **Test Data**: Pre-loaded with sample HCERT certificates

### Customization Options
1. **Validation Rules**: Modify validation logic in helper services
2. **Test Scenarios**: Add/modify test cases in test-suites directory
3. **Certificate Support**: Extend support for additional certificate types
4. **Integration Points**: Configure external validator services

## Troubleshooting

### Common Issues

1. **Services Not Starting**:
   ```bash
   # Check service status
   docker-compose ps
   
   # Check logs
   docker-compose logs gdhcn-validator
   docker-compose logs who-helper-services
   ```

2. **GDHCN Validator Connection Issues**:
   ```bash
   # Test validator connectivity
   curl http://localhost:8080/actuator/health
   
   # Check network connectivity
   docker network ls
   docker network inspect who-itb_default
   ```

3. **Test Execution Failures**:
   - Check test case XML syntax
   - Verify scriptlet dependencies
   - Validate test data format
   - Review helper service logs

### Performance Optimization
- Increase Docker memory allocation for large test suites
- Configure appropriate timeout values for validator calls
- Optimize test data size for faster execution

## Security Considerations
- Default passwords must be changed immediately
- Consider running on isolated networks for production testing
- Implement proper certificate management for mTLS connections
- Regular security updates for all container images

# Links and further reading
This testing composition uses the Interoperability Test Bed as the main tool of orchestrating and reporting test-cases. See further resources on it below.

## Documentation
- **[User Guide](USER_GUIDE.md)**: Step-by-step guide for running tests and using the system
- **[HCERT Test Guide](HCERT_TEST_GUIDE.md)**: Detailed technical guide for HCERT test execution

## Introduction to the ITB
https://interoperable-europe.ec.europa.eu/collection/interoperability-test-bed-repository/solution/interoperability-test-bed

## WHO SMART Trust Documentation
https://smart.who.int/trust

## GDHCN Specifications
https://smart.who.int/trust/concepts.html
