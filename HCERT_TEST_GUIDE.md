# HCERT Test Execution Guide

This guide provides detailed instructions for executing the FLINT-based HCERT validation test cases in the WHO-ITB environment.

## Table of Contents
- [Quick Start](#quick-start)
- [Test Case Overview](#test-case-overview)
- [Detailed Test Execution](#detailed-test-execution)
- [Sample Test Data](#sample-test-data)
- [Troubleshooting](#troubleshooting)
- [Advanced Usage](#advanced-usage)

## Quick Start

### 1. Deploy the Test Environment
```bash
# Linux/Mac
./deploy-hcert-tests.sh

# Windows
deploy-hcert-tests.bat
```

### 2. Access the Test Environment
- **ITB UI**: http://localhost:10003
- **Login**: user@who.itb.test / change_this_password
- **Change password** on first login

### 3. Execute Tests
1. Navigate to **Test Sessions**
2. Select **HCERT Validation Test Suite**
3. Choose a test case and click **Start**

## Test Case Overview

### Test Suite: `ts-hcert-validation`
**Description**: Comprehensive HCERT validation test suite based on WHO GDHCN specifications

| Test Case ID | Name | Description | Duration |
|--------------|------|-------------|----------|
| `tc-qr-valid-hcert` | Valid HCERT QR Code | Tests valid QR code format and HC1: prefix | ~2 min |
| `tc-qr-invalid-hcert` | Invalid HCERT QR Code | Tests rejection of invalid QR codes | ~2 min |
| `tc-cwt-extraction` | CWT Token Extraction | Tests Base45 decoding and CBOR extraction | ~3 min |
| `tc-cwt-validation` | CWT Structure Validation | Validates CWT against FHIR StructureDefinition | ~2 min |
| `tc-signature-algorithm-validation` | Algorithm Validation | Tests ES256/PS256 algorithm support | ~2 min |
| `tc-key-identifier-validation` | Key ID Validation | Tests 8-byte key ID and country code format | ~3 min |
| `tc-signature-verification` | Signature Verification | Tests cryptographic signature validation | ~4 min |
| `tc-hcert-payload-extraction` | Payload Extraction | Tests HCERT payload extraction from CWT | ~3 min |

## Detailed Test Execution

### Prerequisites
1. **Service Health Check**:
   ```bash
   # Check all services are running
   docker-compose ps
   
   # Verify GDHCN validator
   curl http://localhost:8080/actuator/health
   
   # Verify ITB services
   curl http://localhost:10003
   curl http://localhost:10005/flint/services/process?wsdl
   ```

2. **Test Data Preparation**:
   - Valid HCERT QR codes
   - Invalid QR code samples
   - Sample CWT tokens
   - Country codes and key identifiers

### Test Case 1: Valid HCERT QR Code Validation

**Objective**: Validate that a properly formatted HCERT QR code is correctly processed.

**Steps**:
1. **Start Test**: Select `tc-qr-valid-hcert`
2. **Provide QR Code**: When prompted, enter:
   ```
   HC1:NCFOXN%TSMAHN-H+XO5XF7:UY%FJ.FK6ZK7:EDOLOPCO8F6%E5.FK:*P QDHQF67463W5KF6946846G41NKF:QN:96-JN*T1:G1-QN-HKF%6PFQ/TSCZB1KEC0JH%F3*R1YS0JZ9*47+E4F0F6L9HFQE%6I*LG0Z+QN+KN%LO%8M50FLJI%6P9GQHO%F9I1K%P1R2CL%HD-7J/C0*T05THVGK3G-HKPQ1FC
   ```
3. **Expected Results**:
   - ✅ QR code successfully decoded
   - ✅ HC1: prefix validated
   - ✅ HCERT format confirmed
   - ✅ Overall result: SUCCESS

**Validation Points**:
- Prefix validation: Must start with "HC1:"
- QR code format: ISO/IEC 18004:2015 compliance
- Alphanumeric encoding: Mode 2 encoding validation

### Test Case 2: Invalid HCERT QR Code Validation

**Objective**: Ensure invalid QR codes are properly rejected.

**Steps**:
1. **Start Test**: Select `tc-qr-invalid-hcert`
2. **Provide Invalid QR Code**:
   ```
   INVALID:NCFOXN%TSMAHN-H+XO5XF7:UY%FJ.FK6ZK7:EDOLOPCO8F6%E5.FK
   ```
3. **Expected Results**:
   - ❌ QR code rejected due to invalid prefix
   - ✅ Proper error handling
   - ✅ Error message: "invalid_prefix"
   - ✅ Overall result: SUCCESS (negative test)

### Test Case 3: CWT Token Extraction

**Objective**: Extract and validate CBOR Web Token from valid HCERT.

**Steps**:
1. **Start Test**: Select `tc-cwt-extraction`
2. **Provide HCERT**: Enter valid HC1: prefixed QR code
3. **Process Flow**:
   - Remove HC1: prefix
   - Base45 decode payload
   - ZLIB decompress
   - Validate CBOR format
4. **Expected Results**:
   - ✅ Base45 decoding successful
   - ✅ ZLIB decompression successful
   - ✅ Valid CBOR Web Token extracted
   - ✅ CWT structure conforms to FHIR StructureDefinition

### Test Case 4: Signature Algorithm Validation

**Objective**: Validate supported cryptographic algorithms.

**Steps**:
1. **Start Test**: Select `tc-signature-algorithm-validation`
2. **Provide CWT**: Enter CWT token data
3. **Algorithm Testing**:
   - Extract algorithm claim (claim '1')
   - Validate algorithm support
   - Check SOG-IT compliance level
4. **Expected Results**:
   - ✅ ES256: Primary (ECC P-256) ✓
   - ✅ PS256: Secondary (RSA PSS) ✓
   - ❌ Other algorithms: Not supported

**Supported Algorithms**:
| Algorithm | COSE Parameter | SOG-IT Level | Status |
|-----------|----------------|--------------|--------|
| ES256 | ES256 | Primary (ECC P-256) | ✅ Supported |
| PS256 | PS256 | Secondary (RSA PSS) | ✅ Supported |
| Other | - | - | ❌ Not supported |

### Test Case 5: Key Identifier Validation

**Objective**: Validate key identifier format and trust network lookup.

**Steps**:
1. **Start Test**: Select `tc-key-identifier-validation`
2. **Provide CWT**: Enter CWT with valid key identifier
3. **Validation Process**:
   - Extract Key ID (claim '4') - must be 8 bytes
   - Extract Issuer (claim '1') - must be ISO 3166-1 alpha-2
   - Retrieve public key from trust network
4. **Expected Results**:
   - ✅ Key ID is exactly 8 bytes
   - ✅ Issuer is valid country code (e.g., "DE", "FR", "IT")
   - ✅ Public key successfully retrieved from trust network
   - ✅ Key is onboarded and active

**Valid Country Codes**: DE, FR, IT, ES, NL, BE, PT, AT, FI, SE, etc.

### Test Case 6: Digital Signature Verification

**Objective**: Perform cryptographic signature verification.

**Steps**:
1. **Start Test**: Select `tc-signature-verification`
2. **Provide CWT**: Enter CWT with valid signature
3. **Verification Process**:
   - Extract signature components
   - Retrieve public key from trust network
   - Validate token expiration
   - Perform cryptographic verification
4. **Expected Results**:
   - ✅ Token not expired (current time between issued at and expiration)
   - ✅ Public key retrieved successfully
   - ✅ Signature cryptographically valid
   - ✅ Trust chain validated

### Test Case 7: HCERT Payload Extraction

**Objective**: Extract and validate HCERT payload from verified CWT.

**Steps**:
1. **Start Test**: Select `tc-hcert-payload-extraction`
2. **Provide Verified CWT**: Enter CWT with verified signature
3. **Extraction Process**:
   - Extract payload using claim key -260
   - Validate HCERT structure
   - Analyze certificate types
4. **Expected Results**:
   - ✅ HCERT payload extracted from claim -260
   - ✅ Structure validates against FHIR StructureDefinition
   - ✅ Certificate type identified (EU DCC, DDCC VS, DDCC TR, etc.)

**Supported Certificate Types**:
- **EU DCC** (claim 1): European Digital COVID Certificate
- **DDCC VS** (claim 3): WHO DDCC Vaccination Certificate
- **DDCC TR** (claim 4): WHO DDCC Test Result Certificate
- **Smart Health Link** (claim 5): URI-based health certificate

## Sample Test Data

### Valid HCERT QR Code
```
HC1:NCFOXN%TSMAHN-H+XO5XF7:UY%FJ.FK6ZK7:EDOLOPCO8F6%E5.FK:*P QDHQF67463W5KF6946846G41NKF:QN:96-JN*T1:G1-QN-HKF%6PFQ/TSCZB1KEC0JH%F3*R1YS0JZ9*47+E4F0F6L9HFQE%6I*LG0Z+QN+KN%LO%8M50FLJI%6P9GQHO%F9I1K%P1R2CL%HD-7J/C0*T05THVGK3G-HKPQ1FC
```

### Invalid QR Code (for negative testing)
```
INVALID:NCFOXN%TSMAHN-H+XO5XF7:UY%FJ.FK6ZK7:EDOLOPCO8F6%E5.FK
```

### Sample EU DCC Payload
```json
{
  "1": {
    "v": [{
      "tg": "840539006",
      "vp": "1119349007", 
      "mp": "EU/1/20/1528",
      "ma": "ORG-100030215",
      "dn": 2,
      "sd": 2,
      "dt": "2021-02-18",
      "co": "DE",
      "is": "Robert Koch-Institut",
      "ci": "URN:UVCI:01DE/84503/1119349007/DXSGWLWL40SU8ZFKIYIBK39A3#S"
    }]
  }
}
```

## Troubleshooting

### Common Issues

#### 1. Services Not Ready
**Symptoms**: Test cases fail immediately, connection errors

**Solutions**:
```bash
# Check service status
docker-compose ps

# Restart services
docker-compose restart

# Check logs
docker-compose logs gdhcn-validator
docker-compose logs who-helper-services
```

#### 2. GDHCN Validator Connection Issues
**Symptoms**: Processing operations fail, validator timeouts

**Solutions**:
```bash
# Test validator health
curl http://localhost:8080/actuator/health

# Check validator logs
docker-compose logs gdhcn-validator

# Restart validator
docker-compose restart gdhcn-validator
```

#### 3. Invalid Test Data
**Symptoms**: Validation failures, format errors

**Solutions**:
- Verify QR code format (must start with "HC1:")
- Check for special characters or encoding issues
- Use provided sample data for initial testing
- Validate CWT structure before signature tests

#### 4. Test Case XML Errors
**Symptoms**: Test case fails to load, XML parsing errors

**Solutions**:
- Check XML syntax in test case files
- Validate scriptlet references
- Ensure proper namespace declarations
- Review ITB logs for detailed error messages

### Service Health Monitoring

#### ITB Test Bed Health
```bash
# Check ITB UI accessibility
curl -I http://localhost:10003

# Check API availability  
curl http://localhost:10003/api/rest/info
```

#### GDHCN Validator Health
```bash
# Basic health check
curl http://localhost:8080/actuator/health

# Detailed health information
curl http://localhost:8080/actuator/info
```

#### WHO Helper Services Health
```bash
# Check WSDL availability
curl http://localhost:10005/flint/services/process?wsdl
curl http://localhost:10005/flint/services/validation?wsdl
```

## Advanced Usage

### Automated Test Execution

#### REST API Testing
```bash
# Execute test via REST API
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

#### Batch Test Execution
```bash
#!/bin/bash
# Execute all HCERT test cases

TEST_CASES=(
  "tc-qr-valid-hcert"
  "tc-qr-invalid-hcert"
  "tc-cwt-extraction"
  "tc-signature-algorithm-validation"
  "tc-key-identifier-validation"
  "tc-signature-verification"
  "tc-hcert-payload-extraction"
)

for test_case in "${TEST_CASES[@]}"; do
  echo "Executing $test_case..."
  curl -X POST http://localhost:10003/api/rest/tests/execute \
    -H "Content-Type: application/json" \
    -d "{\"testSuite\":\"ts-hcert-validation\",\"testCase\":\"$test_case\"}"
  echo "Completed $test_case"
done
```

### Custom Test Data

#### Creating Custom HCERT Test Data
1. **Generate Valid HCERT**:
   - Use GDHCN validator tools
   - Follow WHO DDCC specifications
   - Ensure proper digital signatures

2. **Create Invalid Test Cases**:
   - Modify prefix (not "HC1:")
   - Corrupt Base45 encoding
   - Invalid CBOR structure
   - Expired signatures

#### Test Data Management
```bash
# Store test data in organized structure
mkdir -p test-data/{valid,invalid,samples}

# Valid test cases
echo "HC1:VALID_HCERT_DATA..." > test-data/valid/sample-vaccination.txt
echo "HC1:VALID_HCERT_DATA..." > test-data/valid/sample-test-result.txt

# Invalid test cases  
echo "INVALID:BAD_PREFIX..." > test-data/invalid/bad-prefix.txt
echo "HC1:CORRUPTED_DATA..." > test-data/invalid/corrupted-data.txt
```

### Performance Testing

#### Load Testing HCERT Validation
```bash
# Install Apache Bench (if not available)
# sudo apt-get install apache2-utils

# Test validator performance
ab -n 100 -c 10 -p test-data.json -T application/json \
   http://localhost:8080/validate/hcert
```

#### Monitoring Resource Usage
```bash
# Monitor container resource usage
docker stats

# Monitor specific services
docker stats who-itb_gdhcn-validator_1 who-itb_who-helper-services_1
```

### Integration with CI/CD

#### GitHub Actions Example
```yaml
name: HCERT Validation Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2
    
    - name: Start WHO-ITB services
      run: |
        docker-compose up -d
        sleep 30  # Wait for services
        
    - name: Execute HCERT tests
      run: |
        ./deploy-hcert-tests.sh --skip-build
        # Add test execution commands
        
    - name: Collect test results
      run: |
        # Export test reports
        # Archive results
```

### Extending Test Cases

#### Adding New Test Scenarios
1. **Create Test Case XML**:
   ```xml
   <testcase id="tc-custom-validation" xmlns="http://www.gitb.com/tdl/v1/">
     <!-- Test case definition -->
   </testcase>
   ```

2. **Update Test Suite**:
   ```xml
   <testsuite id="ts-hcert-validation">
     <!-- Add new test case reference -->
     <testcase id="tc-custom-validation"/>
   </testsuite>
   ```

3. **Create Supporting Scriptlets**:
   ```xml
   <scriptlet id="customValidation">
     <!-- Custom validation logic -->
   </scriptlet>
   ```

#### Custom Validation Logic
Extend WHO helper services with custom operations:

```java
// Add to ProcessingServiceImpl.java
case "customValidation": return customValidation(processRequest);

private ProcessResponse customValidation(ProcessRequest processRequest) {
    // Custom validation implementation
}
```

This comprehensive guide should enable effective execution and management of HCERT validation test cases within the WHO-ITB environment.
