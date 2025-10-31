# WHO-ITB with HCERT Validation
This is a shareable, pre-configured instance of the Interoperability Test Bed for WHO GDHCN Trust Network purposes, designed for validating HCERTs (Health Certificates) using VHL and ICVP test cases.

<img width="1143" height="537" alt="{7DBF0C14-EB8D-42D5-9E03-D7452FDA25DF}" src="https://github.com/user-attachments/assets/89d7ce20-80a7-4d2d-a15c-7a5bd2a8934d" />


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
+ A running, pre-configured Interoperability Test Bed instance (GITB) with all required containers;
+ GDHCN helper service for HCERT decoding and SMART Health Link processing;
+ SMART helper service for FHIR transformation and validation;
+ MatchBox FHIR validation server;
+ HAPI FHIR server;
+ An initial configuration with communities, organizations, users and admins;
+ Test suites for HCERT validation:
    + VHL (Verifiable Health Link) test suite
    + ICVP (International Certificate of Vaccination and Prophylaxis) test suite
    
## Prerequisites
### Prerequisites for running
- Git
- Docker with compose
- A browser
- Internet connection (for pulling Docker images)

### Prerequisites for development and testing
- Basic knowledge of ITB test case development

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/WorldHealthOrganization/WHO-ITB
   cd WHO-ITB
   ```

2. Start the composition with Docker on your local machine:
   ```bash 
   docker-compose up --build
   ```
   This will start the following services (accessible from your host machine):
   - ITB Test Bed UI at http://localhost:10003
   - HCERT Validator (GDHCN helper) at http://localhost:8089
   - FHIR Server (HAPI) at http://localhost:8080
   - MatchBox at http://localhost:8087
   - SMART Helper at http://localhost:8000

3. Go to http://localhost:10003 in your browser.

4. Log in with a predefined user (see Users section below).

5. If you ever want to drop the instance and start up from scratch again, then just remove the composition together with the volumes and start from point 2:
   ```bash
   docker compose down -v
   ```

## HCERT Test Cases

This repository includes test suites for HCERT (Health Certificate) validation covering two main scenarios:

### Test Suite 1: VHL (Verifiable Health Link)
**Test Case**: Track 1 - System Utilizes and Validates HCERT: VHL

This test validates:
1. **QR Code Decoding**: Decode QR code image to HC1 string
2. **HCERT Decoding**: Base45 decode, ZLIB decompress, and extract COSE/CWT structure
3. **Smart Health Link Extraction**: Extract SHLink reference from the HCERT payload
4. **Authorization**: Authorize with PIN to access the manifest
5. **FHIR Resource Retrieval**: Fetch and decrypt FHIR resources from the VHL
6. **Validation**: Validate the retrieved IPS bundle against the LACPass RACSEL IPS 0.1.0 profile

### Test Suite 2: ICVP (International Certificate of Vaccination and Prophylaxis)
**Test Case**: Track 2 - System Utilizes and Validates HCERT: ICVP

This test validates:
1. **QR Code Decoding**: Decode ICVP QR code image to HC1 string
2. **HCERT Decoding**: Base45 decode, ZLIB decompress, and extract ICVP payload from CWT
3. **Implementation Guide Installation**: Upload required IGs to MatchBox
4. **FHIR Transformation**: Transform ICVP claim to IPS Bundle using StructureMap
5. **Validation**: Validate the transformed IPS Bundle against the IPS profile

For detailed test execution instructions, see the **[User Guide](USER_GUIDE.md)**.

## Building and Deployment

### Standard Deployment
For regular use, follow the installation steps above. The system will automatically:
1. Build the GDHCN helper service (Python-based HCERT decoder) from source
2. Build the SMART helper service (Python-based FHIR transformer) from source
3. Pull the MatchBox FHIR validation server image
4. Pull the HAPI FHIR server image
5. Initialize the ITB with pre-configured test suites
6. Set up all required services and dependencies

### Resetting the Environment
To completely reset and start fresh:

```bash
# Stop and remove all containers, networks, and volumes
docker-compose down -v

# Start from scratch
docker-compose up --build
```

**Warning**: This will delete all test data and sessions.

## Running Test Cases

### Prerequisites for Test Execution
1. Ensure all services are running:
   ```bash
   docker-compose ps
   # Should show all services as "Up"
   ```

2. Verify service health:
   ```bash
   # Check HCERT validator (GDHCN helper)
   curl http://localhost:8089/health
   
   # Check FHIR server
   curl http://localhost:8080/fhir/metadata
   
   # Check MatchBox
   curl http://localhost:8087/fhir/metadata
   
   # Check SMART helper
   curl http://localhost:8000/health
   ```

### Executing Test Cases

1. **Access ITB UI**: http://localhost:10003

2. **Login** with test user:
   - Username: `user@who.itb.test`
   - Password: `change_this_password` (change on first login)

3. **Navigate to Test Sessions**:
   - Go to "Conformance Statements" or "Test Sessions" menu
   - You will see available test suites

4. **Run VHL Test Case**:
   - Select "Track 1: System Utilizes and Validates HCERT: VHL"
   - Click "Test" or "Create Test Session"
   - Upload a QR code image containing an HCERT with VHL reference
   - Provide PIN when prompted (e.g., `1234` for test data)
   - Review the validation results

5. **Run ICVP Test Case**:
   - Select "Track 2: System Utilizes and Validates HCERT: ICVP"
   - Click "Test" or "Create Test Session"
   - Upload an ICVP QR code image
   - Wait for IG installation and transformation (may take 30-60 seconds)
   - Review the validation results

For detailed step-by-step instructions, see the **[User Guide](USER_GUIDE.md)**.

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
│   ITB Test Bed  │  │  GDHCN Helper    │  │  SMART Helper   │
│   (port 10003)  │◄─┤  (port 8089)     │  │  (port 8000)    │
│                 │  │  HCERT Decoder   │  │  FHIR Transform │
└─────────────────┘  └──────────────────┘  └─────────────────┘
         │                       │                    │
         │                       │                    ▼
         │                       │          ┌─────────────────┐
         │                       │          │  MatchBox       │
         │                       │          │  (port 8087)    │
         │                       │          │  FHIR Validator │
         │                       │          └─────────────────┘
         │                       │                    │
         ▼                       ▼                    ▼
┌─────────────────────────────────────────────────────────────┐
│                    HAPI FHIR Server (port 8080)             │
│                    FHIR Resource Storage                    │
└─────────────────────────────────────────────────────────────┘
```

### Service Integration
- **ITB Test Bed**: Orchestrates test execution and provides UI
- **GDHCN Helper**: Python-based service for HCERT decoding and SMART Health Link processing
- **SMART Helper**: Python-based service for FHIR transformation using StructureMaps
- **MatchBox**: FHIR validation server with IG support
- **HAPI FHIR Server**: General-purpose FHIR server for resource storage
- **Test Cases**: XML-based test definitions following GITB TDL specifications

### Data Flow

#### VHL Test Flow
1. **QR Code Upload**: User uploads QR code image via ITB UI
2. **HCERT Decoding**: GDHCN helper decodes HC1 string to COSE/CWT structure
3. **SHLink Extraction**: Extract Smart Health Link reference from payload
4. **Authorization**: User provides PIN to authorize VHL access
5. **FHIR Retrieval**: GDHCN helper fetches encrypted FHIR resources
6. **Validation**: SMART helper validates retrieved IPS bundle
7. **Report Generation**: ITB generates comprehensive test report

#### ICVP Test Flow
1. **QR Code Upload**: User uploads ICVP QR code image via ITB UI
2. **HCERT Decoding**: GDHCN helper decodes HC1 string and extracts ICVP claim
3. **IG Installation**: SMART helper uploads required IGs to MatchBox
4. **Transformation**: SMART helper transforms ICVP claim to IPS Bundle via StructureMap
5. **Validation**: MatchBox validates the transformed bundle against IPS profile
6. **Report Generation**: ITB generates comprehensive test report

## Configuration Management

### Environment Variables
Key configuration parameters in `docker-compose.override.yml`:

```yaml
services:
  hcert-validator:
    ports:
      - "8089:8080"  # External port 8089 maps to internal container port 8080
    environment:
      - PYTHONUNBUFFERED=1

  fhir-server:
    ports:
      - "8080:8080"
    environment:
      - hapi.fhir.cr.enabled=true

  matchbox:
    ports:
      - "8087:8080"

  smart-helper:
    ports:
      - "8000:8000"
    environment:
      - FHIR_HOST=http://fhir-server:8080/fhir  # Internal Docker network address
      - MATCHBOX_HOST=http://matchbox:8080/matchboxv3/fhir  # Internal Docker network address
```

**Note**: The environment variables use internal Docker network addresses (e.g., `http://fhir-server:8080`). These are different from the external host access URLs (e.g., `http://localhost:8080`).

### Domain Configuration
The ITB is configured with HCERT-specific domain settings:
- **Domain**: WHO HCERT Validation
- **Test Suites**: VHL and ICVP validation
- **Test Data**: Pre-loaded sample data in `test-data/` directory

## Troubleshooting

### Common Issues

1. **Services Not Starting**:
   ```bash
   # Check service status
   docker-compose ps
   
   # Check logs
   docker-compose logs hcert-validator
   docker-compose logs smart-helper
   docker-compose logs fhir-server
   docker-compose logs matchbox
   ```

2. **HCERT Validator Connection Issues**:
   ```bash
   # Test validator connectivity
   curl http://localhost:8089/health
   
   # Check network connectivity
   docker network ls
   docker network inspect who-itb_default
   ```

3. **FHIR Server Issues**:
   ```bash
   # Test FHIR server
   curl http://localhost:8080/fhir/metadata
   
   # Test MatchBox
   curl http://localhost:8087/fhir/metadata
   
   # Test SMART helper
   curl http://localhost:8000/health
   ```

4. **Test Execution Failures**:
   - Check test case XML syntax in `testsuites/` directory
   - Verify all services are running and healthy
   - Review service logs for error messages
   - Ensure test data files exist in `test-data/` directory

### Performance Optimization
- Increase Docker memory allocation for large test suites (recommended: 4GB+)
- Wait for all services to fully initialize before running tests
- MatchBox IG installation may take 30-60 seconds on first run

## Security Considerations
- Default passwords must be changed immediately
- Consider running on isolated networks for production testing
- Implement proper certificate management for mTLS connections
- Regular security updates for all container images

# Links and further reading
This testing composition uses the Interoperability Test Bed as the main tool of orchestrating and reporting test-cases. See further resources on it below.

## Documentation
- **[User Guide](USER_GUIDE.md)**: Step-by-step guide for running tests and using the system

## Introduction to the ITB
https://interoperable-europe.ec.europa.eu/collection/interoperability-test-bed-repository/solution/interoperability-test-bed

## WHO SMART Trust Documentation
https://smart.who.int/trust

## GDHCN Specifications
https://smart.who.int/trust/concepts.html
