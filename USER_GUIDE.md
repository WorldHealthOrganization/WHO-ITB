# WHO-ITB User Guide

This user guide provides step-by-step instructions for using the WHO Interoperability Test Bed (WHO-ITB) to validate HCERT (Health Certificate) test cases.

## Table of Contents
- [1. Running Docker and Loading the Configuration](#1-running-docker-and-loading-the-configuration)
- [2. Logging In and Changing Your One-Time Password](#2-logging-in-and-changing-your-one-time-password)
- [3. Navigating to Conformance Statements and Starting a Test Session](#3-navigating-to-conformance-statements-and-starting-a-test-session)
- [4. Running the HCERT with VHL Test Case](#4-running-the-hcert-with-vhl-test-case)
- [5. Running the ICVP Test Case](#5-running-the-icvp-test-case)
- [6. Running the Generic QR Code Signature Verification Test Case](#6-running-the-generic-qr-code-signature-verification-test-case)

---

## 1. Running Docker and Loading the Configuration

### Prerequisites
Before you start, ensure you have the following installed on your system:
- **Git** - for cloning the repository
- **Docker** with Docker Compose - for running the services
- **A web browser** - for accessing the web interface
- **Internet connection** - for pulling Docker images

### Step 1.1: Clone the Repository

Open a terminal and run:

```bash
git clone https://github.com/WorldHealthOrganization/WHO-ITB
cd WHO-ITB
```

### Step 1.2: Start the Docker Composition

Run the following command to start all services:

```bash
docker-compose up --build
```

This command will:
- Build the WHO helper services from source
- Pull the GDHCN validator image
- Pull the MatchBox FHIR server image
- Initialize the ITB with pre-configured test suites
- Set up all required services and dependencies

**Expected output**: You should see multiple services starting up. Wait until all services are running.

### Step 1.3: Verify Services are Running

The following services will be started:
- **ITB Test Bed UI** at http://localhost:10003
- **Helper Services** at http://localhost:10005
- **GDHCN Validator** at http://localhost:8080
- **MatchBox FHIR Server** at http://localhost:8089

You can verify that all services are running by executing:

```bash
docker-compose ps
```

All services should show status as "Up".

### Step 1.4: Wait for Services to be Ready

Wait approximately 30-60 seconds for all services to fully initialize. The configuration data will be automatically loaded during startup.

To verify the ITB UI is ready, open your browser and navigate to:

```
http://localhost:10003
```

You should see the WHO-ITB login page.

---

## 2. Logging In and Changing Your One-Time Password

### Step 2.1: Access the Login Page

Open your web browser and navigate to:

```
http://localhost:10003
```

You will see the WHO-ITB login page.

### Step 2.2: Log In with Default Credentials

Use one of the following default user accounts:

| Username              | Password              | Role   |
|-----------------------|-----------------------|--------|
| user@who.itb.test     | change_this_password  | Tester |
| admin@who.itb.test    | change_this_password  | Admin  |

For testing purposes, use:
- **Username**: `user@who.itb.test`
- **Password**: `change_this_password`

Click **"Login"** or press Enter.

### Step 2.3: Change Your One-Time Password

After your first login, you will be prompted to change your password.

1. You will see a **"Change Password"** dialog
2. Enter your current password: `change_this_password`
3. Enter your new password (must meet security requirements)
4. Re-enter your new password to confirm
5. Click **"Change Password"** or **"Submit"**

**Password Requirements**:
- Minimum 8 characters
- Mix of uppercase and lowercase letters recommended
- Include numbers and special characters for better security

After successfully changing your password, you will be logged into the system.

### Step 2.4: Verify Login Success

After changing your password, you should see the WHO-ITB dashboard with:
- Navigation menu on the left
- Welcome message or dashboard overview
- Access to your conformance statements

---

## 3. Navigating to Conformance Statements and Starting a Test Session

### Step 3.1: Navigate to Your Conformance Statements

After logging in, you will see the main dashboard.

1. Look for the **"Conformance Statements"** section or link in the navigation menu
2. Click on **"Conformance Statements"** or **"My Statements"**

You will see a list of conformance statements assigned to your organization.

### Step 3.2: View Available Test Suites

The conformance statements show which test suites are available for your organization. You should see:

- **Generic QR Code Signature Verification**: Upload barcode, decode HC1 and CWT Payload, and verify QR Code signature

- **Track 1: System Utilizes and Validates HCERT: VHL**
  - Description: Validates QR Code, retrieves and validates LACPass RACSEL IPS 0.1.0
  
- **Track 2: System Utilizes and Validates HCERT: ICVP**
  - Description: Validates QR code, retrieves and validates ICVP IPS Bundle

### Step 3.3: Select a Conformance Statement

1. Click on the conformance statement you want to test
2. You will see details about the conformance statement including:
   - Description
   - Test cases included
   - Expected actors
   - Documentation

### Step 3.4: Start a New Test Session

1. Click the **"Test"** or **"Create Test Session"** button
2. Or click on **"Test Sessions"** in the navigation menu
3. Then click **"Create Session"** or **"New Session"**

4. You will be presented with a dialog to configure your test session:
   - **Select Test Suite**: Choose the test suite you want to execute
   - **Session Name** (optional): Give your test session a meaningful name
   - Click **"Start"** or **"Create"**

You are now ready to execute test cases!

---

## 4. Running the HCERT with VHL Test Case

The HCERT with VHL (Verifiable Health Link) test case validates a QR code and retrieves the associated health certificate.

### Step 4.1: Select the VHL Test Case

1. From your test session, select **"Track 1: System Utilizes and Validates HCERT: VHL"**
2. Click **"Start Test"** or **"Execute"**

### Step 4.2: Provide the QR Code Image

The test case will prompt you to provide a QR code image containing an HCERT.

1. You will see a **"QR Code Image"** upload field
2. Click **"Choose File"** or **"Browse"**
3. Select a QR code image file (PNG or JPEG format)
   - Use the sample file: `test-data/1234.png` from the repository if you need test data
4. Click **"Upload"** or the form will auto-submit

**What happens**:
- The system decodes the QR code from the image
- Extracts the HC1: prefixed data
- Decodes the HCERT payload

### Step 4.3: Decode the HCERT

The test will automatically:

1. **Decode the QR Code**: Extract the HC1: string from the image
2. **Base45 Decode**: Decode the Base45-encoded payload
3. **ZLIB Decompress**: Decompress the data
4. **Extract COSE Structure**: Parse the CBOR Web Token (CWT)

You will see the results displayed showing:
- ✅ QR code successfully decoded
- ✅ HCERT structure extracted
- The decoded payload in JSON format

### Step 4.4: Extract Smart Health Link Reference

The test will extract the Smart Health Link (SHLink) reference from the HCERT payload.

**What this step does**:
- Looks for claim key -260 in the CWT payload
- Extracts the HCERT data
- Identifies any Smart Health Link references (claim 5)
- Extracts the VHL URL

You will see:
- ✅ SHLink reference found
- The VHL URL displayed
- Status showing the link is ready for authorization

### Step 4.5: Authorize with PIN

If the Smart Health Link is protected by a PIN, you will be prompted to enter it.

1. You will see a **"PIN"** input field
2. Enter the PIN code (e.g., `1234` for test data)
3. Click **"Authorize"** or **"Submit"**

**What happens**:
- The system attempts to authorize with the VHL server using the PIN
- Retrieves the manifest containing FHIR resource links
- Downloads the encrypted FHIR resources

Results shown:
- ✅ Authorization successful
- Manifest retrieved with resource links
- Number of resources available

### Step 4.6: Retrieve and Validate FHIR Resources

The test will automatically:

1. **Fetch FHIR Resources**: Download the FHIR bundle from the VHL
2. **Decrypt Resources**: Decrypt the encrypted health data
3. **Validate Against Profile**: Validate the IPS bundle against the LACPass RACSEL IPS 0.1.0 profile

You will see validation results:
- ✅ FHIR resources retrieved
- ✅ Bundle validated against profile
- Any validation warnings or errors
- Overall test result: **SUCCESS** or **FAILURE**

### Step 4.7: Review Test Results

1. The test execution screen will show:
   - All test steps completed
   - Validation outcomes for each step
   - Detailed logs
   - Success/failure indicators

2. You can:
   - **View Details**: Click on each step to see detailed logs
   - **Export Report**: Download the test report as PDF or XML
   - **View FHIR Data**: Inspect the retrieved FHIR resources

3. Click **"Finish"** to complete the test session

---

## 5. Running the ICVP Test Case

The ICVP (International Certificate of Vaccination and Prophylaxis) test case validates an ICVP QR code and transforms it into an IPS Bundle.

### Step 5.1: Select the ICVP Test Case

1. From your test session, select **"Track 2: System Utilizes and Validates HCERT: ICVP"**
2. Click **"Start Test"** or **"Execute"**

### Step 5.2: Provide the ICVP QR Code Image

1. You will see a **"QR Code Image"** upload field
2. Click **"Choose File"** or **"Browse"**
3. Select an ICVP QR code image file (PNG or JPEG format)
   - Use the sample file: `test-data/icvp.png` from the repository if you need test data
4. Click **"Upload"** or the form will auto-submit

**What happens**:
- The system decodes the ICVP QR code from the image
- Extracts the HC1: prefixed HCERT data
- Prepares for ICVP-specific processing

### Step 5.3: Decode the ICVP HCERT

The test will automatically decode the ICVP HCERT:

1. **Decode QR Code**: Extract the HC1: string
2. **Base45 Decode**: Decode the payload
3. **ZLIB Decompress**: Decompress the data
4. **Extract CWT**: Parse the CBOR Web Token
5. **Extract ICVP Payload**: Extract the ICVP claim from the HCERT

You will see:
- ✅ QR code decoded successfully
- ✅ ICVP payload extracted
- The ICVP claim data in JSON format showing vaccination information

### Step 5.4: Install Required Implementation Guides

The test will automatically install the required FHIR Implementation Guides into MatchBox:

**Implementation Guides installed**:
- ICVP Implementation Guide
- IPS (International Patient Summary) Implementation Guide
- Required dependencies

You will see:
- ✅ IGs uploaded to MatchBox
- ✅ StructureMaps available
- ✅ Validation profiles loaded

This step may take 30-60 seconds as the IGs are being processed.

### Step 5.5: Transform ICVP to IPS Bundle

The test will execute a FHIR StructureMap transformation:

**Transformation process**:
1. Takes the ICVP claim (vaccination data)
2. Uses the `ICVPClaimtoIPS` StructureMap
3. Transforms to an IPS Bundle conforming to the international standard

You will see:
- ✅ Transformation started
- ✅ StructureMap applied: ICVPClaimtoIPS
- ✅ IPS Bundle created
- The resulting bundle in JSON format

### Step 5.6: Validate the IPS Bundle

The test will validate the transformed IPS Bundle:

**Validation performed**:
1. **Structure Validation**: Ensures the bundle is properly formed
2. **Profile Validation**: Validates against the IPS profile
3. **Resource Validation**: Validates individual resources within the bundle
4. **Reference Validation**: Ensures all references are valid

Results shown:
- ✅ Bundle structure valid
- ✅ Conforms to IPS profile
- ✅ All resources valid
- Any information messages or warnings
- Overall validation result: **SUCCESS** or **FAILURE**

### Step 5.7: Review Validation Results

The validation results will show:

1. **Overall Status**: Pass/Fail indicator
2. **Issues Summary**: Count of errors, warnings, and information messages
3. **Detailed Issues**: Each validation issue with:
   - Severity (error, warning, information)
   - Location in the resource
   - Description of the issue
   - Suggested resolution

### Step 5.8: Review Test Results and Complete

1. Review the complete test execution:
   - All steps completed successfully
   - Validation outcomes
   - Generated IPS Bundle
   - Detailed execution logs

2. Available actions:
   - **View IPS Bundle**: Inspect the transformed bundle
   - **Download Results**: Export as JSON, XML, or PDF
   - **Export Report**: Generate a comprehensive test report
   - **View Logs**: Access detailed execution logs

3. Click **"Finish"** to complete the test session

---

## 6. Running the Generic QR Code Signature Verification Test Case

The Generic QR Code Signature Verification test case validates any HCERT QR code and verifies its cryptographic signature without domain restrictions.

### Step 6.1: Select the Generic QR Code Signature Verification Test Case

1. From your test session, select **"Generic QR Code signature verification test suite"**
2. Click **"Start Test"** or **"Execute"**

### Step 6.2: Provide the QR Code Image

1. You will see a **"QR Code Image"** upload field
2. Click **"Choose File"** or **"Browse"**
3. Select a QR code image file (PNG or JPEG format)
   - Use any HCERT QR code image (VHL, ICVP, or other HCERT formats)
   - Sample files are available in the `test-data/` directory if needed
4. Click **"Upload"** or the form will auto-submit

**What happens**:
- The system decodes the QR code from the image
- Extracts the HC1: prefixed HCERT data
- Prepares for signature verification

### Step 6.3: Decode the QR Code

The test will automatically decode the QR code:

1. **Decode QR Image**: Extract the HC1: string from the image
2. **Base45 Decode**: Decode the HC1 payload
3. **ZLIB Decompress**: Decompress the data
4. **Extract COSE**: Parse the CBOR Object Signing and Encryption structure
5. **Extract CWT Payload**: Extract the CBOR Web Token payload

You will see:
- ✅ QR code decoded successfully
- ✅ HC1 string extracted
- The COSE structure with protected headers
- The CWT payload in JSON format

### Step 6.4: Verify the QR Code Signature

The test will verify the cryptographic signature:

**Verification process**:
1. Extracts the raw COSE signature triplet
2. Attempts to verify using the GDHCN trust network
3. Checks against available trust anchors without domain restrictions
4. Validates the signature cryptographically

**Verification parameters**:
- **Environment**: DEV (development trustlist)
- **Domain**: None (supports any domain)
- **Usage**: DSC (Document Signer Certificate)
- **DID Proof Verification**: Enabled
- **Unverified Trustlist**: Allowed (for testing)

You will see:
- ✅ Signature verification initiated
- ✅ HTTP Status: 200 (if successful)
- ✅ Signature Valid: true/false
- KID (Key Identifier) from header
- KID used for verification
- Number of trust anchor candidates tried
- Detailed verification message

### Step 6.5: Review Verification Results

The verification results will show:

**Successful verification**:
- ✅ COSE signature HTTP response check: PASSED
- ✅ COSE signature validity check: PASSED
- ✅ COSE signature verification successful: PASSED
- Message: "Signature verification PASSED"

**Failed verification** (if signature is invalid):
- ❌ COSE signature validity check: FAILED
- Message: "Signature verification FAILED"
- Additional debug information showing:
  - Available KIDs in the trustlist
  - Candidates tried
  - Reason for failure

### Step 6.6: Complete the Test Session

1. Review the complete test execution:
   - QR code decoding results
   - COSE structure details
   - CWT payload information
   - Signature verification outcome
   - Detailed execution logs

2. Available actions:
   - **View Logs**: Access detailed verification logs
   - **Download Results**: Export as JSON or PDF
   - **Export Report**: Generate a comprehensive test report

3. Click **"Finish"** to complete the test session

**Note**: This test case is generic and works with any HCERT QR code format. It focuses solely on decoding and signature verification without requiring domain-specific validation or transformation.

---

## Additional Tips

### Restarting Services

If you need to restart the services:

```bash
# Stop all services
docker-compose down

# Start services again
docker-compose up --build
```

### Resetting to Clean State

To completely reset and start fresh:

```bash
# Stop and remove all containers, networks, and volumes
docker-compose down -v

# Start from scratch
docker-compose up --build
```

**Warning**: This will delete all test data and sessions.

### Accessing Service Logs

To troubleshoot issues, you can view service logs:

```bash
# View all logs
docker-compose logs

# View specific service logs
docker-compose logs gitb-ui
docker-compose logs gdhcn-validator

# Follow logs in real-time
docker-compose logs -f
```

### Health Checks

Verify service health:

```bash
# Check GDHCN validator
curl http://localhost:8080/actuator/health

# Check MatchBox
curl http://localhost:8089/matchbox/fhir/metadata

# Check all services
docker-compose ps
```

### Common Issues

**Issue**: Services fail to start
- **Solution**: Ensure Docker has enough memory allocated (at least 4GB recommended)
- Check: Docker Desktop → Settings → Resources → Memory

**Issue**: Cannot access http://localhost:10003
- **Solution**: Verify the gitb-ui service is running: `docker-compose ps gitb-ui`
- Check firewall settings allowing localhost connections

**Issue**: Test cases fail with connection errors
- **Solution**: Ensure all services are fully started (wait 1-2 minutes after `docker-compose up`)
- Verify health checks are passing

**Issue**: Forgot new password after changing from default
- **Solution**: Contact your administrator or restart with fresh data using `docker-compose down -v`

---

## Getting Help

For more detailed technical documentation:
- **SOP Documentation**: See `SOP_DOCUMENTATION.md` for best practices on writing tests and conformance statements for SMART Guidelines
- **README**: See `README.md` for architecture and development information
- **ITB Documentation**: https://interoperable-europe.ec.europa.eu/collection/interoperability-test-bed-repository/solution/interoperability-test-bed
- **WHO SMART Trust**: https://smart.who.int/trust

For issues or questions:
- Check the repository issues: https://github.com/WorldHealthOrganization/WHO-ITB/issues
- Review test execution logs for detailed error messages
- Consult the troubleshooting section in `HCERT_TEST_GUIDE.md`
