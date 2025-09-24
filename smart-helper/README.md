# ICVP → IPS End-to-End Test Flow

This is a small helper app that supports processing an **ICVP barcode image** into an **IPS Bundle** using the following pipeline:

1. Upload and decode a **barcode image** into a QR HC1 string.
2. Decode the **HC1 payload** into COSE / payload / hcert JSON.
3. Install required **Implementation Guides (IGs)** into Matchbox via the SMART Helper.
4. Run a **FHIR StructureMap $transform** (ICVPClaimtoIPS) to produce an IPS Bundle.
5. **Validate** the resulting Bundle against the official IPS profile.

---

## API Endpoints

| Component      | Endpoint                              | Method | Description                                                                 |
|----------------|---------------------------------------|--------|-----------------------------------------------------------------------------|
| HCert Decoder  | `/decode/image`                       | POST   | Accepts a PNG/JPG QR code as multipart and returns decoded `qr_data`.       |
| HCert Decoder  | `/decode/hcert`                       | POST   | Accepts JSON `{"qr_data":"HC1:..."}` and returns decoded COSE/payload/hcert.|
| SMART Helper   | `/upload_ig/matchbox`                 | POST   | Uploads an IG to Matchbox. Body: `{"ig_url":"<url>"}`.                      |
| SMART Helper   | `/upload_ig/matchbox?ig_url=<url>`    | POST   | Alternate form with query param instead of JSON body.                       |
| SMART Helper   | `/transform?source=<StructureMap URL>`| POST   | Runs a StructureMap transform. Body: FHIR JSON resource (inner content).    |
| SMART Helper   | `/validate`                           | POST   | Validates a FHIR resource against a profile. Body: `{resource, profile_url}`|
| FHIR Server    | `/<Resource>/$validate`               | POST   | Standard FHIR validation against a profile.                                 |
| SMART Helper   | `/echo`                               | POST   | Debug helper: echoes back body + headers and logs them to console.          |

---

## Sequence Flow

Below is the sequence of interactions as a UML diagram, rendered live via PlantUML:

![Sequence Diagram](https://img.plantuml.biz/plantuml/svg/tLRjRjis5FrlmEzmuRM3YrfcaW4T8CH94oUDNInD5Zd1WBe8Q9csk4YaIb9st21_zm1xn3t9Bad97qcQfNy76B0-Bg_EFUVSIxxNXYfJP6czPhX96VIxL-SGx47_F08cne6H0Vv1ipyuXBSGdHvS3A37qfmfl3sb9av6yXOlF_Jw5s_gjNgDnaOgkDHCrMivvkOnpwamqB0P1amRw5BD6a0ru9C7CRtkCUO_Oh4SCpKKpIHcoWGpcl8nnRHlt38Nz63XEZ0N5FKUH5HOtTlJmpyUlBRu8M9gLgwtzxQSJWSkyrJICV2CJXdy36E73en48DlGwTHhjbZ7sU0mhA97LBamlwfv_kc4V3m_GOOi3HZhYWZX_2mQ0F4fYOiTYgn83RVWo4IgBC3AQUZpT7OdF6LxGt4Gnomt8T0yJtbC3PU2_AcbgDSyWnMOdQqjk8F6LtLjipH2o_1ss6wt6t1lgnFIC51ycXYG4w_7yQrHg26KQs2YP0OVexDFzLgJb0-n36iAkxhao4lc645YkcVHCSdfmZ91d8QEfsTATq53qPN2C662mI9dZwiRYaCvNeHmjofeMS_zZv8IIyrQK89iWKVvNwIKuK2nUYu4oXvxnA6ratz7WfrtMoHu1__yzRSFAgk2fgNnCNTzWKsOfj0_qI35ggbcd6usdELmgcIHOoZyjEtpmGWvMVagwbNC5iw8rtnAiZBZo_dbq-j2fKXlOaokGq961K_7xKd2LLkgAS6ao9-XXl5RnXKbEaE_1aOLsWHvCYSDP3BgMK3OQY4SoRdmJJH5NyGtwEMscNuR2fCmuV5sqGRHGXkM8MzND2rOn0nUHfWqDeLYHsp21RTWyIaMOiK-fVbw2DxMQ_X122ecc0eKqx9GCKhAT2w5Pjf3sxI3BZ8iOT6oKTX_-lCNQmPKoegq8dq7cbyBfXRe14Mpbz6-xzdiE2vV_tBmUkS3_kPIfUE4qTGao2WL_9iJeZtb9Yb6RIunnhFAurcEDoD5HPmmZPSAQRYX_oU6iGq6M9-s4s-pirmRB7l2ji0J_Mbz2vq7tQRe7CgE-xxlhQNV-YdnknKs15-BKmkDxoHepnFPvi8GAmLP9uFO_RARKfuPYLlcUcy_SeQf2jmlFx6xdWakBtxRUwv3bqYhDjtTADTMkhTX2V_L3RIlNeJ1iOb1Swh638UT3hZULDqgkkkspCD2Z75BMiwsnxhBcn3m6wmI7e6NYrg0azlFNDJ_ok_op1qzVCHtvRRJo0q-dBjtzHeqAWisrhBRvxcITilqqmmQfQX9-giROvPIKim8ppLveWk8pnGKim0Z6lNQ_RFwbiSKzk8nMu76RMW5SpauBRrLwbTLxlqoihDhMIflVj0s9J_rcXDmNT8pt6NSghF2n3B3SmlNkc3wILsHYLnYKxJ0RWI5Rg7IBV0BFdz1jR7zAcsFf62h8m3ciKUc4A94pc5fIJn5bcKY0f0UWatm7Z_bZgZ_0W00)

---

