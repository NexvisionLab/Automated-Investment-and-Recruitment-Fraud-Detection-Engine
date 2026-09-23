# Security policy

Report suspected vulnerabilities through GitHub's private vulnerability-reporting or Security Advisory feature for this repository. Do not include real credentials, personal information, live malicious links or case evidence in a public issue.

Supported security fixes are issued for the latest checker and dataset research releases. Reports should identify the affected version, file, reproduction steps, impact and a safe proof of concept using reserved domains or synthetic data.

This project must remain offline by default. The only current subprocess boundary is the optional local Tesseract OCR command, invoked without a shell and with a fixed executable plus bounded arguments. Optional direct DNS/TLS and guarded target-page retrieval are user-enabled. Changes that add any other network access, subprocess execution, unsafe deserialisation, external data submission or credential handling require an explicit threat review and new tests before release.
