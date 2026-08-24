# Enterprise deployment profile

The included services are a single-node reference deployment.

Important production requirements outside this reference package:
- enterprise IdP/reverse proxy
- TLS/mTLS termination
- external secrets/HSM/KMS
- externally immutable/WORM repository or object-lock replication
- centralized backup
- database HA for deployments beyond the SQLite reference profile
- SIEM/SOAR delivery credentials and network policy
