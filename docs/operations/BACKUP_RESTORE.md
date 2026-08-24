# Backup & Restore Validation

A backup is not validated until restored and hash-checked.

1. Create signed backup manifest.
2. Copy database/object-store backup to an isolated recovery environment.
3. Restore metadata and evidence.
4. Run `dr_integrity_v15.py` validation.
5. Verify random evidence extraction/decryption with authorized test keys.
6. Record `validated_utc`, RPO/RTO results and unresolved gaps.
7. Feed DR validation into production readiness.
