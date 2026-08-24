# Air-Gapped Deployment

1. Build a dependency wheelhouse on an approved connected build host.
2. Transfer it with a signed manifest and verify hashes inside the enclave.
3. Exclude the optional PyMuPDF profile unless AGPL/commercial licensing is approved.
4. Install using `pip --no-index --find-links <wheelhouse>`.
5. Collect external provider evidence with signed collectors and transfer raw
   evidence plus receipts into the enclave.
6. Verify acquisition signatures/hashes after transfer.
7. Import external transparency receipts rather than making analyst hosts contact
   remote transparency services.
