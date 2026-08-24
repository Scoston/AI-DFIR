# Upgrade and Rollback

Before upgrade, export/sign active cases, validate a database restore, record the
current package SHA-256/readiness result, run the new version against synthetic
fixtures, and review schema/Evidence Pack changes.

Never roll back by replacing or deleting immutable evidence. Roll application
code back only when metadata schema compatibility is understood and tested.
