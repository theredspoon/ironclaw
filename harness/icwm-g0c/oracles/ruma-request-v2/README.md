# Ruma request-shape oracle pin

This isolated build-only crate pins the test oracle used to construct and
review `REQUEST-VECTORS-v2.json`. Its independent workspace keeps the Git
dependency out of the candidate-neutral harness graph and every production
graph.

The manifest selects `ruma-client-api 0.24.0` with `client` and `ruma-common
0.19.0` with `api` and `client` from Ruma commit
`ea3455221fd99985256b196866abb85e22ff4bdd`, with default features disabled.
The checked-in lockfile binds the complete resolved graph.
This crate is oracle evidence, not a candidate implementation and not a
production dependency.
