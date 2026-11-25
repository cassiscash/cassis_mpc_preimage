# cassis_mpc_preimage

Prototype library for a simple, fast two-party MPC protocol that lets two parties jointly generate SHA-256 hashes without either of them knowing the preimage.

Each party contributes a random 32-byte share; the preimage is the XOR of the two shares, and the hash is computed with garbled circuits (mpz half-gates) plus dual execution, so a malicious party cannot make the other accept a wrong hash. Hashes can be pregenerated in batches and the preimage revealed later by having both parties publish their shares.

This is intended to power less-trusted Cassis preimage servers, which, in combination with a gateway server, allow payments to be received offline, noncustodially, and without any interaction from the payee (besides a one-time authorization/delegation step).

This library was not reviewed by a competent cryptographer.
