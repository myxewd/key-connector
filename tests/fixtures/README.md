# Test fixtures

`test_priv.pem` and `test_pub.pem` are a throwaway RSA keypair used only by
`src/tests.rs` (which is compiled under `#[cfg(test)]`) to sign and verify JWTs in
tests. They are never compiled into the release binary and are not used by the
running service.

Do not replace them with a real identity provider key, and do not reuse them
anywhere outside the test suite.
