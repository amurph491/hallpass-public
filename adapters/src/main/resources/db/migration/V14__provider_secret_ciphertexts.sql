-- Provider credentials under envelope encryption.
--
-- Each secret is encrypted locally with its own random AES-256-GCM data key.
-- The data key is stored only wrapped by the key-encryption service (Vault
-- Transit today), whose key never leaves that service. Neither the plaintext
-- secret nor the plaintext data key is ever stored.
--
-- The ciphertext's associated data binds it to (tenant, connection,
-- reference), and the data key is wrapped under a per-tenant derived key, so
-- a row copied to another tenant or connection cannot be decrypted there.
--
-- The row is written before the connection that uses it (the connection is
-- created only after the secret is safely stored), so connection_id is not a
-- foreign key; credential_references links the connection to this row.
CREATE TABLE provider_secrets (
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  reference text NOT NULL CHECK (reference ~ '^sec_[A-Za-z0-9_-]{22,128}$'),
  connection_id uuid NOT NULL,
  key_name text NOT NULL CHECK (char_length(key_name) BETWEEN 1 AND 300),
  wrapped_key text NOT NULL CHECK (char_length(wrapped_key) BETWEEN 1 AND 4096),
  nonce bytea NOT NULL CHECK (octet_length(nonce) = 12),
  ciphertext bytea NOT NULL CHECK (octet_length(ciphertext) BETWEEN 17 AND 65552),
  created_at timestamptz NOT NULL DEFAULT now(),
  rewrapped_at timestamptz,
  PRIMARY KEY (tenant_id, reference)
);

ALTER TABLE provider_secrets ENABLE ROW LEVEL SECURITY;
ALTER TABLE provider_secrets FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON provider_secrets
  USING (tenant_id = nullif(current_setting('authai.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = nullif(current_setting('authai.tenant_id', true), '')::uuid);
