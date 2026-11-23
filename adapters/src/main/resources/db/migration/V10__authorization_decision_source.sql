ALTER TABLE authorization_requests
  ADD COLUMN authorization_source text;

ALTER TABLE authorization_requests
  ADD CONSTRAINT authorization_requests_source_check
  CHECK (authorization_source IS NULL OR authorization_source IN ('AGENT_CALL', 'HUMAN_PREVIEW'));
