-- An unmapped external tool has no catalog resource or action yet, but its denial still needs durable evidence.
ALTER TABLE authorization_requests
  ALTER COLUMN resource_id DROP NOT NULL,
  ALTER COLUMN action DROP NOT NULL;
