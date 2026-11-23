-- A capability key (namespace || '.' || name, for example Slack.Message.Read) is
-- the kernel's capability identity. Two capabilities with the same resource and
-- action are distinct authority when their keys differ, so every catalog row must
-- carry the action and resource the kernel evaluates and a key it can parse. The
-- pattern mirrors CapabilityKey.parse: three to six segments, each an upper-case
-- letter followed by at most 63 letters or digits.
ALTER TABLE capabilities
  ALTER COLUMN action SET NOT NULL,
  ALTER COLUMN resource_id SET NOT NULL,
  ADD CONSTRAINT capabilities_key_format CHECK (
    char_length(namespace || '.' || name) <= 200
    AND (namespace || '.' || name) ~ '^[A-Z][A-Za-z0-9]{0,63}(\.[A-Z][A-Za-z0-9]{0,63}){2,5}$'
  );
