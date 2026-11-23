-- Notion. The connection root is the Notion
-- workspace the integration was installed in (Workspace custody); an
-- administrator selects pages under it. Pages are addressed by their Notion
-- UUID. Nested pages are not addressable unless selected themselves.
INSERT INTO resource_kinds (wire, provider, parent_wire, resource_type, custody)
VALUES
  ('notion.workspace', 'notion', NULL, 'ACCOUNT', 'WORKSPACE'),
  ('notion.page', 'notion', 'notion.workspace', 'DOCUMENT', NULL);

-- Notion publishes no access-token lifetime, so a Notion connection stores a
-- bearer credential (with its refresh token, encrypted) rather than
-- the expiring OAUTH_REFRESHABLE shape.
ALTER TABLE credential_references DROP CONSTRAINT credential_references_type_check;
ALTER TABLE credential_references
  ADD CONSTRAINT credential_references_type_check
    CHECK (credential_type IN ('SLACK_OAUTH', 'OAUTH_REFRESHABLE', 'GITHUB_APP_INSTALLATION', 'NOTION_OAUTH'));
