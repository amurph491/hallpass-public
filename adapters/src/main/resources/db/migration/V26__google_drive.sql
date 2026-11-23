-- Google (Drive; Gmail reuses the root). The connection root is one person's Google account under PERSONAL
-- custody: only that human can be the root of authority for anything below it
-- (kernel custody rule). With the drive.file scope, the app can reach
-- only files the user picked (Google Picker) or created with it; picked files
-- are then selectable under the account root.
INSERT INTO resource_kinds (wire, provider, parent_wire, resource_type, custody)
VALUES
  ('google.account', 'google', NULL, 'ACCOUNT', 'PERSONAL'),
  ('google.drive_file', 'google', 'google.account', 'DOCUMENT', NULL);
