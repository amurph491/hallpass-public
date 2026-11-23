-- Linear's resource kinds. The connection root is
-- the Linear organization (Workspace custody); administrators select teams
-- under it. The application's operation registry declares the same kinds.
INSERT INTO resource_kinds (wire, provider, parent_wire, resource_type, custody)
VALUES
  ('linear.organization', 'linear', NULL, 'ACCOUNT', 'WORKSPACE'),
  ('linear.team', 'linear', 'linear.organization', 'TEAM', NULL);
