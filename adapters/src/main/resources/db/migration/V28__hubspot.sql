-- HubSpot. The connection root is the HubSpot
-- portal (hub_id, Workspace custody). An administrator selects CRM object
-- types under it (external IDs "contacts", "deals"); records are addressed by
-- argument and authorized at their object type. Field-level limits are
-- valued constraints on the properties an update writes.
INSERT INTO resource_kinds (wire, provider, parent_wire, resource_type, custody)
VALUES
  ('hubspot.portal', 'hubspot', NULL, 'ACCOUNT', 'WORKSPACE'),
  ('hubspot.object_type', 'hubspot', 'hubspot.portal', 'CUSTOM', NULL);
