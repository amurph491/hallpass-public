-- Gmail send. The mailbox is an explicit,
-- selectable child of the person's google.account root, so it inherits
-- PERSONAL custody and an agent can address exactly one person's mailbox even
-- when several Google accounts are connected in the tenant. Its external ID is
-- the account's stable `sub`.
INSERT INTO resource_kinds (wire, provider, parent_wire, resource_type, custody)
VALUES ('google.mailbox', 'google', 'google.account', 'CHANNEL', NULL);
