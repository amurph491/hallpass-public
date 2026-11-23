-- psql inherits this value from the official PostgreSQL entrypoint.
-- Keep it out of command arguments and SQL files distributed to participants.
\getenv hallpass_app_password POSTGRES_PASSWORD

-- Keep the bootstrap superuser separate from Hallpass's runtime/migration role.
CREATE ROLE hallpass
  LOGIN
  PASSWORD :'hallpass_app_password'
  NOSUPERUSER
  NOCREATEDB
  NOCREATEROLE
  NOREPLICATION;

GRANT CONNECT ON DATABASE :"DBNAME" TO hallpass;
GRANT USAGE, CREATE ON SCHEMA public TO hallpass;
