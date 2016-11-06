CREATE OR REPLACE FUNCTION update_modified_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.modified = now();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TABLE users (
    id serial not null primary key,
    email varchar(100) not null,
    password varchar(100) not null,
    first_name varchar(100),
    last_name varchar(100),
    created timestamp NOT NULL default CURRENT_TIMESTAMP,
    modified timestamp
);

CREATE TRIGGER update_user_modtime BEFORE UPDATE ON users FOR EACH ROW EXECUTE PROCEDURE update_modified_column();

CREATE TABLE authorization_roles (
    id serial not null primary key,
    name varchar(100),
    created timestamp NOT NULL default CURRENT_TIMESTAMP,
    modified timestamp
);

CREATE TRIGGER update_authorization_roles_modtime BEFORE UPDATE ON authorization_roles FOR EACH ROW EXECUTE PROCEDURE update_modified_column();

CREATE TABLE authorization_user_roles (
    id serial not null primary key,
    user_id integer not null references users ON DELETE CASCADE,
    role_id integer not null references authorization_roles ON DELETE CASCADE,
    created timestamp NOT NULL default CURRENT_TIMESTAMP
);
