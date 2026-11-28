CREATE TABLE hosts (
    id INTEGER PRIMARY KEY,
    ip TEXT,
    hostname TEXT,
    domain TEXT,
    os TEXT,
    signing_required BOOLEAN,
    channel_binding TEXT
);
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    domain TEXT,
    username TEXT,
    password TEXT,
    credtype TEXT,
    pillaged_from_hostid INTEGER
);
INSERT INTO hosts VALUES (1,'10.20.30.10','DC01','LAB.LOCAL','Windows Server 2022 Build 20348',1,'LDAP');
INSERT INTO users VALUES (1,'LAB.LOCAL','alice','S3cr3t!','plaintext',NULL);
INSERT INTO users VALUES (2,'LAB.LOCAL','bob','S3cr3t!','plaintext',NULL);
