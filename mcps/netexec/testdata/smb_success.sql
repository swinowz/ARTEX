CREATE TABLE hosts (
    id INTEGER PRIMARY KEY,
    ip TEXT,
    hostname TEXT,
    domain TEXT,
    os TEXT,
    dc BOOLEAN,
    smbv1 BOOLEAN,
    signing BOOLEAN
);
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    domain TEXT,
    username TEXT,
    password TEXT,
    credtype TEXT,
    pillaged_from_hostid INTEGER
);
CREATE TABLE groups (
    id INTEGER PRIMARY KEY,
    domain TEXT,
    name TEXT,
    rid TEXT,
    member_count_ad INTEGER
);
CREATE TABLE shares (
    id INTEGER PRIMARY KEY,
    hostid TEXT,
    userid INTEGER,
    name TEXT,
    remark TEXT,
    read BOOLEAN,
    write BOOLEAN,
    type TEXT
);
CREATE TABLE admin_relations (
    id INTEGER PRIMARY KEY,
    userid INTEGER,
    hostid TEXT
);
INSERT INTO hosts VALUES (1,'10.20.30.10','DC01','LAB.LOCAL','Windows Server 2022 Build 20348 x64',1,0,0);
INSERT INTO hosts VALUES (2,'10.20.30.11','WS01','LAB.LOCAL','Windows 10.0 Build 19045 x64',0,0,1);
INSERT INTO users VALUES (1,'LAB.LOCAL','alice','S3cr3t!','plaintext',NULL);
INSERT INTO users VALUES (2,'LAB.LOCAL','bob','S3cr3t!','plaintext',NULL);
INSERT INTO groups VALUES (1,'LAB.LOCAL','Domain Admins','512',3);
INSERT INTO shares VALUES (1,'10.20.30.10',1,'ADMIN$','Remote Admin',1,1,'Disk');
INSERT INTO shares VALUES (2,'10.20.30.10',1,'SYSVOL','Logon server share',1,0,'Disk');
INSERT INTO admin_relations VALUES (1,1,'10.20.30.10');
