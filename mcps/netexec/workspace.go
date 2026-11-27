package netexec

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	_ "modernc.org/sqlite"
)

// workspace is what NetExec persisted in its per-run database, read back only
// to structure the result. The directory is removed right after, because the
// same database holds the credential.
type workspace struct {
	Hosts  []Host
	Shares []Share
	Groups []Object
	Users  []Object
	Access []Access
}

// readWorkspace opens the per-run sqlite workspace read-only. A missing file or
// an unexpected schema is an error: the caller reports it as a failed check
// instead of pretending the enumeration produced nothing.
func readWorkspace(workDir, protocol string) (workspace, error) {
	path := filepath.Join(workDir, "nxc", "workspaces", "default", protocol+".db")
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro&_pragma=busy_timeout(2000)")
	if err != nil {
		return workspace{}, err
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		return workspace{}, fmt.Errorf("workspace database unavailable: %w", err)
	}

	hostCols := []string{"id", "ip", "hostname", "domain", "os"}
	signingCol := "signing"
	if protocol == "ldap" {
		signingCol = "signing_required"
	}
	if err := requireColumns(db, "hosts", append(hostCols, signingCol)...); err != nil {
		return workspace{}, err
	}

	ws := workspace{}
	hostByKey := map[string]string{}
	rows, err := db.Query(`SELECT id, ip, hostname, domain, os, ` + signingCol + ` FROM hosts`)
	if err != nil {
		return workspace{}, err
	}
	for rows.Next() {
		var (
			id              int64
			ip, host, dom   sql.NullString
			osName          sql.NullString
			signingRequired sql.NullBool
		)
		if err := rows.Scan(&id, &ip, &host, &dom, &osName, &signingRequired); err != nil {
			rows.Close()
			return workspace{}, err
		}
		h := Host{Target: ip.String, Hostname: host.String, Domain: dom.String, OS: osName.String}
		if signingRequired.Valid {
			v := signingRequired.Bool
			if protocol == "ldap" {
				v = !v // columns differ in sense; keep the SMB meaning in the result
			}
			h.Signing = &v
		}
		ws.Hosts = append(ws.Hosts, h)
		key := strconv.FormatInt(id, 10)
		hostByKey[key] = ip.String
		hostByKey[ip.String] = ip.String
		hostByKey[host.String] = ip.String
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return workspace{}, err
	}

	if protocol == "smb" {
		if err := requireColumns(db, "shares", "hostid", "name", "remark", "read", "write", "type"); err != nil {
			return workspace{}, err
		}
		srows, err := db.Query(`SELECT hostid, name, remark, read, write, type FROM shares`)
		if err != nil {
			return workspace{}, err
		}
		for srows.Next() {
			var hostID sql.NullString
			var name, remark, kind sql.NullString
			var read, write sql.NullBool
			if err := srows.Scan(&hostID, &name, &remark, &read, &write, &kind); err != nil {
				srows.Close()
				return workspace{}, err
			}
			ws.Shares = append(ws.Shares, Share{
				Host:   resolveHost(hostByKey, hostID.String),
				Name:   name.String,
				Remark: remark.String,
				Type:   kind.String,
				Read:   read.Bool,
				Write:  write.Bool,
			})
		}
		srows.Close()

		if hasColumns(db, "admin_relations", "userid", "hostid") && hasColumns(db, "users", "id", "username") {
			arows, err := db.Query(`SELECT COALESCE(u.username,''), COALESCE(u.domain,''), COALESCE(a.hostid,'')
				FROM admin_relations a LEFT JOIN users u ON u.id = a.userid`)
			if err == nil {
				for arows.Next() {
					var user, domain, hostID sql.NullString
					if err := arows.Scan(&user, &domain, &hostID); err != nil {
						break
					}
					detail := strings.TrimSpace(domain.String + `\` + user.String)
					ws.Access = append(ws.Access, Access{
						Host:   resolveHost(hostByKey, hostID.String),
						Kind:   "admin",
						Detail: detail,
					})
				}
				arows.Close()
			}
		}
	}

	if hasColumns(db, "users", "domain", "username") {
		urows, err := db.Query(`SELECT COALESCE(domain,''), COALESCE(username,'') FROM users`)
		if err == nil {
			for urows.Next() {
				var domain, name sql.NullString
				if err := urows.Scan(&domain, &name); err != nil {
					break
				}
				if name.String != "" {
					ws.Users = append(ws.Users, Object{Name: name.String, Domain: domain.String})
				}
			}
			urows.Close()
		}
	}
	if hasColumns(db, "groups", "domain", "name") {
		grows, err := db.Query(`SELECT COALESCE(domain,''), COALESCE(name,'') FROM groups`)
		if err == nil {
			for grows.Next() {
				var domain, name sql.NullString
				if err := grows.Scan(&domain, &name); err != nil {
					break
				}
				if name.String != "" {
					ws.Groups = append(ws.Groups, Object{Name: name.String, Domain: domain.String})
				}
			}
			grows.Close()
		}
	}
	return ws, nil
}

func resolveHost(byKey map[string]string, hostID string) string {
	if v, ok := byKey[hostID]; ok {
		return v
	}
	return hostID
}

// requireColumns fails when a table we rely on does not exist or changed shape.
func requireColumns(db *sql.DB, table string, cols ...string) error {
	have, err := columns(db, table)
	if err != nil {
		return err
	}
	for _, c := range cols {
		if !have[c] {
			return fmt.Errorf("workspace schema changed: table %s has no column %s", table, c)
		}
	}
	return nil
}

func hasColumns(db *sql.DB, table string, cols ...string) bool {
	have, err := columns(db, table)
	if err != nil {
		return false
	}
	for _, c := range cols {
		if !have[c] {
			return false
		}
	}
	return true
}

func columns(db *sql.DB, table string) (map[string]bool, error) {
	rows, err := db.Query(`PRAGMA table_info(` + table + `)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var (
			cid     int
			name    string
			ctype   string
			notnull int
			dflt    sql.NullString
			pk      int
		)
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return nil, err
		}
		out[name] = true
	}
	return out, rows.Err()
}
