package db

import (
	"fmt"
	"strings"
	"time"
)

// FindingCommandEvidence is captured command/tool output bound to a finding as
// non-HTTP proof (ADR-0004, #8). Content is stored already capped by the caller;
// Truncated records that a cut happened, so verification can fail closed on a miss.
type FindingCommandEvidence struct {
	ID        int64     `json:"id,string"`
	FindingID int64     `json:"finding_id,string"`
	Role      string    `json:"role"`
	Command   string    `json:"command"`
	Content   string    `json:"content"`
	Truncated bool      `json:"truncated"`
	Position  int       `json:"position"`
	CreatedAt time.Time `json:"created_at"`
}

// ValidCommandEvidenceRole mirrors ValidTrafficRole: the same four roles so the
// verification path treats proof/verification identically across evidence kinds.
func ValidCommandEvidenceRole(role string) bool {
	return role == "baseline" || role == "proof" || role == "verification" || role == "supporting"
}

// AddFindingCommandEvidence stores one captured command output bound to a finding.
// role defaults to "supporting" when empty. The position is the next slot for the
// finding, so List returns insertion order.
func (d *DB) AddFindingCommandEvidence(findingID int64, role, command, content string, truncated bool) (int64, error) {
	role = strings.TrimSpace(role)
	if role == "" {
		role = "supporting"
	}
	if !ValidCommandEvidenceRole(role) {
		return 0, fmt.Errorf("invalid command evidence role %q", role)
	}
	var id int64
	err := d.QueryRow(
		`INSERT INTO finding_command_evidence (finding_id, role, command, content, truncated, position)
		 VALUES ($1, $2, $3, $4, $5, COALESCE((SELECT MAX(position)+1 FROM finding_command_evidence WHERE finding_id=$1), 0))
		 RETURNING id`,
		findingID, role, command, content, truncated,
	).Scan(&id)
	return id, err
}

// ListFindingCommandEvidence returns a finding's command evidence in insertion order.
func (d *DB) ListFindingCommandEvidence(findingID int64) ([]FindingCommandEvidence, error) {
	rows, err := d.Query(
		`SELECT id, finding_id, role, command, content, truncated, position, created_at
		 FROM finding_command_evidence WHERE finding_id=$1 ORDER BY position, id`,
		findingID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FindingCommandEvidence
	for rows.Next() {
		var e FindingCommandEvidence
		if err := rows.Scan(&e.ID, &e.FindingID, &e.Role, &e.Command, &e.Content, &e.Truncated, &e.Position, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
