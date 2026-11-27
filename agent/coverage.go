package agent

import (
	"log/slog"

	"github.com/Autumn-27/artex/db"
)

// sendAuthMaterialOn reports whether this task opted out of the
// authentication-material redaction (#11). It fails closed: a nil store, an
// unknown task or a read error keeps the redaction on.
func sendAuthMaterialOn(as *db.AssetStore, taskID int64) bool {
	if as == nil {
		return false
	}
	send, err := as.SendAuthMaterial(taskID)
	if err != nil {
		slog.Warn("[redact] reading send_auth_material failed; leaving the redaction on", "task_id", taskID, "err", err)
		return false
	}
	return send
}

// coverageOn reports whether asset-coverage tools stay available for this task.
// A nil store is the historical default (enabled). A database error is logged and
// treated as enabled so a transient read failure does not drop the tools mid-run.
func coverageOn(as *db.AssetStore, taskID int64) bool {
	if as == nil {
		return true
	}
	enabled, err := as.CoverageEnabled(taskID)
	if err != nil {
		slog.Warn("[coverage] reading the coverage flag failed; leaving coverage on", "task_id", taskID, "err", err)
		return true
	}
	return enabled
}
