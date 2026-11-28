package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/db"
)

// cloneTask starts a fresh task from the stored configuration of a terminal task.
// The new exploration is created normally, so it receives a clean graph; only the
// task's configuration and declared scope are copied.
func (s *Server) cloneTask(w http.ResponseWriter, r *http.Request) {
	origin, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	if !s.engine.beginTaskOperation(origin.ID) {
		writeErr(w, http.StatusConflict, "task is being deleted; cannot clone")
		return
	}
	defer s.engine.decInflight(origin.ID)
	if !isTerminalStatus(origin.lifecycleSnapshot().Status) {
		writeErr(w, http.StatusConflict, "only terminated tasks can be cloned")
		return
	}
	categoryID := origin.CategoryID
	rotate := origin.LLMRotate
	quiet := origin.PlanQuietMode
	coverage := origin.CoverageEnabled
	gate := origin.targetGate.Load()
	originID, _ := strconv.ParseInt(origin.ID, 10, 64)
	var interceptRules []db.TaskInterceptRuleInput
	if assets := s.m.Assets(); assets != nil {
		rules, err := assets.ListTaskInterceptRules(originID)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, fmt.Sprintf("read task interception rules: %v", err))
			return
		}
		for _, rule := range rules {
			interceptRules = append(interceptRules, db.TaskInterceptRuleInput{Enabled: rule.Enabled, Action: rule.Action, Kind: rule.Kind, Pattern: rule.Pattern, Note: rule.Note})
		}
	}
	credentials, err := s.m.PG().TaskCredentials(originID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, fmt.Sprintf("read task credentials: %v", err))
		return
	}
	cloned, err := s.m.CreateTaskWithOptions(origin.Description, origin.Goal, db.TaskCreateOptions{
		Name: origin.Name, CategoryID: categoryID, ParentRef: origin.ID,
		SourceTaskIDs: append([]int64(nil), origin.SourceTaskIDs...), CompanyIDs: append([]int64(nil), origin.CompanyIDs...),
		LLMProfileIDs: append([]int64(nil), origin.LLMProfileIDs...), TimeoutSeconds: origin.TimeoutSeconds,
		PlanHeartbeatSeconds: origin.PlanHeartbeatSeconds, PlanQuietMode: &quiet, CoverageEnabled: &coverage,
		InterceptRules: interceptRules, LLMRotate: &rotate, TargetGate: &gate,
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	cloneID, _ := strconv.ParseInt(cloned.ID, 10, 64)
	if assets := s.m.Assets(); assets != nil {
		if err := assets.CloneTaskScope(originID, cloneID); err != nil {
			writeErr(w, http.StatusInternalServerError, fmt.Sprintf("copy task scope: %v", err))
			return
		}
	}
	for _, credential := range credentials {
		if _, err := s.m.PG().UpsertTaskCredential(cloneID, db.TaskCredentialInput{
			Domain: credential.Domain, Username: credential.Username, Password: credential.Password,
			Source: credential.Source, Note: credential.Note,
		}); err != nil {
			writeErr(w, http.StatusInternalServerError, fmt.Sprintf("copy task credential: %v", err))
			return
		}
	}
	goals, err := origin.Store.ListByKind(db.KindGoal, 10000)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, fmt.Sprintf("read origin goals: %v", err))
		return
	}
	for _, goal := range goals {
		var payload struct {
			Text      string `json:"text"`
			VulnClass string `json:"vulnclass"`
		}
		if err := json.Unmarshal(goal.Payload, &payload); err != nil || strings.TrimSpace(payload.Text) == "" {
			continue
		}
		newID, err := cloned.Store.AddNode(db.KindGoal, map[string]any{"text": payload.Text, "vulnclass": payload.VulnClass}, goal.Priority, "open", "clone", nil)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, fmt.Sprintf("copy origin goal: %v", err))
			return
		}
		if root, _ := cloned.Store.OriginFactID(); root > 0 {
			if err := cloned.Store.Link(root, db.RelSpawns, newID); err != nil {
				writeErr(w, http.StatusInternalServerError, fmt.Sprintf("link cloned goal: %v", err))
				return
			}
		}
	}
	s.launchTask(cloned, origin.Description+" "+origin.Goal, false)
	writeJSON(w, http.StatusCreated, taskDTO(cloned, s.resolvedTaskStatus(cloned)))
}
