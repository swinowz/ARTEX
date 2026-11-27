package server

import (
	"context"
	"fmt"
	"reflect"
	"testing"
)

// scaleWorkerNames is the pure accounting for hot worker scaling (ADR-0005, #32):
// given the current worker-loop count and a target, it returns the names of the new
// loops to start (empty when target <= current). These tests pin that logic without
// spawning goroutines.

func TestScaleWorkerNamesAddsFromNextIndex(t *testing.T) {
	got := scaleWorkerNames(3, 5)
	want := []string{"work#4", "work#5"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("scaleWorkerNames(3,5) = %v, want %v", got, want)
	}
}

func TestScaleWorkerNamesNoOpWhenTargetNotHigher(t *testing.T) {
	for _, tc := range []struct{ cur, target int }{{5, 5}, {5, 3}, {1, 0}, {3, -1}} {
		if got := scaleWorkerNames(tc.cur, tc.target); len(got) != 0 {
			t.Fatalf("scaleWorkerNames(%d,%d) = %v, want empty", tc.cur, tc.target, got)
		}
	}
}

func TestScaleWorkerNamesFromZero(t *testing.T) {
	got := scaleWorkerNames(0, 2)
	want := []string{"work#1", "work#2"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("scaleWorkerNames(0,2) = %v, want %v", got, want)
	}
}

// The names must match Engine.Run's scheme (work#1..work#N) so a scaled loop never
// collides with an existing one.
func TestScaleWorkerNamesMatchRunScheme(t *testing.T) {
	// Run starts work#1..work#3 for workers=3; scaling 3->4 must produce work#4.
	got := scaleWorkerNames(3, 4)
	if len(got) != 1 || got[0] != "work#4" {
		t.Fatalf("scaleWorkerNames(3,4) = %v, want [work#4]", got)
	}
}

// Engine.ScaleWorkers accounting on a registered (running) task. NewEngine(nil) has
// no resolver, so the spawned workerLoops get a nil worker from snapshotFor and idle
// until the context is cancelled — safe to run in a unit test.
func TestScaleWorkersAddsLoopsOnRunningTask(t *testing.T) {
	e := NewEngine(nil)
	ctx, cancel := context.WithCancel(context.Background())
	const taskID = "scale-t1"
	rt := e.registerTaskRoutines(ctx, taskID, 3, 3) // task started with 3 worker loops
	if rt == nil {
		t.Fatal("runtime not registered")
	}
	for i := 0; i < 3; i++ {
		runTaskRoutine(rt, func(c context.Context) { <-c.Done() })
	}
	task := &Task{ID: taskID}

	added, total, running := e.ScaleWorkers(task, 5)
	if !running || added != 2 || total != 5 {
		t.Fatalf("scale 3->5: added=%d total=%d running=%v, want 2 5 true", added, total, running)
	}
	// target <= current is a no-op (never kills in-flight workers).
	added, total, running = e.ScaleWorkers(task, 4)
	if !running || added != 0 || total != 5 {
		t.Fatalf("scale ->4: added=%d total=%d running=%v, want 0 5 true", added, total, running)
	}
	cancel()
	rt.wg.Wait()
}

func TestScaleWorkersNotRunningTask(t *testing.T) {
	e := NewEngine(nil)
	added, total, running := e.ScaleWorkers(&Task{ID: "never-started"}, 5)
	if running || added != 0 || total != 0 {
		t.Fatalf("not running: added=%d total=%d running=%v, want 0 0 false", added, total, running)
	}
}

func TestScaleWorkersClampsBelowOne(t *testing.T) {
	e := NewEngine(nil)
	ctx, cancel := context.WithCancel(context.Background())
	rt := e.registerTaskRoutines(ctx, "c1", 1, 1)
	runTaskRoutine(rt, func(c context.Context) { <-c.Done() })
	// target 0 -> default handled by the HTTP layer; at the engine it clamps to 1,
	// which equals current, so it is a no-op returning the current total.
	added, total, running := e.ScaleWorkers(&Task{ID: "c1"}, 0)
	if !running || added != 0 || total != 1 {
		t.Fatalf("clamp: added=%d total=%d running=%v, want 0 1 true", added, total, running)
	}
	cancel()
	rt.wg.Wait()
}

// Issue #6: PUT /api/settings?workers=N applies to tasks started afterwards and
// leaves running tasks untouched; POST /api/tasks/{id}/scale with omitted/0
// workers scales a running task up to the new global setting without restart.
func TestWorkersSettingAndScaleTask(t *testing.T) {
	g := newGateServer(t)
	task, err := g.m.CreateTask("workers setting probe", "verify workers setting and hot scale", nil, 0, 0)
	if err != nil {
		t.Fatalf("CreateTask: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	rt := g.s.engine.registerTaskRoutines(ctx, task.ID, 3, 3)
	if rt == nil {
		cancel()
		t.Fatal("runtime not registered")
	}
	for i := 0; i < 3; i++ {
		runTaskRoutine(rt, func(c context.Context) { <-c.Done() })
	}
	t.Cleanup(func() {
		cancel()
		rt.wg.Wait()
	})

	// Raising global workers via PUT /api/settings updates the setting but does
	// not mutate the already-running task's worker count.
	code, out := g.do(t, "PUT", "/api/settings", `{"workers":5}`)
	if code != 200 || out["workers"] != float64(5) {
		t.Fatalf("PUT /api/settings workers=5: code=%d out=%v", code, out)
	}
	_, cur, _ := g.s.engine.ScaleWorkers(task, 0)
	if cur != 3 {
		t.Fatalf("running task workers after PUT /api/settings = %d, want 3", cur)
	}

	// POST /api/tasks/{id}/scale with omitted workers defaults to the global
	// workers setting (5) and adds the 2 missing loops.
	code, out = g.do(t, "POST", fmt.Sprintf("/api/tasks/%s/scale", task.ID), `{}`)
	if code != 200 || out["added"] != float64(2) || out["workers"] != float64(5) {
		t.Fatalf("POST /scale: code=%d out=%v, want added=2 workers=5", code, out)
	}
}
