package server

import (
	"context"
	"log"
	"strconv"
	"time"

	"github.com/Autumn-27/artex/sandbox"
)

func WithCommandSandbox(service *sandbox.Service) Option {
	return func(s *Server) { s.commandSandbox = service; s.engine.commandSandbox = service }
}

func (e *Engine) removeSandbox(task string) {
	if e.commandSandbox == nil {
		return
	}
	id, err := strconv.ParseInt(task, 10, 64)
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := e.commandSandbox.Remove(ctx, id); err != nil {
		log.Printf("[sandbox] cleanup task %s: %v", task, err)
	}
}
