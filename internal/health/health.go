package health

import (
    "github.com/gin-gonic/gin"
    "github.com/ruvcoindev/ruvchain/internal/core"
)

type Checker struct {
    core *core.Core
}

func New(core *core.Core) *Checker {
    return &Checker{core: core}
}

func (h *Checker) Liveness(c *gin.Context) {
    if h.core.IsRunning() {
        c.JSON(200, gin.H{"status": "ok"})
        return
    }
    c.JSON(503, gin.H{"status": "down"})
}

func (h *Checker) Readiness(c *gin.Context) {
    if h.core.IsSynced() {
        c.JSON(200, gin.H{"status": "ready"})
        return
    }
    c.JSON(503, gin.H{"status": "syncing"})
}
