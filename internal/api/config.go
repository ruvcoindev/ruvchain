// internal/api/config.go
func (h *Handler) HandleConfigUpdate(c *gin.Context) {
	var update map[string]interface{}
	if err := c.BindJSON(&update); err != nil {
		c.AbortWithStatusJSON(400, gin.H{"error": "invalid request"})
		return
	}

	if err := h.config.ApplyUpdates(update); err != nil {
		c.AbortWithStatusJSON(400, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, gin.H{"status": "updated"})
}
