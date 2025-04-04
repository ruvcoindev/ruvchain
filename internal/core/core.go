// internal/core/core.go
func (c *Core) Start() error {
    // Инициализация Jaeger
    tp, err := tracing.InitTracing(
        c.config.Tracing.Jaeger.Endpoint,
        c.config.Tracing.Jaeger.ServiceName,
    )
    // ...
}
