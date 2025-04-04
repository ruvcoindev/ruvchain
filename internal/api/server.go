healthChecker := health.New(node)
r.GET("/healthz", healthChecker.Liveness)
r.GET("/ready", healthChecker.Readiness)


func NewServer(cfg *config.Config) *gin.Engine {
    r := gin.Default()
    
    // Prometheus метрики
    metrics.Init()
    r.GET("/metrics", metrics.Handler())
    
    return r
}
