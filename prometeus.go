package metrics

import (
    "github.com/gin-gonic/gin"
    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
    // Метрики блокчейна
    BlocksProcessed = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "ruvchain_blocks_processed_total",
            Help: "Total number of processed blocks",
        },
        []string{"status"},
    )

    // Метрики сети
    PeersConnected = prometheus.NewGauge(
        prometheus.GaugeOpts{
            Name: "ruvchain_peers_connected",
            Help: "Number of connected peers",
        },
    )
)

func Init() {
    prometheus.MustRegister(BlocksProcessed, PeersConnected)
}

func Handler() gin.HandlerFunc {
    return func(c *gin.Context) {
        promhttp.Handler().ServeHTTP(c.Writer, c.Request)
    }
}
