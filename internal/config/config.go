// internal/config/config.go
type TracingConfig struct {
    Jaeger struct {
        Endpoint    string  `yaml:"endpoint"`
        ServiceName string  `yaml:"service_name"`
        Sampler     float64 `yaml:"sampler"`
    } `yaml:"jaeger"`
}

type Config struct {
    Tracing TracingConfig `yaml:"tracing"`
    // ... другие поля
}
