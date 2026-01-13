package middleware

import (
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	requestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "s3_gateway_requests_total",
			Help: "Total number of HTTP requests",
		},
		[]string{"method", "path", "status"},
	)

	requestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "s3_gateway_request_duration_seconds",
			Help:    "HTTP request duration in seconds",
			Buckets: []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10},
		},
		[]string{"method", "path"},
	)

	requestSize = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "s3_gateway_request_size_bytes",
			Help:    "HTTP request size in bytes",
			Buckets: prometheus.ExponentialBuckets(100, 10, 8),
		},
		[]string{"method", "path"},
	)

	responseSize = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "s3_gateway_response_size_bytes",
			Help:    "HTTP response size in bytes",
			Buckets: prometheus.ExponentialBuckets(100, 10, 8),
		},
		[]string{"method", "path"},
	)
)

func init() {
	prometheus.MustRegister(requestsTotal)
	prometheus.MustRegister(requestDuration)
	prometheus.MustRegister(requestSize)
	prometheus.MustRegister(responseSize)
}

// PrometheusMetrics creates a middleware that records Prometheus metrics
func PrometheusMetrics() gin.HandlerFunc {
	return func(c *gin.Context) {
		startTime := time.Now()

		// Record request size
		requestSize.WithLabelValues(c.Request.Method, c.FullPath()).Observe(float64(c.Request.ContentLength))

		// Process request
		c.Next()

		// Calculate duration
		duration := time.Since(startTime).Seconds()

		// Get normalized path (with route parameters like :id instead of actual values)
		path := c.FullPath()
		if path == "" {
			path = c.Request.URL.Path
		}

		// Record metrics
		status := strconv.Itoa(c.Writer.Status())
		requestsTotal.WithLabelValues(c.Request.Method, path, status).Inc()
		requestDuration.WithLabelValues(c.Request.Method, path).Observe(duration)
		responseSize.WithLabelValues(c.Request.Method, path).Observe(float64(c.Writer.Size()))
	}
}
