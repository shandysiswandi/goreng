package telemetry

import (
	"context"
	"log"
	"strings"
	"time"

	"github.com/shandysiswandi/goreng/telemetry/filter"
	"github.com/shandysiswandi/goreng/telemetry/logger"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type Option func(*Telemetry)

func WithServiceName(serviceName string) Option {
	return func(t *Telemetry) {
		t.name = serviceName
	}
}

func WithVerbose() Option {
	return func(t *Telemetry) {
		t.verbose = true
	}
}

func WithLogFilter(keys ...string) Option {
	return func(t *Telemetry) {
		values := make([]string, 0, len(keys))
		for _, value := range keys {
			values = append(values, strings.ToLower(value))
		}

		t.filter = filter.NewFilter(
			filter.WithHeaders(values...),
			filter.WithQueries(values...),
			filter.WithFields(values...),
		)
	}
}

func WithZapLogger(serviceName string, lvl logger.Level, enableLogFile bool) Option {
	return func(t *Telemetry) {
		svcName := ""
		if enableLogFile {
			svcName = serviceName + ".log"
		}
		lo := logger.NewZapLogger(svcName, lvl)
		t.logger = lo
		t.flushers = append(t.flushers, lo.Close)
	}
}

func WithOTLP(address string) Option {
	return func(t *Telemetry) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
		defer cancel()

		conn, err := grpc.NewClient(address, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			log.Printf("failed to create gRPC connection to collector %v", err)

			return
		}

		traceExporter, err := otlptracegrpc.New(ctx, otlptracegrpc.WithGRPCConn(conn))
		if err != nil {
			log.Printf("failed to create trace exporter %v", err)

			return
		}

		tracerProvider := trace.NewTracerProvider(
			trace.WithBatcher(traceExporter),
			trace.WithSampler(trace.AlwaysSample()),
			trace.WithResource(
				resource.NewWithAttributes(
					semconv.SchemaURL,
					semconv.ServiceNameKey.String(t.name),
				),
			),
		)

		metricExporter, err := otlpmetricgrpc.New(ctx, otlpmetricgrpc.WithGRPCConn(conn))
		if err != nil {
			log.Printf("failed to create metrics exporter %v", err)

			return
		}

		meterProvider := metric.NewMeterProvider(
			metric.WithReader(metric.NewPeriodicReader(metricExporter)),
			metric.WithResource(
				resource.NewWithAttributes(
					semconv.SchemaURL,
					semconv.ServiceNameKey.String(t.name),
				),
			),
		)

		t.tracer = tracerProvider
		t.meter = meterProvider
		t.collector = OPENTELEMETRY
		t.flushers = append(t.flushers,
			func() error { return tracerProvider.Shutdown(ctx) },
			func() error { return meterProvider.Shutdown(ctx) },
			func() error { return conn.Close() },
		)
	}
}
