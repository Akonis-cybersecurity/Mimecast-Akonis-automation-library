from prometheus_client import Counter, Gauge, Histogram

# Module-specific namespace for Mimecast collected events
prom_namespace_mimecast = "symphony_module_mimecast"

INCOMING_EVENTS = Counter(
    name="collected_events",
    documentation="Number of events collected from Mimecast",
    namespace=prom_namespace_mimecast,
    labelnames=["intake_key", "source"],
)

# Common namespace shared across all symphony modules
prom_namespace_common = "symphony_module_common"

OUTCOMING_EVENTS = Counter(
    name="forwarded_events",
    documentation="Number of events forwarded to SEKOIA.IO",
    namespace=prom_namespace_common,
    labelnames=["intake_key", "source"],
)

FORWARD_EVENTS_DURATION = Histogram(
    name="forward_events_duration",
    documentation="Duration in seconds to collect and forward a batch of events",
    namespace=prom_namespace_common,
    labelnames=["intake_key", "source"],
)

EVENTS_LAG = Gauge(
    name="events_lags",
    documentation="Delay in seconds from the timestamp of the last event seen",
    namespace=prom_namespace_common,
    labelnames=["intake_key", "source"],
)
