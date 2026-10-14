-- ClickHouse: columnar telemetry store.
-- One flat events table (simpler ops than one table per EventType)
-- with the codecs the blueprint calls out: DoubleDelta for the
-- timestamp, T64 for small integers, Gorilla for metric floats,
-- LowCardinality for repeated identifiers, ZSTD(3) for free text.

CREATE DATABASE IF NOT EXISTS endpointguard;

CREATE TABLE IF NOT EXISTS endpointguard.telemetry_events
(
    event_id        String,
    agent_id        LowCardinality(String),
    hostname        LowCardinality(String),
    event_type      LowCardinality(String),
    event_time      DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),

    process_id      UInt32 CODEC(T64, ZSTD(1)),
    parent_pid      UInt32 CODEC(T64, ZSTD(1)),
    image_path      String CODEC(ZSTD(3)),
    command_line    String CODEC(ZSTD(3)),
    user_name       LowCardinality(String),

    window_title    String CODEC(ZSTD(3)),
    is_idle         UInt8,

    cpu_pct         Float32 CODEC(Gorilla, ZSTD(1)),
    mem_used_bytes  UInt64  CODEC(DoubleDelta, ZSTD(1)),
    battery_pct     Float32 CODEC(Gorilla, ZSTD(1)),

    dlp_category    LowCardinality(String),

    -- Full decoded event as JSON, for fields not promoted to a
    -- column (socket lists, USB details, exit codes, ...).
    raw_json        String CODEC(ZSTD(3)),

    ingested_at     DateTime DEFAULT now()
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(event_time)
ORDER BY (agent_id, event_type, event_time)
TTL toDateTime(event_time) + INTERVAL 90 DAY DELETE
SETTINGS index_granularity = 8192;
