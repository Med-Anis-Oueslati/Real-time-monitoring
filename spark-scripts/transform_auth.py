from pyspark.sql.functions import regexp_extract, when, current_timestamp, to_timestamp, col
from pyspark.sql.types import StructType, StructField, StringType, TimestampType

# Define schema (used in main.py)
schema = StructType([
    StructField("timestamp", TimestampType(), True),
    StructField("hostname", StringType(), True),
    StructField("process", StringType(), True),
    StructField("pid", StringType(), True),
    StructField("event_type", StringType(), True),
    StructField("severity", StringType(), True),
    StructField("message", StringType(), True),
    StructField("log_source", StringType(), True),
    StructField("processed_at", TimestampType(), True)
])

def transform(raw_log, log_source):
    # Extract fields using regex
    timestamp = to_timestamp(
        regexp_extract(raw_log, r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?\+\d{2}:\d{2})", 1),
        "yyyy-MM-dd'T'HH:mm:ss.SSSSSSXXX"
    )
    hostname = regexp_extract(raw_log, r"^\S+\s+(\S+)", 1)
    process_pid = regexp_extract(raw_log, r"\s+(\S+(?:\[\d+\])?):\s+", 1)
    process = regexp_extract(process_pid, r"^(\S+?)(?:\[\d+\])?$", 1)
    pid = regexp_extract(process_pid, r"\[(\d+)\]", 1)
    message = regexp_extract(raw_log, r"\s+\S+(?:\[\d+\])?:\s+(.*)", 1)

    # Define event_type classification
    event_type = when(raw_log.contains("session opened for user"), "session_open") \
        .when(raw_log.contains("session closed for user"), "session_close") \
        .when(raw_log.contains("COMMAND="), "sudo_command") \
        .when(raw_log.contains("pam_unix(su:session)"), "su_session") \
        .when(raw_log.contains("pam_unix(cron:session)"), "cron_session") \
        .when(raw_log.contains("systemd-logind"), "logind_event") \
        .when(raw_log.contains("New session") | raw_log.contains("Removed session"), "session_event") \
        .when(raw_log.contains("Failed to activate") | raw_log.contains("unable to locate"), "error") \
        .otherwise("auth_misc")

    # Define severity level
    severity = when(raw_log.contains("Failed to activate") | raw_log.contains("unable to locate"), "high") \
        .when(raw_log.contains("COMMAND=") | raw_log.contains("su:session"), "medium") \
        .when(raw_log.contains("session opened") | raw_log.contains("session closed"), "low") \
        .otherwise("info")

    return (
        timestamp,
        hostname,
        process,
        pid,
        event_type,
        severity,
        message,
        log_source,
        current_timestamp()
    )