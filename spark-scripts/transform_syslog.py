from pyspark.sql.functions import regexp_extract, when, current_timestamp, to_timestamp
from pyspark.sql.types import StructType, StructField, StringType, TimestampType

# Define schema (must match main.py)
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
    # Parse and transform the syslog entry
    timestamp = to_timestamp(
        regexp_extract(raw_log, r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+\+\d{2}:\d{2})", 1),
        "yyyy-MM-dd'T'HH:mm:ss.SSSSSSXXX"
    )
    hostname = regexp_extract(raw_log, r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+\+\d{2}:\d{2}\s+(\S+)", 1)
    process = regexp_extract(raw_log, r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+\+\d{2}:\d{2}\s+\S+\s+(\S+?)(?:\[\d+\])?:", 1)
    pid = regexp_extract(raw_log, r"\[(\d+)\]", 1)
    message = regexp_extract(raw_log, r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+\+\d{2}:\d{2}\s+\S+\s+\S+(?:\[\d+\])?:\s+(.+)", 1)
    
    # Categorize event type
    event_type = when(raw_log.contains("Started ") | raw_log.contains("Starting "), "service_start") \
        .when(raw_log.contains("Finished ") | raw_log.contains("Deactivated successfully"), "service_stop") \
        .when(raw_log.contains("user-") | raw_log.contains("User ") | raw_log.contains("[PAM]"), "user_activity") \
        .when(raw_log.contains("CRON"), "cron_job") \
        .when(raw_log.contains("sddm"), "display_manager") \
        .when(raw_log.contains("error") | raw_log.contains("unset environment variable"), "error") \
        .otherwise("system")
    
    # Assign severity
    severity = when(raw_log.contains("error") | raw_log.contains("unset environment variable"), "high") \
        .when(raw_log.contains("Started ") | raw_log.contains("Finished "), "medium") \
        .otherwise("low")
    
    # Return structured row
    return (timestamp, hostname, process, pid, event_type, severity, message, log_source, current_timestamp())