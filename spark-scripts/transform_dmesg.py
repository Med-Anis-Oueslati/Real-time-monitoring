from pyspark.sql.functions import regexp_extract, when, current_timestamp, col
from pyspark.sql.types import StructType, StructField, StringType, TimestampType

# Define schema (matches main.py)
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
    # Parse the dmesg entry
    boot_time_sec = regexp_extract(raw_log, r"\[\s*(\d+\.\d+)\]", 1)
    message = regexp_extract(raw_log, r"kernel:\s+(.+)", 1)
    
    # Approximate absolute timestamp (boot time + seconds since boot)
    # Note: In a real setup, you'd need the system boot time from a reliable source (e.g., Kafka metadata or a separate lookup).
    # For simplicity, we'll use current_timestamp() as a placeholder and adjust in Spark if needed.
    timestamp = current_timestamp() if boot_time_sec == "" else None  # Placeholder; adjust in Spark if boot time is available
    
    # Hostname not explicitly in dmesg; use a placeholder or derive later if needed
    hostname = "unknown"  # Could be enriched in main.py if hostname is available elsewhere
    
    # Categorize event type
    event_type = when(raw_log.contains("Linux version") | raw_log.contains("Command line") | raw_log.contains("OS Product"), "system_info") \
        .when(raw_log.contains("scsi") | raw_log.contains("usb") | raw_log.contains("NIC Link") | raw_log.contains("Detected") | raw_log.contains("Video Device"), "hardware") \
        .when(raw_log.contains("ERROR") | raw_log.contains("Cannot allocate") | raw_log.contains("not supported"), "error") \
        .when(raw_log.contains("module loaded") | raw_log.contains("Starting") | raw_log.contains("Initialized"), "boot") \
        .otherwise("kernel")
    
    # Assign severity
    severity = when(raw_log.contains("ERROR") | raw_log.contains("Cannot allocate") | raw_log.contains("not supported"), "high") \
        .when(raw_log.contains("scsi") | raw_log.contains("usb") | raw_log.contains("NIC Link") | raw_log.contains("Detected"), "medium") \
        .otherwise("low")
    
    # Return structured row
    return (timestamp, hostname, "kernel", None, event_type, severity, message, log_source, current_timestamp())