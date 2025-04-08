from pyspark.sql.functions import regexp_extract, when, current_timestamp, to_timestamp
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
    # Parse the kern.log entry
    timestamp = to_timestamp(
        regexp_extract(raw_log, r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+\+\d{2}:\d{2})", 1),
        "yyyy-MM-dd'T'HH:mm:ss.SSSSSSXXX"
    )
    hostname = regexp_extract(raw_log, r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+\+\d{2}:\d{2}\s+(\S+)", 1)
    message = regexp_extract(raw_log, r"kernel:\s+\d{2}:\d{2}:\d{2}\.\d+\s+\S+\s+(.+)", 1)
    pid = regexp_extract(raw_log, r"Process ID:\s+(\d+)", 1)  # Extract PID if present
    
    # Categorize event type
    event_type = when(raw_log.contains("started") | raw_log.contains("Service started"), "service_start") \
        .when(raw_log.contains("Initializing service") | raw_log.contains("Creating worker thread"), "service_init") \
        .when(raw_log.contains("OS Product") | raw_log.contains("OS Release") | raw_log.contains("Executable"), "system_info") \
        .when(raw_log.contains("Monitor") | raw_log.contains("RRScreenChangeNotify") | raw_log.contains("output[0] successfully configured"), "hardware") \
        .when(raw_log.contains("Error") | raw_log.contains("VERR_"), "error") \
        .otherwise("kernel")
    
    # Assign severity
    severity = when(raw_log.contains("Error") | raw_log.contains("VERR_"), "high") \
        .when(raw_log.contains("started") | raw_log.contains("Service started") | raw_log.contains("Monitor"), "medium") \
        .otherwise("low")
    
    # Return structured row
    return (timestamp, hostname, "kernel", pid, event_type, severity, message, log_source, current_timestamp())