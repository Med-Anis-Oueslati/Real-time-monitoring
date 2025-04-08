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
    # Parse the ufw.log entry
    timestamp = to_timestamp(
        regexp_extract(raw_log, r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+\+\d{2}:\d{2})", 1),
        "yyyy-MM-dd'T'HH:mm:ss.SSSSSSXXX"
    )
    hostname = regexp_extract(raw_log, r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+\+\d{2}:\d{2}\s+(\S+)", 1)
    message = regexp_extract(raw_log, r"\[UFW BLOCK\]\s+(.+)", 1)
    
    # Categorize event type (all samples are blocks; could expand for ALLOW or other actions)
    event_type = "firewall_block"
    
    # Assign severity (medium for blocks; could adjust based on context like repeated attempts)
    severity = "medium"
    
    # Return structured row
    return (timestamp, hostname, "kernel", None, event_type, severity, message, log_source, current_timestamp())