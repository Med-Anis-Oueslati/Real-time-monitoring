from pyspark.sql import SparkSession
from pyspark.sql.functions import col, regexp_extract, when, current_timestamp, to_timestamp, lit
from pyspark.sql.types import StructType, StructField, StringType, TimestampType

# Initialize Spark session
spark = SparkSession.builder \
    .appName("LogTransformationPipeline") \
    .master("spark://spark:7077") \
    .config("spark.sql.shuffle.partitions", "4") \
    .config("spark.streaming.stopGracefullyOnShutdown", "true") \
    .getOrCreate()

# Define Kafka topic
topics = "lubuntu_auth"

# Unified schema for all transformed logs
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

# Read from Kafka
kafka_df = spark \
    .readStream \
    .format("kafka") \
    .option("kafka.bootstrap.servers", "kafka:9092") \
    .option("subscribe", topics) \
    .option("startingOffsets", "latest") \
    .option("failOnDataLoss", "false") \
    .load()

# Extract raw log and topic
raw_df = kafka_df.select(
    col("value").cast("string").alias("raw_log"),
    col("topic").alias("log_source")
)

# Apply transformation directly on the DataFrame (adapted for lubuntu_auth)
transformed_df = raw_df.select(
    to_timestamp(
        regexp_extract(col("raw_log"), r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?\+\d{2}:\d{2})", 1),
        "yyyy-MM-dd'T'HH:mm:ss.SSSSSSXXX"
    ).alias("timestamp"),
    regexp_extract(col("raw_log"), r"^\S+\s+(\S+)", 1).alias("hostname"),
    regexp_extract(
        regexp_extract(col("raw_log"), r"\s+(\S+(?:\[\d+\])?):\s+", 1),
        r"^(\S+?)(?:\[\d+\])?$", 1
    ).alias("process"),
    regexp_extract(
        regexp_extract(col("raw_log"), r"\s+(\S+(?:\[\d+\])?):\s+", 1),
        r"\[(\d+)\]", 1
    ).alias("pid"),
    when(col("raw_log").contains("session opened for user"), "session_open")
    .when(col("raw_log").contains("session closed for user"), "session_close")
    .when(col("raw_log").contains("COMMAND="), "sudo_command")
    .when(col("raw_log").contains("pam_unix(su:session)"), "su_session")
    .when(col("raw_log").contains("pam_unix(cron:session)"), "cron_session")
    .when(col("raw_log").contains("systemd-logind"), "logind_event")
    .when(col("raw_log").contains("New session") | col("raw_log").contains("Removed session"), "session_event")
    .when(col("raw_log").contains("Failed to activate") | col("raw_log").contains("unable to locate"), "error")
    .otherwise("auth_misc").alias("event_type"),
    when(col("raw_log").contains("Failed to activate") | col("raw_log").contains("unable to locate"), "high")
    .when(col("raw_log").contains("COMMAND=") | col("raw_log").contains("su:session"), "medium")
    .when(col("raw_log").contains("session opened") | col("raw_log").contains("session closed"), "low")
    .otherwise("info").alias("severity"),
    regexp_extract(col("raw_log"), r"\s+\S+(?:\[\d+\])?:\s+(.*)", 1).alias("message"),
    col("log_source"),  # Use the topic as log_source instead of hardcoding "system"
    current_timestamp().alias("processed_at")
).filter(
    # Filter out low-severity noise across all logs
    col("severity").isin("high", "medium")
)

# Write to console for testing
query = transformed_df \
    .writeStream \
    .format("console") \
    .outputMode("append") \
    .trigger(processingTime="10 seconds") \
    .option("checkpointLocation", "/tmp/spark-checkpoint") \
    .start()

# Keep the stream running
query.awaitTermination()