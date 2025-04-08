from pyspark.sql import SparkSession
from pyspark.sql.functions import col, udf
from pyspark.sql.types import StructType, StructField, StringType, TimestampType
import importlib

# Initialize Spark session
spark = SparkSession.builder \
    .appName("LogTransformationPipeline") \
    .master("spark://spark:7077") \
    .config("spark.sql.shuffle.partitions", "4") \
    .config("spark.streaming.stopGracefullyOnShutdown", "true") \
    .getOrCreate()

# Define all Kafka topics /// no kali
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

# Function to dynamically call transformation modules based on topic /// no kali
def transform_log(log_source, raw_log):
    # Map topics to transformation modules
    topic_to_module = {
        
        "lubuntu_auth": "transform_auth",
    }
    
    # Default to transform_syslog if topic is unrecognized
    module_name = topic_to_module.get(log_source, "transform_syslog")
    try:
        module = importlib.import_module(module_name)
        return module.transform(raw_log, log_source)
    except Exception as e:
        # Return a fallback row in case of transformation failure
        return (None, None, None, None, "error", "high", f"Transformation failed: {str(e)}", log_source, None)

# Register UDF
transform_udf = udf(transform_log, schema)

# Apply transformations
transformed_df = raw_df.select(
    transform_udf(col("log_source"), col("raw_log")).alias("structured_log")
).select(
    col("structured_log.timestamp"),
    col("structured_log.hostname"),
    col("structured_log.process"),
    col("structured_log.pid"),
    col("structured_log.event_type"),
    col("structured_log.severity"),
    col("structured_log.message"),
    col("structured_log.log_source"),
    col("structured_log.processed_at")
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