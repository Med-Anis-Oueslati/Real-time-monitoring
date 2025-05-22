from pyspark.sql import SparkSession
from pyspark.sql.functions import col, from_json, to_timestamp, year, month, dayofmonth, hour, minute, second, lit, first, window
from pyspark.sql.types import StructType, StructField, StringType, DoubleType, TimestampType
from dotenv import load_dotenv
import logging
import os

# Initialize logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# Initialize Spark session
spark_jars = [
    "/opt/spark/jars/spark-sql-kafka-0-10_2.12-3.5.0.jar",
    "/opt/spark/jars/kafka-clients-3.4.1.jar",
    "/opt/spark/jars/spark-streaming_2.12-3.5.0.jar",
    "/opt/spark/jars/spark-token-provider-kafka-0-10_2.12-3.5.0.jar",
    "/opt/spark/jars/commons-pool2-2.11.1.jar",
    "/opt/spark/jars/snowflake-jdbc-3.23.2.jar",
    "/opt/spark/jars/spark-snowflake_2.12-3.1.1.jar",
    "/opt/spark/jars/jackson-databind-2.15.2.jar",
    "/opt/spark/jars/jackson-core-2.15.2.jar",
    "/opt/spark/jars/jackson-annotations-2.15.2.jar"
]
spark = SparkSession.builder \
    .appName("SystemMetricsToSnowflake") \
    .config("spark.dynamicAllocation.enabled", "true") \
    .config("spark.ui.port", "4056") \
    .getOrCreate()

# Define schemas for each metric type (all fields as strings to avoid type mismatches)
cpu_schema = StructType([
    StructField("user", StringType(), True),
    StructField("nice", StringType(), True),
    StructField("system", StringType(), True),
    StructField("iowait", StringType(), True),
    StructField("steal", StringType(), True),
    StructField("idle", StringType(), True),
    StructField("hostname", StringType(), True),
    StructField("vm_id", StringType(), True)
])

memory_schema = StructType([
    StructField("total", StringType(), True),
    StructField("used", StringType(), True),
    StructField("free", StringType(), True),
    StructField("shared", StringType(), True),
    StructField("buff_cache", StringType(), True),
    StructField("available", StringType(), True),
    StructField("hostname", StringType(), True),
    StructField("vm_id", StringType(), True)
])

disk_schema = StructType([
    StructField("device", StringType(), True),
    StructField("r_s", StringType(), True),
    StructField("rkB_s", StringType(), True),
    StructField("rrqm_s", StringType(), True),
    StructField("rrqm_pct", StringType(), True),
    StructField("r_await", StringType(), True),
    StructField("rareq_sz", StringType(), True),
    StructField("w_s", StringType(), True),
    StructField("wkB_s", StringType(), True),
    StructField("wrqm_s", StringType(), True),
    StructField("wrqm_pct", StringType(), True),
    StructField("w_await", StringType(), True),
    StructField("wareq_sz", StringType(), True),
    StructField("hostname", StringType(), True),
    StructField("vm_id", StringType(), True)
])

# Read from Kafka
kafka_df = spark \
    .readStream \
    .format("kafka") \
    .option("kafka.bootstrap.servers", "kafka:9092") \
    .option("subscribe", "system_metrics") \
    .option("startingOffsets", "latest") \
    .option("kafka.group.id", "system_metrics_group") \
    .option("kafka.session.timeout.ms", "10000") \
    .option("kafka.heartbeat.interval.ms", "3000") \
    .option("kafka.max.poll.records", "500") \
    .load()

# Log raw Kafka messages for debugging
kafka_df.selectExpr("CAST(value AS STRING) AS raw_message").writeStream \
    .format("console") \
    .outputMode("append") \
    .trigger(processingTime="5 seconds") \
    .start()

# Parse Kafka message
parsed_df = kafka_df.select(
    col("value").cast("string").alias("raw_json"),
    from_json(col("value").cast("string"), cpu_schema).alias("cpu"),
    from_json(col("value").cast("string"), memory_schema).alias("memory"),
    from_json(col("value").cast("string"), disk_schema).alias("disk"),
    col("timestamp").alias("kafka_timestamp")
)

# Process CPU metrics
cpu_df = parsed_df.filter(col("raw_json").like("%user%")) \
    .select(
        col("kafka_timestamp").alias("timestamp"),
        col("cpu.user").cast("double").alias("cpu_user"),
        col("cpu.system").cast("double").alias("cpu_system"),
        col("cpu.iowait").cast("double").alias("cpu_iowait"),
        col("cpu.idle").cast("double").alias("cpu_idle"),
        lit(None).cast("double").alias("mem_used"),
        lit(None).cast("double").alias("mem_total"),
        lit(None).cast("double").alias("disk_read_kbs"),
        lit(None).cast("double").alias("disk_write_kbs"),
        col("cpu.hostname").alias("hostname"),
        col("cpu.vm_id").alias("vm_id"),
        col("raw_json")
    )

# Process memory metrics
memory_df = parsed_df.filter(col("raw_json").like("%total%")) \
    .select(
        col("kafka_timestamp").alias("timestamp"),
        lit(None).cast("double").alias("cpu_user"),
        lit(None).cast("double").alias("cpu_system"),
        lit(None).cast("double").alias("cpu_iowait"),
        lit(None).cast("double").alias("cpu_idle"),
        col("memory.used").cast("double").alias("mem_used"),
        col("memory.total").cast("double").alias("mem_total"),
        lit(None).cast("double").alias("disk_read_kbs"),
        lit(None).cast("double").alias("disk_write_kbs"),
        col("memory.hostname").alias("hostname"),
        col("memory.vm_id").alias("vm_id"),
        col("raw_json")
    )

# Process disk metrics
disk_df = parsed_df.filter(col("raw_json").like("%device%")) \
    .select(
        col("kafka_timestamp").alias("timestamp"),
        lit(None).cast("double").alias("cpu_user"),
        lit(None).cast("double").alias("cpu_system"),
        lit(None).cast("double").alias("cpu_iowait"),
        lit(None).cast("double").alias("cpu_idle"),
        lit(None).cast("double").alias("mem_used"),
        lit(None).cast("double").alias("mem_total"),
        col("disk.rkB_s").cast("double").alias("disk_read_kbs"),
        col("disk.wkB_s").cast("double").alias("disk_write_kbs"),
        col("disk.hostname").alias("hostname"),
        col("disk.vm_id").alias("vm_id"),
        col("raw_json")
    )

# Union all metrics
enriched_df = cpu_df.union(memory_df).union(disk_df)

# Add watermark before aggregation
watermarked_df = enriched_df.withWatermark("timestamp", "10 seconds")

# Aggregate by 10-second window to combine metrics
aggregated_df = watermarked_df.groupBy(
    window(col("timestamp"), "10 seconds"),
    col("hostname"),
    col("vm_id")
).agg(
    first("cpu_user", ignorenulls=True).alias("cpu_user"),
    first("cpu_system", ignorenulls=True).alias("cpu_system"),
    first("cpu_iowait", ignorenulls=True).alias("cpu_iowait"),
    first("cpu_idle", ignorenulls=True).alias("cpu_idle"),
    first("mem_used", ignorenulls=True).alias("mem_used"),
    first("mem_total", ignorenulls=True).alias("mem_total"),
    first("disk_read_kbs", ignorenulls=True).alias("disk_read_kbs"),
    first("disk_write_kbs", ignorenulls=True).alias("disk_write_kbs"),
    first("raw_json").alias("raw_json")
).select(
    col("window.start").alias("timestamp"),
    col("cpu_user"),
    col("cpu_system"),
    col("cpu_iowait"),
    col("cpu_idle"),
    col("mem_used"),
    col("mem_total"),
    col("disk_read_kbs"),
    col("disk_write_kbs"),
    col("hostname"),
    col("vm_id"),
    col("raw_json")
)

# Transform timestamp and decompose
final_df = aggregated_df \
    .withColumn("year", year(col("timestamp"))) \
    .withColumn("month", month(col("timestamp"))) \
    .withColumn("day", dayofmonth(col("timestamp"))) \
    .withColumn("hour", hour(col("timestamp"))) \
    .withColumn("minute", minute(col("timestamp"))) \
    .withColumn("second", second(col("timestamp"))) \
    .select(
        col("year"),
        col("month"),
        col("day"),
        col("hour"),
        col("minute"),
        col("second"),
        col("timestamp"),
        col("cpu_user"),
        col("cpu_system"),
        col("cpu_iowait"),
        col("cpu_idle"),
        col("disk_read_kbs"),
        col("disk_write_kbs"),
        col("mem_used"),
        col("mem_total"),
        col("hostname"),
        col("vm_id"),
        col("raw_json")
    )

# Debug: Print schemas and sample data
logger.info("Schema of parsed_df:")
parsed_df.printSchema()
logger.info("Schema of enriched_df:")
enriched_df.printSchema()
logger.info("Schema of aggregated_df:")
aggregated_df.printSchema()
logger.info("Schema of final_df:")
final_df.printSchema()

# Write to console for debugging
final_df.writeStream \
    .format("console") \
    .outputMode("complete") \
    .trigger(processingTime="5 seconds") \
    .start()

# Snowflake connection options
snowflake_options = {
    "sfURL": os.getenv("SNOWFLAKE_URL"),
    "sfAccount": os.getenv("SNOWFLAKE_ACCOUNT"),
    "sfUser": os.getenv("SNOWFLAKE_USER"),
    "sfPassword": os.getenv("SNOWFLAKE_PASSWORD"),
    "sfDatabase": os.getenv("SNOWFLAKE_DATABASE"),
    "sfSchema": os.getenv("SNOWFLAKE_SCHEMA"),
    "sfWarehouse": os.getenv("SNOWFLAKE_WAREHOUSE"),
    "sfRole": os.getenv("SNOWFLAKE_ROLE"),
    "dbtable": "SYSTEM_METRICS"
}

# Write to Snowflake and console
def write_to_snowflake(batch_df, batch_id):
    logger.info(f"Processing batch {batch_id} with {batch_df.count()} records")
    if batch_df.count() > 0:
        # Show output in console
        batch_df.show(truncate=False)
        # Write to Snowflake
        try:
            batch_df.drop("raw_json").write \
                .format("snowflake") \
                .options(**snowflake_options) \
                .option("dbtable", "SYSTEM_METRICS") \
                .option("sfOnError", "CONTINUE") \
                .mode("append") \
                .save()
            logger.info(f"Successfully wrote batch {batch_id} to Snowflake")
        except Exception as e:
            logger.error(f"Failed to write batch {batch_id} to Snowflake: {e}")
    else:
        logger.info("No records in batch")

# Write stream to Snowflake
query = final_df.writeStream \
    .outputMode("complete") \
    .trigger(processingTime="10 seconds") \
    .foreachBatch(write_to_snowflake) \
    .start()

try:
    query.awaitTermination()
except Exception as e:
    logger.error(f"Streaming query failed: {e}")
finally:
    spark.stop()