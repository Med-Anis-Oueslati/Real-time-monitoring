from pyspark.sql import SparkSession
from pyspark.sql.functions import col, from_json, from_unixtime, year, month, dayofmonth, hour, minute, second, when
from pyspark.sql.types import StructType, StructField, StringType, DoubleType, IntegerType
import os
import logging

# Initialize logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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
    .appName("ZeekCaptureLossProcessing") \
    .config("spark.executor.memory", "4g") \
    .config("spark.executor.cores", "4") \
    .config("spark.driver.memory", "4g") \
    .config("spark.kafka.consumer.pollTimeoutMs", "60000") \
    .config("spark.streaming.stopGracefullyOnShutdown", "true") \
    .config("spark.dynamicAllocation.enabled", "false") \
    .config("spark.jars", ",".join(spark_jars)) \
    .getOrCreate()

# Define schema for zeek_capture_loss JSON
capture_loss_schema = StructType([
    StructField("ts", DoubleType(), True),
    StructField("ts_delta", DoubleType(), True),
    StructField("peer", StringType(), True),
    StructField("gaps", IntegerType(), True),
    StructField("acks", IntegerType(), True),
    StructField("percent_lost", DoubleType(), True),
    StructField("hostname", StringType(), True),
    StructField("vm_id", StringType(), True)
])

# Read from Kafka
kafka_df = spark \
    .readStream \
    .format("kafka") \
    .option("kafka.bootstrap.servers", "kafka:9092") \
    .option("subscribe", "zeek_capture_loss") \
    .option("startingOffsets", "latest") \
    .option("kafka.group.id", "zeek_capture_loss_group") \
    .option("kafka.session.timeout.ms", "10000") \
    .option("kafka.heartbeat.interval.ms", "3000") \
    .option("kafka.max.poll.records", "500") \
    .load()

# Parse Kafka message
parsed_df = kafka_df.select(
    from_json(col("value").cast("string"), capture_loss_schema).alias("data")
).select("data.*")

# Convert ts to timestamp and decompose
enriched_df = parsed_df \
    .withColumn("timestamp", from_unixtime(col("ts"))) \
    .withColumn("year", year(col("timestamp"))) \
    .withColumn("month", month(col("timestamp"))) \
    .withColumn("day", dayofmonth(col("timestamp"))) \
    .withColumn("hour", hour(col("timestamp"))) \
    .withColumn("minute", minute(col("timestamp"))) \
    .withColumn("second", second(col("timestamp")))

# Add loss severity classification
enriched_df = enriched_df.withColumn(
    "loss_severity",
    when(col("percent_lost") < 5, "Low")
    .when(col("percent_lost").between(5, 10), "Medium")
    .when(col("percent_lost") > 10, "High")
    .otherwise("Unknown")
)

# Select final columns for output
final_df = enriched_df.select(
    col("ts"),
    col("year"),
    col("month"),
    col("day"),
    col("hour"),
    col("minute"),
    col("second"),
    col("timestamp"),
    col("ts_delta"),
    col("peer"),
    col("gaps"),
    col("acks"),
    col("percent_lost"),
    col("loss_severity"),
    col("hostname"),
    col("vm_id")
)

# Comment out Snowflake connection
# from dotenv import load_dotenv
# load_dotenv()
#
# snowflake_options = {
#     "sfURL": os.getenv("SNOWFLAKE_URL"),
#     "sfAccount": os.getenv("SNOWFLAKE_ACCOUNT"),
#     "sfUser": os.getenv("SNOWFLAKE_USER"),
#     "sfPassword": os.getenv("SNOWFLAKE_PASSWORD"),
#     "sfDatabase": os.getenv("SNOWFLAKE_DATABASE"),
#     "sfSchema": os.getenv("SNOWFLAKE_SCHEMA"),
#     "sfWarehouse": os.getenv("SNOWFLAKE_WAREHOUSE"),
#     "sfRole": os.getenv("SNOWFLAKE_ROLE"),
#     "dbtable": "ZEEK_CAPTURE_LOSS"
# }
#
# def write_to_snowflake(batch_df, batch_id):
#     logger.info(f"Processing batch {batch_id} with {batch_df.count()} records")
#     if batch_df.count() > 0:
#         batch_df.show(truncate=False)
#         batch_df.write \
#             .format("snowflake") \
#             .options(**snowflake_options) \
#             .option("dbtable", "ZEEK_CAPTURE_LOSS") \
#             .mode("append") \
#             .save()
#     else:
#         logger.info("No records in batch")

# Write to console for testing
query = final_df.writeStream \
    .outputMode("append") \
    .format("console") \
    .trigger(processingTime="10 seconds") \
    .option("truncate", "false") \
    .start()

try:
    query.awaitTermination()
except Exception as e:
    logger.error(f"Streaming query failed: {e}")
finally:
    spark.stop()