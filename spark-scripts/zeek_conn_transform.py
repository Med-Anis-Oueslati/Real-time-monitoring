from pyspark.sql import SparkSession
from pyspark.sql.functions import col, from_json, to_timestamp, year, month, dayofmonth, hour, minute, second, from_unixtime
from pyspark.sql.types import StructType, StructField, StringType, DoubleType, IntegerType, LongType, BooleanType
import logging
import os
from dotenv import load_dotenv

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
    .appName("ZeekConnToSnowflake") \
    .config("spark.executor.memory", "4g") \
    .config("spark.executor.cores", "4") \
    .config("spark.driver.memory", "4g") \
    .config("spark.kafka.consumer.pollTimeoutMs", "60000") \
    .config("spark.streaming.stopGracefullyOnShutdown", "true") \
    .config("spark.dynamicAllocation.enabled", "false") \
    .config("spark.jars", ",".join(spark_jars)) \
    .getOrCreate()

# Define schema for zeek_conn JSON
conn_schema = StructType([
    StructField("ts", DoubleType(), True),
    StructField("uid", StringType(), True),
    StructField("id.orig_h", StringType(), True),
    StructField("id.orig_p", IntegerType(), True),
    StructField("id.resp_h", StringType(), True),
    StructField("id.resp_p", IntegerType(), True),
    StructField("proto", StringType(), True),
    StructField("service", StringType(), True),
    StructField("duration", DoubleType(), True),
    StructField("orig_bytes", LongType(), True),
    StructField("resp_bytes", LongType(), True),
    StructField("conn_state", StringType(), True),
    StructField("local_orig", BooleanType(), True),
    StructField("local_resp", BooleanType(), True),
    StructField("missed_bytes", LongType(), True),
    StructField("history", StringType(), True),
    StructField("orig_pkts", LongType(), True),
    StructField("orig_ip_bytes", LongType(), True),
    StructField("resp_pkts", LongType(), True),
    StructField("resp_ip_bytes", LongType(), True),
    StructField("ip_proto", IntegerType(), True),
    StructField("hostname", StringType(), True),
    StructField("vm_id", StringType(), True)
])

# Read from Kafka
kafka_df = spark \
    .readStream \
    .format("kafka") \
    .option("kafka.bootstrap.servers", "kafka:9092") \
    .option("subscribe", "zeek_conn") \
    .option("startingOffsets", "latest") \
    .option("kafka.group.id", "zeek_conn_group") \
    .option("kafka.session.timeout.ms", "10000") \
    .option("kafka.heartbeat.interval.ms", "3000") \
    .option("kafka.max.poll.records", "500") \
    .load()

# Parse Kafka message
parsed_df = kafka_df.select(
    from_json(col("value").cast("string"), conn_schema).alias("data")
).select("data.*")

# Debug: Print schema after parsing
logger.info("Schema of parsed_df:")
parsed_df.printSchema()

# Transform ts to timestamp and decompose
enriched_df = parsed_df \
    .withColumn("timestamp", to_timestamp(from_unixtime(col("ts"), 'yyyy-MM-dd HH:mm:ss.SSSSSS'))) \
    .withColumn("year", year(col("timestamp"))) \
    .withColumn("month", month(col("timestamp"))) \
    .withColumn("day", dayofmonth(col("timestamp"))) \
    .withColumn("hour", hour(col("timestamp"))) \
    .withColumn("minute", minute(col("timestamp"))) \
    .withColumn("second", second(col("timestamp")))

# Debug: Print schema after enrichment
logger.info("Schema of enriched_df:")
enriched_df.printSchema()

# Select relevant columns
final_df = enriched_df.select(
    col("year"),
    col("month"),
    col("day"),
    col("hour"),
    col("minute"),
    col("second"),
    col("timestamp"),
    col("`id.orig_h`").alias("id_orig_h"),
    col("`id.orig_p`").alias("id_orig_p"),
    col("`id.resp_h`").alias("id_resp_h"),
    col("`id.resp_p`").alias("id_resp_p"),
    col("proto"),
    col("service"),
    col("duration"),
    col("orig_bytes"),
    col("resp_bytes"),
    col("conn_state"),
    col("orig_pkts"),
    col("orig_ip_bytes"),
    col("resp_pkts"),
    col("resp_ip_bytes"),
    col("hostname"),
    col("vm_id")
)

# Debug: Print schema of final_df
logger.info("Schema of final_df:")
final_df.printSchema()

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
    "dbtable": "ZEEK_CONN"
}

# Write to Snowflake and console
def write_to_snowflake(batch_df, batch_id):
    logger.info(f"Processing batch {batch_id} with {batch_df.count()} records")
    if batch_df.count() > 0:
        # Show output in console
        batch_df.show(truncate=False)
        # Write to Snowflake
        try:
            batch_df.write \
                .format("snowflake") \
                .options(**snowflake_options) \
                .option("dbtable", "ZEEK_CONN") \
                .option("sfOnError", "CONTINUE") \
                .mode("append") \
                .save()
            logger.info(f"Successfully wrote batch {batch_id} to Snowflake")
        except Exception as e:
            logger.error(f"Failed to write batch {batch_id} to Snowflake: {e}")
    else:
        logger.info("No records in batch")

# Write stream to Snowflake and console
query = final_df.writeStream \
    .outputMode("append") \
    .trigger(processingTime="10 seconds") \
    .foreachBatch(write_to_snowflake) \
    .start()

try:
    query.awaitTermination()
except Exception as e:
    logger.error(f"Streaming query failed: {e}")
finally:
    spark.stop()