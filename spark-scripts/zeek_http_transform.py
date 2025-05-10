from pyspark.sql import SparkSession
from pyspark.sql.functions import col, from_json, to_timestamp, year, month, dayofmonth, hour, minute, second, from_unixtime
from pyspark.sql.types import StructType, StructField, StringType, DoubleType, IntegerType, BooleanType, ArrayType
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
    "/opt/spark/jars/jackson-annotations-2.15.2.jar",
    "/opt/spark/jars/parquet-avro-1.12.3.jar",
    "/opt/spark/jars/parquet-hadoop-1.12.3.jar",
    "/opt/spark/jars/avro-1.11.3.jar"
]
spark = SparkSession.builder \
    .appName("ZeekHTTPToSnowflake") \
    .config("spark.dynamicAllocation.enabled", "true") \
    .config("spark.ui.port", "4053") \
    .getOrCreate()


# Define schema for zeek_http JSON
http_schema = StructType([
    StructField("ts", DoubleType(), True),
    StructField("uid", StringType(), True),
    StructField("id.orig_h", StringType(), True),
    StructField("id.orig_p", IntegerType(), True),
    StructField("id.resp_h", StringType(), True),
    StructField("id.resp_p", IntegerType(), True),
    StructField("trans_depth", IntegerType(), True),
    StructField("method", StringType(), True),
    StructField("host", StringType(), True),
    StructField("uri", StringType(), True),
    StructField("version", StringType(), True),
    StructField("user_agent", StringType(), True),
    StructField("request_body_len", IntegerType(), True),
    StructField("response_body_len", IntegerType(), True),
    StructField("status_code", IntegerType(), True),
    StructField("status_msg", StringType(), True),
    StructField("tags", ArrayType(StringType()), True),
    StructField("resp_fuids", ArrayType(StringType()), True),
    StructField("orig_fuids", ArrayType(StringType()), True),
    StructField("orig_mime_types", ArrayType(StringType()), True),
    StructField("resp_mime_types", ArrayType(StringType()), True),
    StructField("hostname", StringType(), True),
    StructField("vm_id", StringType(), True)
])

# Read from Kafka
kafka_df = spark \
    .readStream \
    .format("kafka") \
    .option("kafka.bootstrap.servers", "kafka:9092") \
    .option("subscribe", "zeek_http") \
    .option("startingOffsets", "latest") \
    .option("kafka.group.id", "zeek_http_group") \
    .option("kafka.session.timeout.ms", "10000") \
    .option("kafka.heartbeat.interval.ms", "3000") \
    .option("kafka.max.poll.records", "500") \
    .load()


# Parse Kafka message
parsed_df = kafka_df.select(
    from_json(col("value").cast("string"), http_schema).alias("data")
).select("data.*")


# Transform ts to timestamp and decompose
enriched_df = parsed_df \
    .withColumn("timestamp", to_timestamp(from_unixtime(col("ts"), 'yyyy-MM-dd HH:mm:ss.SSSSSS'))) \
    .withColumn("year", year(col("timestamp"))) \
    .withColumn("month", month(col("timestamp"))) \
    .withColumn("day", dayofmonth(col("timestamp"))) \
    .withColumn("hour", hour(col("timestamp"))) \
    .withColumn("minute", minute(col("timestamp"))) \
    .withColumn("second", second(col("timestamp")))

# Select relevant columns
final_df = enriched_df.select(
    col("year"),
    col("month"),
    col("day"),
    col("hour"),
    col("minute"),
    col("second"),
    col("timestamp"),
    col("uid"),
    col("`id.orig_h`").alias("id_orig_h"),
    col("`id.orig_p`").alias("id_orig_p"),
    col("`id.resp_h`").alias("id_resp_h"),
    col("`id.resp_p`").alias("id_resp_p"),
    col("trans_depth"),
    col("method"),
    col("host"),
    col("uri"),
    col("version"),
    col("user_agent"),
    col("request_body_len"),
    col("response_body_len"),
    col("status_code"),
    col("status_msg"),
    col("tags"),
    col("resp_fuids"),
    col("orig_fuids"),
    col("orig_mime_types"),
    col("resp_mime_types"),
    col("hostname"),
    col("vm_id")
)



# Snowflake connection options
snowflake_options = {
    "sfURL": os.getenv("SNOWFLAKE_URL"),
    "sfAccount": os.getenv("SNOWFLAKE_ACCOUNT"),
    "sfUser": os.getenv("SNOWFLAKE_USER"),
    "sfPassword": os.getenv("SNOWFLAKE_PASSWORD"),
    "sfDatabase": os.getenv("SNOWFLAKE_DATABASE"),
    "sfSchema": os.getenv("SNOWFLAKE_SCHEMA"),
    "sfWarehouse": os.getenv("SNOWFLAKE_WAREHOUSE"),
    "sfRole": os.getenv("SNOWFLAKE_ROLE")
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
                .option("dbtable", "ZEEK_HTTP") \
                .option("sfOnError", "CONTINUE") \
                .mode("append") \
                .save()
        except Exception as e:
            logger.error(f"Failed to write batch {batch_id} to Snowflake: {e}")
    else:
        logger.info("No records in batch")

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