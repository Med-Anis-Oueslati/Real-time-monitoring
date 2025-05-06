from pyspark.sql import SparkSession
from pyspark.sql.functions import col, from_json, to_timestamp, year, month, dayofmonth, hour, minute, second, from_unixtime
from pyspark.sql.types import StructType, StructField, StringType, DoubleType, IntegerType, LongType, BooleanType
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
    "/opt/spark/jars/commons-pool2-2.11.1.jar"
]
spark = SparkSession.builder \
    .appName("ZeekConnTerminal") \
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

# Debug: Print schema and sample data after parsing
# Parse Kafka message
parsed_df = kafka_df.select(
    from_json(col("value").cast("string"), conn_schema).alias("data")
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

# Write to console
query = final_df.writeStream \
    .outputMode("append") \
    .trigger(processingTime="10 seconds") \
    .format("console") \
    .option("truncate", "false") \
    .start()

try:
    query.awaitTermination()
except Exception as e:
    logger.error(f"Streaming query failed: {e}")
finally:
    spark.stop()