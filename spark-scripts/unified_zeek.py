import sys
from pyspark.sql import SparkSession
from pyspark.sql.functions import (
    col, from_json, to_timestamp, from_unixtime, year, month, dayofmonth,
    hour, minute, second, lit, to_json, struct, sha2, concat_ws, when, current_timestamp
)
from pyspark.sql.types import ArrayType, StringType
from dotenv import load_dotenv
import geoip2.database
import logging
import os
from zeek_schemas import (
    capture_loss_schema, conn_schema, dns_schema,
    http_schema, notice_schema, ssl_schema
)
from threading import Lock
from pyspark.sql.functions import pandas_udf
from pandas import Series
from tenacity import retry, stop_after_attempt, wait_exponential
from pyspark.sql.streaming import StreamingQueryListener


# Initialize logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
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
    .appName("ZeekUnifiedToSnowflake") \
    .config("spark.dynamicAllocation.enabled", "true") \
    .config("spark.ui.port", "4050") \
    .config("spark.sql.shuffle.partitions", "400") \
    .config("spark.sql.adaptive.enabled", "true") \
    .config("spark.sql.streaming.minBatchesToRetain", "100") \
    .config("spark.streaming.kafka.maxOffsetsPerTrigger", "10000") \
    .getOrCreate()

# Adjust shuffle partitions dynamically
spark.conf.set("spark.sql.shuffle.partitions", spark.sparkContext.defaultParallelism * 2)

# Broadcast GeoLite2 database path
geoip_db_path = "/opt/spark/GeoLite2-City.mmdb"
if not os.path.exists(geoip_db_path):
    logger.error(f"GeoIP database not found at {geoip_db_path}. Please download from MaxMind.")
    sys.exit(1)
broadcast_geoip_db_path = spark.sparkContext.broadcast(geoip_db_path)

# Thread-safe GeoIP Reader Singleton (serialization-safe)
class GeoIPReaderSingleton:
    _instance = None
    _lock = None  # Initialize lock lazily to avoid pickling

    @staticmethod
    def _get_lock():
        if GeoIPReaderSingleton._lock is None:
            GeoIPReaderSingleton._lock = Lock()
        return GeoIPReaderSingleton._lock

    @staticmethod
    def get_instance(path):
        with GeoIPReaderSingleton._get_lock():
            if GeoIPReaderSingleton._instance is None:
                GeoIPReaderSingleton._instance = geoip2.database.Reader(path)
            return GeoIPReaderSingleton._instance

    def __getstate__(self):
        # Exclude _lock from serialization
        state = self.__dict__.copy()
        state['_lock'] = None
        return state

    def __setstate__(self, state):
        # Restore state without lock; it will be re-initialized if needed
        self.__dict__.update(state)

# Pandas UDF for GeoIP lookup
@pandas_udf(ArrayType(StringType()))
def get_geolocation(ip_series: Series) -> Series:
    reader = GeoIPReaderSingleton.get_instance(broadcast_geoip_db_path.value)
    def lookup(ip):
        try:
            if ip is None:
                return [None, None, None]
            response = reader.city(ip)
            return [str(response.location.latitude), str(response.location.longitude), response.city.name]
        except Exception:
            return [None, None, None]
    return ip_series.apply(lookup)

# Kafka topics and schemas
topics_schemas = {
    "zeek_capture_loss": capture_loss_schema,
    "zeek_conn": conn_schema,
    "zeek_dns": dns_schema,
    "zeek_http": http_schema,
    "zeek_notice": notice_schema,
    "zeek_ssl": ssl_schema
}

# Read from multiple Kafka topics
kafka_dfs = {}
for topic, schema in topics_schemas.items():
    kafka_df = spark \
        .readStream \
        .format("kafka") \
        .option("kafka.bootstrap.servers", "kafka:9092") \
        .option("subscribe", topic) \
        .option("startingOffsets", os.getenv("KAFKA_STARTING_OFFSETS", "latest")) \
        .option("kafka.group.id", f"{topic}_group") \
        .option("kafka.session.timeout.ms", "10000") \
        .option("kafka.heartbeat.interval.ms", "3000") \
        .option("kafka.max.poll.records", "500") \
        .option("kafka.partition.assignment.strategy", "cooperative-sticky") \
        .load()
    parsed_df = kafka_df.select(
        from_json(col("value").cast("string"), schema).alias("data"),
        lit(topic).alias("log_type")
    ).select("data.*", "log_type")
    if topic != "zeek_capture_loss":
        parsed_df = parsed_df \
            .withColumnRenamed("id.orig_h", "id_orig_h") \
            .withColumnRenamed("id.orig_p", "id_orig_p") \
            .withColumnRenamed("id.resp_h", "id_resp_h") \
            .withColumnRenamed("id.resp_p", "id_resp_p")
    if topic == "zeek_capture_loss":
        parsed_df = parsed_df.withColumn(
            "loss_severity",
            when(col("percent_lost") < 5, "Low")
            .when(col("percent_lost").between(5, 10), "Medium")
            .when(col("percent_lost") > 10, "High")
            .otherwise("Unknown")
        )
    logger.info(f"Schema for {topic}:")
    parsed_df.printSchema()
    kafka_dfs[topic] = parsed_df

# Union all DataFrames
union_df = None
for df in kafka_dfs.values():
    if union_df is None:
        union_df = df
    else:
        union_df = union_df.unionByName(df, allowMissingColumns=True)

logger.info("Schema after union:")
union_df.printSchema()

# Enrich with timestamp and geolocation, and add watermark
enriched_df = union_df \
    .withColumn("timestamp", to_timestamp(from_unixtime(col("ts"), 'yyyy-MM-dd HH:mm:ss.SSSSSS'))) \
    .withColumn("year", year(col("timestamp"))) \
    .withColumn("month", month(col("timestamp"))) \
    .withColumn("day", dayofmonth(col("timestamp"))) \
    .withColumn("hour", hour(col("timestamp"))) \
    .withColumn("minute", minute(col("timestamp"))) \
    .withColumn("second", second(col("timestamp"))) \
    .withColumn("orig_geo", when(col("id_orig_h").isNotNull(), get_geolocation(col("id_orig_h"))).otherwise(lit([None, None, None]))) \
    .withColumn("resp_geo", when(col("id_resp_h").isNotNull(), get_geolocation(col("id_resp_h"))).otherwise(lit([None, None, None]))) \
    .withWatermark("timestamp", "6 hours")

logger.info("Schema after enrichment:")
enriched_df.printSchema()

# Create dim_time DataFrame with deduplication
dim_time_df = enriched_df.select(
    col("timestamp"),
    col("year"),
    col("month"),
    col("day"),
    col("hour"),
    col("minute"),
    col("second")
).distinct() \
    .withColumn("time_id", sha2(col("timestamp").cast("string"), 256).cast("long")) \
    .withWatermark("timestamp", "6 hours")

# Create dim_host DataFrame with deduplication
dim_host_df = enriched_df.select(
    col("hostname"),
    col("vm_id")
).distinct() \
    .withColumn("host_id", sha2(concat_ws("||", col("hostname"), col("vm_id")), 256).cast("long"))

# Create dim_network_entity DataFrame
source_network_df = enriched_df.select(
    col("id_orig_h").alias("ip_address"),
    col("id_orig_p").alias("port"),
    lit(True).alias("is_source"),
    lit(False).alias("is_destination"),
    col("orig_geo")[0].alias("latitude"),
    col("orig_geo")[1].alias("longitude"),
    col("orig_geo")[2].alias("city")
).where(col("id_orig_h").isNotNull())

dest_network_df = enriched_df.select(
    col("id_resp_h").alias("ip_address"),
    col("id_resp_p").alias("port"),
    lit(False).alias("is_source"),
    lit(True).alias("is_destination"),
    col("resp_geo")[0].alias("latitude"),
    col("resp_geo")[1].alias("longitude"),
    col("resp_geo")[2].alias("city")
).where(col("id_resp_h").isNotNull())

dim_network_entity_df = source_network_df.union(dest_network_df).distinct() \
    .withColumn("network_entity_id", sha2(concat_ws("||", col("ip_address"), col("port").cast("string")), 256).cast("long"))

logger.info("Schema for dim_network_entity_df:")
dim_network_entity_df.printSchema()

# Create fact_zeek_events DataFrame
fact_zeek_events_df = enriched_df \
    .withColumn("event_data", to_json(struct([c for c in enriched_df.columns if c not in [
        "ts", "timestamp", "year", "month", "day", "hour", "minute", "second",
        "id_orig_h", "id_orig_p", "id_resp_h", "id_resp_p", "hostname", "vm_id",
        "log_type", "proto", "service", "uid", "orig_geo", "resp_geo"
    ]]))) \
    .select(
        col("timestamp"),
        col("hostname"),
        col("id_orig_h"), col("id_orig_p"),
        col("id_resp_h"), col("id_resp_p"),
        col("uid"),
        col("log_type"),
        col("proto"),
        col("service"),
        col("event_data")
    ).distinct()

logger.info("Schema for fact_zeek_events_df before joins:")
fact_zeek_events_df.printSchema()

# Simplified join with dimension tables
fact_zeek_events_df = fact_zeek_events_df.alias("fact") \
    .join(dim_time_df.alias("time"), ["timestamp"], "left") \
    .join(dim_host_df.alias("host"), ["hostname"], "left") \
    .select(
        col("time.time_id").alias("time_id"),
        col("host.host_id").alias("host_id"),
        col("fact.id_orig_h"),
        col("fact.id_orig_p"),
        col("fact.id_resp_h"),
        col("fact.id_resp_p"),
        col("fact.uid"),
        col("fact.log_type"),
        col("fact.proto"),
        col("fact.service"),
        col("fact.event_data"),
        col("fact.timestamp"),
        col("time.year"),
        col("time.month"),
        col("time.day")
    )

logger.info("Schema for fact_zeek_events_df after time and host joins:")
fact_zeek_events_df.printSchema()

# Join with source network entity
fact_zeek_events_df = fact_zeek_events_df \
    .join(dim_network_entity_df.alias("source"),
          (fact_zeek_events_df["id_orig_h"] == col("source.ip_address")) &
          (fact_zeek_events_df["id_orig_p"] == col("source.port")), "left") \
    .select(
        col("time_id"),
        col("host_id"),
        col("source.network_entity_id").alias("source_network_entity_id"),
        col("id_resp_h"),
        col("id_resp_p"),
        col("uid"),
        col("log_type"),
        col("proto"),
        col("service"),
        col("event_data"),
        col("timestamp"),
        col("year"),
        col("month"),
        col("day")
    )

logger.info("Schema for fact_zeek_events_df after source join:")
fact_zeek_events_df.printSchema()

# Join with destination network entity
fact_zeek_events_df = fact_zeek_events_df \
    .join(dim_network_entity_df.alias("dest"),
          (fact_zeek_events_df["id_resp_h"] == col("dest.ip_address")) &
          (fact_zeek_events_df["id_resp_p"] == col("dest.port")), "left") \
    .select(
        sha2(concat_ws("||", col("uid"), col("timestamp").cast("string"), col("log_type")), 256).cast("long").alias("event_id"),
        col("time_id"),
        col("host_id"),
        col("source_network_entity_id"),
        col("dest.network_entity_id").alias("dest_network_entity_id"),
        col("uid"),
        col("log_type"),
        col("proto"),
        col("service"),
        col("event_data"),
        col("year"),
        col("month"),
        col("day"),
        current_timestamp().alias("created_at")
    )

logger.info("Final schema for fact_zeek_events_df:")
fact_zeek_events_df.printSchema()

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

# Write to Snowflake with retry logic
@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
def write_to_snowflake(batch_df, batch_id, table_name):
    logger.info(f"Processing batch {batch_id} for {table_name} with {batch_df.count()} records")
    if batch_df.count() > 0:
        sample_df = batch_df.limit(5)
        logger.info(f"Sample records for batch {batch_id} in {table_name}:")
        sample_df.show(truncate=False)
        batch_df.write \
            .format("snowflake") \
            .options(**snowflake_options) \
            .option("dbtable", table_name) \
            .option("sfOnError", "CONTINUE") \
            .mode("append") \
            .save()
    else:
        logger.info(f"No records in batch {batch_id} for {table_name}")

# Streaming query listener for monitoring
class QueryMonitor(StreamingQueryListener):
    def onQueryStarted(self, event):
        logger.info(f"Query started: {event.id} - {event.name}")
    
    def onQueryProgress(self, event):
        progress = event.progress
        logger.info(f"Query {event.name}: {progress.numInputRows} rows processed, "
                    f"lag: {progress.endOffset - progress.startOffset}")
    
    def onQueryTerminated(self, event):
        if event.exception:
            logger.error(f"Query {event.id} terminated with exception: {event.exception}")
        else:
            logger.info(f"Query {event.id} terminated")
    
    def onQueryIdle(self, event):
        logger.info(f"Query {event.id} is idle")

spark.streams.addListener(QueryMonitor())

# Write dimension tables with checkpointing
dim_time_query = dim_time_df.writeStream \
    .outputMode("append") \
    .trigger(processingTime="10 seconds") \
    .option("checkpointLocation", "/mnt/spark-checkpoints/dim_time") \
    .foreachBatch(lambda df, id: write_to_snowflake(df, id, "DIM_TIME")) \
    .start()

dim_host_query = dim_host_df.writeStream \
    .outputMode("append") \
    .trigger(processingTime="10 seconds") \
    .option("checkpointLocation", "/mnt/spark-checkpoints/dim_host") \
    .foreachBatch(lambda df, id: write_to_snowflake(df, id, "DIM_HOST")) \
    .start()

dim_network_entity_query = dim_network_entity_df.writeStream \
    .outputMode("append") \
    .trigger(processingTime="10 seconds") \
    .option("checkpointLocation", "/mnt/spark-checkpoints/dim_network_entity") \
    .foreachBatch(lambda df, id: write_to_snowflake(df, id, "DIM_NETWORK_ENTITY")) \
    .start()

# Write fact table
fact_zeek_events_query = fact_zeek_events_df.writeStream \
    .outputMode("append") \
    .trigger(processingTime="10 seconds") \
    .option("checkpointLocation", "/mnt/spark-checkpoints/fact_zeek_events") \
    .foreachBatch(lambda df, id: write_to_snowflake(df, id, "FACT_ZEEK_EVENTS")) \
    .start()

try:
    spark.streams.awaitAnyTermination()
except Exception as e:
    logger.error(f"Streaming query failed: {e}")
finally:
    spark.stop()