# Initialize logging
import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

from pyspark.sql import SparkSession
from pyspark.sql.functions import col, split, udf, from_json, size, when, to_timestamp, year, month, dayofmonth, hour, minute, second, regexp_extract, array, concat_ws
from pyspark.sql.types import StructType, StructField, StringType, ArrayType
import geoip2.database
from dotenv import load_dotenv
import os

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
    .appName("AuthLogProcessing") \
    .config("spark.executor.memory", "4g") \
    .config("spark.executor.cores", "4") \
    .config("spark.driver.memory", "4g") \
    .config("spark.kafka.consumer.pollTimeoutMs", "60000") \
    .config("spark.streaming.stopGracefullyOnShutdown", "true") \
    .config("spark.dynamicAllocation.enabled", "false") \
    .config("spark.jars", ",".join(spark_jars)) \
    .getOrCreate()

# Broadcast GeoLite2 database path
geoip_db_path = "/opt/spark/GeoLite2-City.mmdb"
if not os.path.exists(geoip_db_path):
    logger.warning(f"GeoLite2 database not found at {geoip_db_path}. Geolocation enrichment will be skipped.")
    broadcast_geoip_db_path = None
else:
    broadcast_geoip_db_path = spark.sparkContext.broadcast(geoip_db_path)

# Singleton for GeoIP Reader
class GeoIPReaderSingleton:
    _instance = None

    @staticmethod
    def get_instance(path):
        if GeoIPReaderSingleton._instance is None:
            GeoIPReaderSingleton._instance = geoip2.database.Reader(path)
        return GeoIPReaderSingleton._instance

# Geolocation lookup function
def get_geolocation(ip):
    if broadcast_geoip_db_path is None:
        return [None, None, None]
    try:
        if not ip:
            return [None, None, None]
        reader = GeoIPReaderSingleton.get_instance(broadcast_geoip_db_path.value)
        response = reader.city(ip)
        return [
            str(response.location.latitude) if response.location.latitude is not None else None,
            str(response.location.longitude) if response.location.longitude is not None else None,
            response.city.name if response.city.name is not None else None
        ]
    except geoip2.errors.AddressNotFoundError:
        return [None, None, None]
    except Exception as e:
        logger.error(f"Error during GeoIP lookup for IP {ip}: {e}")
        return [None, None, None]

# Register UDF
get_geolocation_udf = spark.udf.register("get_geolocation", get_geolocation, ArrayType(StringType()))

# Kafka message schema
kafka_message_schema = StructType([StructField("message", StringType(), True)])

# Read from Kafka
kafka_df = spark \
    .readStream \
    .format("kafka") \
    .option("kafka.bootstrap.servers", "kafka:9092") \
    .option("subscribe", "lubuntu_auth") \
    .option("startingOffsets", "earliest") \
    .option("kafka.session.timeout.ms", "10000") \
    .option("kafka.heartbeat.interval.ms", "3000") \
    .option("kafka.max.poll.records", "500") \
    .load()

# Parse Kafka message
parsed_df = kafka_df.select(
    from_json(col("value").cast("string"), kafka_message_schema).alias("data")
).select("data.message")

# --- AUTH LOG PARSING AND ENRICHMENT ---

# Regex to split standard syslog fields
syslog_pattern = r"^(\S+)\s+(\S+)\s+([\w\-\.]+)(?:\[(\d+)\])?:?\s+(.*)$"

# Extract standard syslog fields
extracted_df = parsed_df \
    .withColumn(
        "log_timestamp_str",
        regexp_extract(col("message"), syslog_pattern, 1)
    ) \
    .withColumn(
        "hostname",
        regexp_extract(col("message"), syslog_pattern, 2)
    ) \
    .withColumn(
        "process_info",
        regexp_extract(col("message"), syslog_pattern, 3)
    ) \
    .withColumn(
        "pid",
        regexp_extract(col("message"), syslog_pattern, 4)
    ) \
    .withColumn(
        "log_message_content",
        regexp_extract(col("message"), syslog_pattern, 5)
    )

# Convert log_timestamp_str to timestamp
extracted_df = extracted_df.withColumn(
    "log_timestamp",
    to_timestamp(col("log_timestamp_str"), "yyyy-MM-dd'T'HH:mm:ss.SSSSSSXXX")
)

# Decompose timestamp
extracted_df = extracted_df \
    .withColumn("year", year(col("log_timestamp"))) \
    .withColumn("month", month(col("log_timestamp"))) \
    .withColumn("day", dayofmonth(col("log_timestamp"))) \
    .withColumn("hour", hour(col("log_timestamp"))) \
    .withColumn("minute", minute(col("log_timestamp"))) \
    .withColumn("second", second(col("log_timestamp")))

# --- Specific Log Type Parsing ---

# Define regex patterns
sudo_pattern = r"^\s*(\S+)\s*:\s*TTY=(\S+);\s*PWD=([^;]+);\s*USER=(\S+);\s*COMMAND=(.+)$"
sshd_accepted_pattern = r"^Accepted (\w+) for (\S+) from (\S+) port (\d+)"
sshd_failed_pattern = r"^Failed (\w+) for (\S+) from (\S+) port (\d+)"
sshd_publickey_pattern = r"^Accepted publickey for (\S+) from (\S+) port (\d+)"
logind_new_session_pattern = r"^New session (\S+) of user (\S+)\.$"
logind_session_logout_pattern = r"^Session (\S+) logged out\."
logind_removed_session_pattern = r"^Removed session (\S+)\.$"

# Apply parsing logic
enriched_df = extracted_df \
    .withColumn(
        "event_type",
        when(col("process_info") == "sudo", "sudo") \
        .when(col("process_info") == "sshd", 
            when(col("log_message_content").contains("Accepted password"), "sshd_login_success") \
            .when(col("log_message_content").contains("Failed password"), "sshd_login_fail") \
            .when(col("log_message_content").contains("Accepted publickey"), "sshd_login_success_pubkey") \
            .otherwise("other")
        ) \
        .when(col("process_info") == "systemd-logind", 
            when(col("log_message_content").contains("New session"), "logind_new_session") \
            .when(col("log_message_content").contains("logged out"), "logind_session_logout") \
            .when(col("log_message_content").contains("Removed session"), "logind_session_removed") \
            .otherwise("other")
        ) \
        .otherwise("other")
    ) \
    .withColumn(
        "sudo_user",
        when(col("event_type") == "sudo", regexp_extract(col("log_message_content"), sudo_pattern, 1)).otherwise(None)
    ) \
    .withColumn(
        "sudo_tty",
        when(col("event_type") == "sudo", regexp_extract(col("log_message_content"), sudo_pattern, 2)).otherwise(None)
    ) \
    .withColumn(
        "sudo_pwd",
        when(col("event_type") == "sudo", regexp_extract(col("log_message_content"), sudo_pattern, 3)).otherwise(None)
    ) \
    .withColumn(
        "sudo_target_user",
        when(col("event_type") == "sudo", regexp_extract(col("log_message_content"), sudo_pattern, 4)).otherwise(None)
    ) \
    .withColumn(
        "sudo_command",
        when(col("event_type") == "sudo", regexp_extract(col("log_message_content"), sudo_pattern, 5)).otherwise(None)
    ) \
    .withColumn(
        "sshd_user",
        when(col("event_type") == "sshd_login_success", regexp_extract(col("log_message_content"), sshd_accepted_pattern, 2)) \
        .when(col("event_type") == "sshd_login_fail", regexp_extract(col("log_message_content"), sshd_failed_pattern, 2)) \
        .when(col("event_type") == "sshd_login_success_pubkey", regexp_extract(col("log_message_content"), sshd_publickey_pattern, 1)) \
        .otherwise(None)
    ) \
    .withColumn(
        "sshd_src_ip",
        when(col("event_type") == "sshd_login_success", regexp_extract(col("log_message_content"), sshd_accepted_pattern, 3)) \
        .when(col("event_type") == "sshd_login_fail", regexp_extract(col("log_message_content"), sshd_failed_pattern, 3)) \
        .when(col("event_type") == "sshd_login_success_pubkey", regexp_extract(col("log_message_content"), sshd_publickey_pattern, 2)) \
        .otherwise(None)
    ) \
    .withColumn(
        "sshd_port",
        when(col("event_type") == "sshd_login_success", regexp_extract(col("log_message_content"), sshd_accepted_pattern, 4)) \
        .when(col("event_type") == "sshd_login_fail", regexp_extract(col("log_message_content"), sshd_failed_pattern, 4)) \
        .when(col("event_type") == "sshd_login_success_pubkey", regexp_extract(col("log_message_content"), sshd_publickey_pattern, 3)) \
        .otherwise(None)
    ) \
    .withColumn(
        "sshd_auth_method",
        when(col("event_type") == "sshd_login_success", "password") \
        .when(col("event_type") == "sshd_login_fail", "password") \
        .when(col("event_type") == "sshd_login_success_pubkey", "publickey") \
        .otherwise(None)
    ) \
    .withColumn(
        "sshd_success",
        when(col("event_type").contains("sshd_login_success"), True) \
        .when(col("event_type") == "sshd_login_fail", False) \
        .otherwise(None)
    ) \
    .withColumn(
        "logind_session_id",
        when(col("event_type") == "logind_new_session", regexp_extract(col("log_message_content"), logind_new_session_pattern, 1)) \
        .when(col("event_type") == "logind_session_logout", regexp_extract(col("log_message_content"), logind_session_logout_pattern, 1)) \
        .when(col("event_type") == "logind_session_removed", regexp_extract(col("log_message_content"), logind_removed_session_pattern, 1)) \
        .otherwise(None)
    ) \
    .withColumn(
        "logind_user",
        when(col("event_type") == "logind_new_session", regexp_extract(col("log_message_content"), logind_new_session_pattern, 2)) \
        .otherwise(None)
    ) \
    .withColumn(
        "logind_session_status",
        when(col("event_type") == "logind_new_session", "new") \
        .when(col("event_type") == "logind_session_logout", "logged_out") \
        .when(col("event_type") == "logind_session_removed", "removed") \
        .otherwise(None)
    ) \
    .withColumn(
        "src_ip_address",
        col("sshd_src_ip")
    )

# Apply geolocation lookup
if broadcast_geoip_db_path is not None:
    enriched_df = enriched_df.withColumn("src_geo", get_geolocation_udf(col("src_ip_address")))
    enriched_df = enriched_df \
        .withColumn("src_latitude", col("src_geo").getItem(0)) \
        .withColumn("src_longitude", col("src_geo").getItem(1)) \
        .withColumn("src_city", col("src_geo").getItem(2)) \
        .drop("src_geo")
else:
    enriched_df = enriched_df \
        .withColumn("src_latitude", None) \
        .withColumn("src_longitude", None) \
        .withColumn("src_city", None)
    logger.warning("Skipping geolocation enrichment due to missing database.")

# Select and rename final columns
final_auth_df = enriched_df.select(
    col("log_timestamp").alias("timestamp"),
    col("year"),
    col("month"),
    col("day"),
    col("hour"),
    col("minute"),
    col("second"),
    col("hostname"),
    col("process_info").alias("process_name"),
    col("pid"),
    col("event_type"),
    col("message").alias("raw_message"),
    col("sudo_user"),
    col("sudo_tty"),
    col("sudo_pwd"),
    col("sudo_target_user"),
    col("sudo_command"),
    col("sshd_user"),
    col("sshd_src_ip"),
    col("sshd_port"),
    col("sshd_auth_method"),
    col("sshd_success"),
    col("logind_session_id"),
    col("logind_user").alias("logind_session_user"),
    col("logind_session_status"),
    col("src_latitude"),
    col("src_longitude"),
    col("src_city")
)

# Load environment variables
load_dotenv()

# Define Snowflake connection options
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

# Write to Snowflake
def write_to_snowflake(batch_df, batch_id):
    logger.info(f"Writing batch {batch_id} with {batch_df.count()} rows to Snowflake")
    batch_df.write \
        .format("snowflake") \
        .options(**snowflake_options) \
        .option("dbtable", "AUTH_LOGS") \
        .option("sfFileFormatOptions", "error_on_column_count_mismatch=false") \
        .mode("append") \
        .save()
    batch_df.show()

# Start the streaming query
query = final_auth_df.writeStream \
    .outputMode("append") \
    .foreachBatch(write_to_snowflake) \
    .trigger(processingTime="10 seconds") \
    .start()

logger.info("Auth log streaming query started. Waiting for termination...")
try:
    query.awaitTermination()
except KeyboardInterrupt:
    logger.info("Shutdown signal received (KeyboardInterrupt), terminating stream gracefully.")
    query.stop()
except Exception as e:
    logger.error(f"Streaming query failed: {e}")
    query.stop()
finally:
    logger.info("Spark session stopped.")
    spark.stop()