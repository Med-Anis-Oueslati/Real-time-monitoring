import logging
from pyspark.sql import SparkSession
from pyspark.sql.functions import col, from_json, to_timestamp, year, month, dayofmonth, hour, minute, second, regexp_extract, when, lit, regexp_replace
from pyspark.sql.types import StructType, StructField, StringType, ArrayType, BooleanType
import geoip2.database
from dotenv import load_dotenv
import os

# Initialize logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s: %(message)s')
logger = logging.getLogger(__name__)

# Load environment variables from .env file
load_dotenv()

# Initialize Spark session with explicit configurations
spark = None
try:
    # Define Spark JARs required for Kafka and Snowflake connectivity
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
    # Configure Spark session with dynamic allocation and specified JARs
    spark = SparkSession.builder \
        .appName("AuthToSnowflake") \
        .config("spark.dynamicAllocation.enabled", "true") \
        .config("spark.ui.port", "4058") \
        .getOrCreate()
    logger.info("Spark session initialized successfully")
except Exception as e:
    logger.error(f"Failed to initialize Spark session: {e}")
    # Re-raise the exception to stop execution if Spark session fails
    raise

# Broadcast GeoLite2 database path for efficient access across Spark executors
# Note: Geolocation enrichment is not used in the simplified output schema,
# but the setup remains in case it's needed for future extensions.
geoip_db_path = "/opt/spark/GeoLite2-City.mmdb"
if not os.path.exists(geoip_db_path):
    logger.warning(f"GeoLite2 database not found at {geoip_db_path}. Geolocation enrichment will be skipped.")
    broadcast_geoip_db_path = None
else:
    broadcast_geoip_db_path = spark.sparkContext.broadcast(geoip_db_path)

# Singleton for GeoIP Reader to avoid re-initializing for each lookup
class GeoIPReaderSingleton:
    _instance = None

    @staticmethod
    def get_instance(path):
        """Returns a singleton instance of the GeoIP2 database reader."""
        if GeoIPReaderSingleton._instance is None:
            GeoIPReaderSingleton._instance = geoip2.database.Reader(path)
        return GeoIPReaderSingleton._instance

# Geolocation lookup function using the broadcasted database path
def get_geolocation(ip):
    """
    Performs a geolocation lookup for a given IP address.
    Returns a list containing latitude, longitude, and city name.
    Handles private IPs and lookup errors gracefully.
    """
    if broadcast_geoip_db_path is None:
        return [None, None, None]
    try:
        # Skip lookup for private IP ranges
        if not ip or ip.startswith(("192.168.", "10.", "172.16.", "127.")):
            return [None, None, None]
        reader = GeoIPReaderSingleton.get_instance(broadcast_geoip_db_path.value)
        response = reader.city(ip)
        return [
            str(response.location.latitude) if response.location.latitude is not None else None,
            str(response.location.longitude) if response.location.longitude is not None else None,
            response.city.name if response.city.name is not None else None
        ]
    except geoip2.errors.AddressNotFoundError:
        # IP address not found in the database
        return [None, None, None]
    except Exception as e:
        logger.error(f"Error during GeoIP lookup for IP {ip}: {e}")
        return [None, None, None]

# Register UDF (User Defined Function) for geolocation lookup
get_geolocation_udf = spark.udf.register("get_geolocation", get_geolocation, ArrayType(StringType()))

# Kafka message schema for incoming JSON data
kafka_message_schema = StructType([
    StructField("message", StringType(), True),
    StructField("hostname", StringType(), True),
    StructField("vm_id", StringType(), True)
])

# Read from Kafka with enhanced options for streaming

kafka_df = spark \
    .readStream \
    .format("kafka") \
    .option("kafka.bootstrap.servers", "kafka:9092") \
    .option("subscribe", "lubuntu_auth") \
    .option("startingOffsets", "latest") \
    .option("kafka.group.id", "lubuntu_auth_group") \
    .option("kafka.session.timeout.ms", "10000") \
    .option("kafka.heartbeat.interval.ms", "3000") \
    .option("kafka.max.poll.records", "500") \
    .load()


# Parse Kafka message value (JSON string) into structured columns
parsed_df = kafka_df.select(
    from_json(col("value").cast("string"), kafka_message_schema).alias("data")
).select(
    col("data.message"),
    col("data.hostname"),
    col("data.vm_id")
)

# --- AUTH LOG PARSING AND ENRICHMENT ---

# Syslog regex pattern to extract timestamp, hostname, process info, PID, and message content
# Group 1: Timestamp (e.g., 2025-05-30T11:44:34.439856+01:00)
# Group 2: Hostname (e.g., kali)
# Group 3: Process Info (e.g., sudo, systemd-logind[530], CRON[9792]) - Matches up to the first colon
# Group 4: PID (optional)
# Group 5: Log Message Content (the rest of the message)
syslog_pattern = r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+\+\d{2}:\d{2})\s+(\S+)\s+([^\s\[\]:]+(?:\[[\d\w-]+\]|\(\w+\))?)?(?:\[(\d+)\])?:?\s+(.*)$"

# Extract syslog fields using the defined pattern
extracted_df = parsed_df \
    .withColumn(
        "log_timestamp_str",
        regexp_extract(col("message"), syslog_pattern, 1)
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
    ) \
    .withColumn(
        # Normalize process_info by removing brackets/parentheses for easier comparison
        "process_info_normalized",
        regexp_replace(regexp_extract(col("message"), syslog_pattern, 3), r"[\[\]\(\)]", "")
    )

# Convert log_timestamp_str to a proper timestamp type
extracted_df = extracted_df.withColumn(
    "log_timestamp",
    to_timestamp(col("log_timestamp_str"), "yyyy-MM-dd'T'HH:mm:ss.SSSSSSXXX")
)

# Decompose timestamp into separate year, month, day, hour, minute, second columns
extracted_df = extracted_df \
    .withColumn("year", year(col("log_timestamp"))) \
    .withColumn("month", month(col("log_timestamp"))) \
    .withColumn("day", dayofmonth(col("log_timestamp"))) \
    .withColumn("hour", hour(col("log_timestamp"))) \
    .withColumn("minute", minute(col("log_timestamp"))) \
    .withColumn("second", second(col("log_timestamp")))

# --- Define specific regex patterns for SSHD-related log event types ---

# SSHD patterns
sshd_accepted_pattern = r"Accepted password for (\S+) from ([\d\.]+) port (\d+)"
sshd_failed_password_pattern = r"Failed password for (\S+) from ([\d\.]+) port (\d+)"
sshd_publickey_pattern = r"Accepted publickey for (\S+) from ([\d\.]+) port (\d+)"
# Patterns for various SSHD brute force attempts messages
sshd_max_attempts_pattern = r"error: maximum authentication attempts exceeded for (\S+) from ([\d\.]+) port (\d+)"
sshd_disconnect_fail_pattern = r"Disconnecting authenticating user (\S+) ([\d\.]+) port (\d+): Too many authentication failures"
sshd_pam_auth_fail_pattern = r"pam_unix\(sshd:auth\): authentication failure;.*rhost=([\d\.]+)\s+user=(\S+)"


# Enrich the DataFrame with event types and extracted fields, focusing only on SSHD
enriched_df = extracted_df \
    .withColumn(
        "event_type",
        when(col("process_info_normalized") == "sshd",
            when(col("log_message_content").contains("Accepted password"), "sshd_login_success") \
            .when(col("log_message_content").contains("Accepted publickey"), "sshd_login_success_pubkey") \
            # Classify various failed SSH attempts under a single event_type for simplicity
            .when(col("log_message_content").contains("Failed password"), "sshd_login_fail") \
            .when(col("log_message_content").contains("maximum authentication attempts exceeded"), "sshd_login_fail") \
            .when(col("log_message_content").contains("Disconnecting authenticating user") & col("log_message_content").contains("Too many authentication failures"), "sshd_login_fail") \
            .when(col("log_message_content").contains("pam_unix(sshd:auth): authentication failure"), "sshd_login_fail") \
            .otherwise("sshd_other")
        ) \
        .otherwise("other") # All non-sshd logs are classified as "other"
    ) \
    .withColumn(
        "sshd_user",
        when(col("event_type") == "sshd_login_success", regexp_extract(col("log_message_content"), sshd_accepted_pattern, 1)) \
        .when(col("event_type") == "sshd_login_fail",
              # Extract user from various failed SSH messages
              when(col("log_message_content").rlike(sshd_failed_password_pattern), regexp_extract(col("log_message_content"), sshd_failed_password_pattern, 1)) \
              .when(col("log_message_content").rlike(sshd_max_attempts_pattern), regexp_extract(col("log_message_content"), sshd_max_attempts_pattern, 1)) \
              .when(col("log_message_content").rlike(sshd_disconnect_fail_pattern), regexp_extract(col("log_message_content"), sshd_disconnect_fail_pattern, 1)) \
              .when(col("log_message_content").rlike(sshd_pam_auth_fail_pattern), regexp_extract(col("log_message_content"), sshd_pam_auth_fail_pattern, 2)) \
              .otherwise(None)
        ) \
        .when(col("event_type") == "sshd_login_success_pubkey", regexp_extract(col("log_message_content"), sshd_publickey_pattern, 1)) \
        .otherwise(None)
    ) \
    .withColumn(
        "sshd_src_ip",
        when(col("event_type") == "sshd_login_success", regexp_extract(col("log_message_content"), sshd_accepted_pattern, 2)) \
        .when(col("event_type") == "sshd_login_fail",
              # Extract source IP from various failed SSH messages
              when(col("log_message_content").rlike(sshd_failed_password_pattern), regexp_extract(col("log_message_content"), sshd_failed_password_pattern, 2)) \
              .when(col("log_message_content").rlike(sshd_max_attempts_pattern), regexp_extract(col("log_message_content"), sshd_max_attempts_pattern, 2)) \
              .when(col("log_message_content").rlike(sshd_disconnect_fail_pattern), regexp_extract(col("log_message_content"), sshd_disconnect_fail_pattern, 2)) \
              .when(col("log_message_content").rlike(sshd_pam_auth_fail_pattern), regexp_extract(col("log_message_content"), sshd_pam_auth_fail_pattern, 1)) \
              .otherwise(None)
        ) \
        .when(col("event_type") == "sshd_login_success_pubkey", regexp_extract(col("log_message_content"), sshd_publickey_pattern, 2)) \
        .otherwise(None)
    ) \
    .withColumn(
        "sshd_port",
        when(col("event_type") == "sshd_login_success", regexp_extract(col("log_message_content"), sshd_accepted_pattern, 3)) \
        .when(col("event_type") == "sshd_login_fail",
              # Extract port from various failed SSH messages (PAM auth failure logs don't contain port)
              when(col("log_message_content").rlike(sshd_failed_password_pattern), regexp_extract(col("log_message_content"), sshd_failed_password_pattern, 3)) \
              .when(col("log_message_content").rlike(sshd_max_attempts_pattern), regexp_extract(col("log_message_content"), sshd_max_attempts_pattern, 3)) \
              .when(col("log_message_content").rlike(sshd_disconnect_fail_pattern), regexp_extract(col("log_message_content"), sshd_disconnect_fail_pattern, 3)) \
              .otherwise(None) # For PAM auth failure logs, port is not in the message
        ) \
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
        when(col("event_type").contains("sshd_login_success"), lit(True)) \
        .when(col("event_type") == "sshd_login_fail", lit(False)) \
        .otherwise(lit(None)) # Use lit(None) for explicit null boolean
    ) \
    .withColumn(
        # Source IP for geolocation, currently only from SSHD logs
        "src_ip_address",
        col("sshd_src_ip")
    ) \
    .withColumn(
        # Apply geolocation UDF if src_ip_address is available
        "geo_data",
        when(col("src_ip_address").isNotNull(), get_geolocation_udf(col("src_ip_address"))).otherwise(lit(None).cast(ArrayType(StringType()))) # Explicitly cast lit(None) to ArrayType(StringType())
    ) \
    .withColumn(
        "src_latitude",
        when(col("geo_data").isNotNull(), col("geo_data")[0]).otherwise(None)
    ) \
    .withColumn(
        "src_longitude",
        when(col("geo_data").isNotNull(), col("geo_data")[1]).otherwise(None)
    ) \
    .withColumn(
        "src_city",
        when(col("geo_data").isNotNull(), col("geo_data")[2]).otherwise(None)
    )

# Select and rename final columns to match Snowflake table schema, focusing on SSH brute force
final_auth_df = enriched_df.filter(col("event_type") == "sshd_login_fail").select(
    col("log_timestamp").alias("timestamp"),
    col("hostname"),
    col("vm_id"),
    col("event_type"),
    col("message").alias("raw_message"),
    col("sshd_src_ip").alias("source_ip"), # Renamed for clarity
    col("sshd_port").alias("source_port")  # Renamed for clarity
)

# Snowflake connection options, loaded from environment variables
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

# Function to write each micro-batch to Snowflake
def write_to_snowflake(batch_df, batch_id):
    """
    Writes a Spark DataFrame batch to Snowflake.
    Logs the number of rows being written and handles potential write errors.
    """
    # Show the batch DataFrame before any filtering to inspect raw Kafka data
    logger.info(f"--- Batch {batch_id} (Before Filtering) ---")
    batch_df.show(truncate=False)

    # Apply the filter to get only SSHD login failures
    # Note: enriched_df is created outside this function, so we need to ensure
    # that the batch_df passed here is the one that has been enriched.
    # For a foreachBatch sink, batch_df is already the result of the stream's transformations.
    # So, we need to apply the filter and select columns again if we want to show intermediate steps.
    # However, for debugging, it's more effective to inspect the 'enriched_df' itself
    # before the final filter that creates 'final_auth_df'.
    # Since 'enriched_df' is a transformation on the stream, it's not directly available
    # inside foreachBatch as 'batch_df' is already the result of 'final_auth_df'.

    # To truly debug, we need to inspect the DataFrame *before* the final_auth_df.filter()
    # This means moving the filter inside the foreachBatch or making the filtering part of the stream.
    # Given the current structure where final_auth_df is the stream, batch_df *is* the result
    # of the filter. So, if batch_df is empty, it means the filter already removed everything.

    # Let's revert to a more direct debugging approach:
    # If the batch_df is empty, it means the filter in the main stream definition is too strict.
    # We need to see what 'enriched_df' looks like before that filter.
    # The current setup passes 'final_auth_df' (which is already filtered) to write_to_snowflake.
    # So, if batch_df is empty here, the problem is upstream.

    # To properly debug the 'enriched_df' state, we would need to restructure the stream
    # or add a separate sink for debugging purposes.
    # For now, let's assume 'batch_df' here is already the result of 'final_auth_df'.

    if batch_df.count() > 0:
        logger.info(f"Writing batch {batch_id} with {batch_df.count()} rows to Snowflake")
        try:
            batch_df.write \
                .format("snowflake") \
                .options(**snowflake_options) \
                .option("dbtable", "AUTH_LOGS") \
                .option("sfFileFormatOptions", "error_on_column_count_mismatch=false") \
                .mode("append") \
                .save()
            logger.info(f"--- Data written to Snowflake for batch {batch_id} ---")
            batch_df.show(truncate=False) # Show data that was actually written
        except Exception as e:
            logger.error(f"Failed to write batch {batch_id} to Snowflake: {e}")
    else:
        logger.info(f"Batch {batch_id} is empty after filtering, skipping write to Snowflake.")

# Start the streaming query to process data and write to Snowflake
query = None
try:
    query = final_auth_df.writeStream \
        .outputMode("append") \
        .trigger(processingTime="10 seconds") \
        .foreachBatch(write_to_snowflake) \
        .start()
    logger.info("Streaming query started successfully.")
except Exception as e:
    logger.error(f"Failed to start streaming query: {e}")
    raise

# Await termination of the streaming query, handling shutdown signals
try:
    query.awaitTermination()
except KeyboardInterrupt:
    logger.info("Shutdown signal received (KeyboardInterrupt), terminating stream gracefully.")
    query.stop()
except Exception as e:
    logger.error(f"Streaming query failed unexpectedly: {e}")
    query.stop()
finally:
    logger.info("Spark session stopped.")
    if spark is not None:
        spark.stop()
