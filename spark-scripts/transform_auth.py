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

# Load environment variables
load_dotenv()

# Initialize Spark session with explicit configurations
spark = None
try:
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
        .appName("AuthToSnowflake") \
        .config("spark.dynamicAllocation.enabled", "true") \
        .config("spark.ui.port", "4058") \
        .config("spark.jars", ",".join(spark_jars)) \
        .config("spark.executor.heartbeatInterval", "60s") \
        .config("spark.network.timeout", "120s") \
        .config("spark.sql.streaming.kafka.useDeprecatedOffsetFetching", "false") \
        .config("spark.sql.streaming.minBatchesToRetain", "10") \
        .getOrCreate()
    logger.info("Spark session initialized successfully")
except Exception as e:
    logger.error(f"Failed to initialize Spark session: {e}")
    raise

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
        return [None, None, None]
    except Exception as e:
        logger.error(f"Error during GeoIP lookup for IP {ip}: {e}")
        return [None, None, None]

# Register UDF
get_geolocation_udf = spark.udf.register("get_geolocation", get_geolocation, ArrayType(StringType()))

# Kafka message schema
kafka_message_schema = StructType([
    StructField("message", StringType(), True),
    StructField("hostname", StringType(), True),
    StructField("vm_id", StringType(), True)
])

# Read from Kafka with enhanced options
try:
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
        .option("failOnDataLoss", "false") \
        .load()
    logger.info("Kafka stream initialized successfully")
except Exception as e:
    logger.error(f"Failed to initialize Kafka stream: {e}")
    raise

# Parse Kafka message
parsed_df = kafka_df.select(
    from_json(col("value").cast("string"), kafka_message_schema).alias("data")
).select(
    col("data.message"),
    col("data.hostname"),
    col("data.vm_id")
)

# --- AUTH LOG PARSING AND ENRICHMENT ---

# Updated syslog regex pattern
syslog_pattern = r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+\+\d{2}:\d{2})\s+(\S+)\s+([^\s\[\]:]+(?:\[[\d\w-]+\]|\(\w+\))?)?(?:\[(\d+)\])?:?\s+(.*)$"

# Extract syslog fields
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
        "process_info_normalized",
        regexp_replace(regexp_extract(col("message"), syslog_pattern, 3), r"[\[\]\(\)]", "")
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

# Updated regex patterns
sudo_pattern = r"^\s*(\S+)\s*:\s*(?:TTY=(\S+);\s*PWD=([^;]+);\s*USER=(\S+);\s*COMMAND=(.+)|3 incorrect password attempts.*COMMAND=(.+))$"
sudo_auth_failure_pattern = r"^pam_unix\(sudo:auth\): (?:conversation failed|auth could not identify password for \[(\S+)\]|authentication failure.*user=(\S+))"
su_pattern = r"^\(to (\S+)\)\s+(\S+)\s+on\s+(\S+)$"
cron_session_pattern = r"^pam_unix\(cron:session\): session (opened|closed) for user (\S+)(?:\(uid=\d+\))? by (\S+)?(?:\(uid=\d+\))?"

# SSHD regex patterns
sshd_accepted_pattern = r"Accepted password for (\S+) from ([\d\.]+) port (\d+)"
sshd_failed_pattern = r"Failed password for (\S+) from ([\d\.]+) port (\d+)"
sshd_publickey_pattern = r"Accepted publickey for (\S+) from ([\d\.]+) port (\d+)"
logind_new_session_pattern = r"New session (\S+) of user (\S+)"
logind_session_logout_pattern = r"User (\S+) logged out"
logind_removed_session_pattern = r"Removed session (\S+)\."

# Updated event type and field extraction
enriched_df = extracted_df \
    .withColumn(
        "event_type",
        when(col("process_info_normalized") == "sudo",
            when(col("log_message_content").rlike(sudo_pattern), "sudo_command") \
            .when(col("log_message_content").rlike(sudo_auth_failure_pattern), "sudo_auth_failure") \
            .when(col("log_message_content").contains("pam_unix(sudo:session)"), "sudo_session") \
            .otherwise("sudo_other")
        ) \
        .when(col("process_info_normalized") == "CRON", "cron_session") \
        .when(col("process_info_normalized").isin("gdm-password", "gdm-launch-environment"), "gdm_auth") \
        .when(col("process_info_normalized") == "sshd",
            when(col("log_message_content").contains("Accepted password"), "sshd_login_success") \
            .when(col("log_message_content").contains("Failed password"), "sshd_login_fail") \
            .when(col("log_message_content").contains("Accepted publickey"), "sshd_login_success_pubkey") \
            .otherwise("sshd_other")
        ) \
        .when(col("process_info_normalized") == "systemd-logind",
            when(col("log_message_content").contains("New session"), "logind_new_session") \
            .when(col("log_message_content").contains("logged out"), "logind_session_logout") \
            .when(col("log_message_content").contains("Removed session"), "logind_session_removed") \
            .otherwise("logind_other")
        ) \
        .when(col("process_info_normalized") == "su", "su_session") \
        .when(col("process_info_normalized") == "unix_chkpwd", "auth_failure") \
        .when(col("process_info_normalized") == "polkitd", "polkitd_event") \
        .otherwise("other")
    ) \
    .withColumn(
        "sudo_user",
        when(col("event_type") == "sudo_command", regexp_extract(col("log_message_content"), sudo_pattern, 1)) \
        .when(col("event_type") == "sudo_auth_failure", 
              when(regexp_extract(col("log_message_content"), sudo_auth_failure_pattern, 1) != "", 
                   regexp_extract(col("log_message_content"), sudo_auth_failure_pattern, 1)
              ).otherwise(regexp_extract(col("log_message_content"), sudo_auth_failure_pattern, 2))
        ) \
        .when(col("event_type") == "sudo_session", regexp_extract(col("log_message_content"), r"session (opened|closed) for user (\S+)", 2)) \
        .otherwise(None)
    ) \
    .withColumn(
        "sudo_tty",
        when(col("event_type") == "sudo_command", regexp_extract(col("log_message_content"), sudo_pattern, 2)).otherwise(None)
    ) \
    .withColumn(
        "sudo_pwd",
        when(col("event_type") == "sudo_command", regexp_extract(col("log_message_content"), sudo_pattern, 3)).otherwise(None)
    ) \
    .withColumn(
        "sudo_target_user",
        when(col("event_type") == "sudo_command", regexp_extract(col("log_message_content"), sudo_pattern, 4)).otherwise(None)
    ) \
    .withColumn(
        "sudo_command",
        when(col("event_type") == "sudo_command", 
             when(regexp_extract(col("log_message_content"), sudo_pattern, 5) != "", 
                  regexp_extract(col("log_message_content"), sudo_pattern, 5)
             ).otherwise(regexp_extract(col("log_message_content"), sudo_pattern, 6))
        ).otherwise(None)
    ) \
    .withColumn(
        "sudo_session_status",
        when(col("event_type") == "sudo_session", 
             regexp_extract(col("log_message_content"), r"session (opened|closed)", 1)
        ).otherwise(None)
    ) \
    .withColumn(
        "cron_user",
        when(col("event_type") == "cron_session", regexp_extract(col("log_message_content"), cron_session_pattern, 2)).otherwise(None)
    ) \
    .withColumn(
        "cron_session_status",
        when(col("event_type") == "cron_session", regexp_extract(col("log_message_content"), cron_session_pattern, 1)).otherwise(None)
    ) \
    .withColumn(
        "cron_by_user",
        when(col("event_type") == "cron_session", regexp_extract(col("log_message_content"), cron_session_pattern, 3)).otherwise(None)
    ) \
    .withColumn(
        "sshd_user",
        when(col("event_type") == "sshd_login_success", regexp_extract(col("log_message_content"), sshd_accepted_pattern, 1)) \
        .when(col("event_type") == "sshd_login_fail", regexp_extract(col("log_message_content"), sshd_failed_pattern, 1)) \
        .when(col("event_type") == "sshd_login_success_pubkey", regexp_extract(col("log_message_content"), sshd_publickey_pattern, 1)) \
        .otherwise(None)
    ) \
    .withColumn(
        "sshd_src_ip",
        when(col("event_type") == "sshd_login_success", regexp_extract(col("log_message_content"), sshd_accepted_pattern, 2)) \
        .when(col("event_type") == "sshd_login_fail", regexp_extract(col("log_message_content"), sshd_failed_pattern, 2)) \
        .when(col("event_type") == "sshd_login_success_pubkey", regexp_extract(col("log_message_content"), sshd_publickey_pattern, 2)) \
        .otherwise(None)
    ) \
    .withColumn(
        "sshd_port",
        when(col("event_type") == "sshd_login_success", regexp_extract(col("log_message_content"), sshd_accepted_pattern, 3)) \
        .when(col("event_type") == "sshd_login_fail", regexp_extract(col("log_message_content"), sshd_failed_pattern, 3)) \
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
        "su_target_user",
        when(col("event_type") == "su_session", regexp_extract(col("log_message_content"), su_pattern, 1)).otherwise(None)
    ) \
    .withColumn(
        "su_user",
        when(col("event_type") == "su_session", regexp_extract(col("log_message_content"), su_pattern, 2)).otherwise(None)
    ) \
    .withColumn(
        "su_tty",
        when(col("event_type") == "su_session", regexp_extract(col("log_message_content"), su_pattern, 3)).otherwise(None)
    ) \
    .withColumn(
        "src_ip_address",
        col("sshd_src_ip")
    ) \
    .withColumn(
        "geo_data",
        when(col("src_ip_address").isNotNull(), get_geolocation_udf(col("src_ip_address"))).otherwise(lit(None))
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
# Update final_auth_df to include new columns
final_auth_df = enriched_df.select(
    col("log_timestamp").alias("timestamp"),
    col("year"),
    col("month"),
    col("day"),
    col("hour"),
    col("minute"),
    col("second"),
    col("hostname"),
    col("vm_id"),
    col("process_info").alias("process_name"),
    col("pid"),
    col("event_type"),
    col("message").alias("raw_message"),
    col("sudo_user"),
    col("sudo_tty"),
    col("sudo_pwd"),
    col("sudo_target_user"),
    col("sudo_command"),
    col("sudo_session_status"),
    col("cron_user"),
    col("cron_session_status"),
    col("cron_by_user"),
    col("sshd_user"),
    col("sshd_src_ip"),
    col("sshd_port"),
    col("sshd_auth_method"),
    col("sshd_success"),
    col("logind_session_id"),
    col("logind_user").alias("logind_session_user"),
    col("logind_session_status"),
    col("su_target_user"),
    col("su_user"),
    col("su_tty"),
    col("src_latitude"),
    col("src_longitude"),
    col("src_city")
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

# Write to Snowflake
def write_to_snowflake(batch_df, batch_id):
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
            batch_df.show(truncate=False)
        except Exception as e:
            logger.error(f"Failed to write batch {batch_id}: {e}")
    else:
        logger.info(f"Batch {batch_id} is empty")

# Start the streaming query
query = None
try:
    query = final_auth_df.writeStream \
        .outputMode("append") \
        .trigger(processingTime="10 seconds") \
        .foreachBatch(write_to_snowflake) \
        .start()
    logger.info("Streaming query started successfully")
except Exception as e:
    logger.error(f"Failed to start streaming query: {e}")
    raise

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
    if spark is not None:
        spark.stop()