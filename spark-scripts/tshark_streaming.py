from pyspark.sql import SparkSession
from pyspark.sql.functions import col, split, udf, from_json, size, when, to_timestamp, year, month, dayofmonth, hour, minute, second
from pyspark.sql.types import StructType, StructField, StringType, ArrayType
import geoip2.database
import logging

# Initialize logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Spark session (unchanged)
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
    .appName("LogProcessing") \
    .config("spark.executor.memory", "4g") \
    .config("spark.executor.cores", "4") \
    .config("spark.driver.memory", "4g") \
    .config("spark.kafka.consumer.pollTimeoutMs", "60000") \
    .config("spark.streaming.stopGracefullyOnShutdown", "true") \
    .config("spark.dynamicAllocation.enabled", "false") \
    .config("spark.jars", ",".join(spark_jars)) \
    .getOrCreate()

# Broadcast GeoLite2 database path (unchanged)
geoip_db_path = "/opt/spark/GeoLite2-City.mmdb"
broadcast_geoip_db_path = spark.sparkContext.broadcast(geoip_db_path)

# Singleton for GeoIP Reader (unchanged)
class GeoIPReaderSingleton:
    _instance = None

    @staticmethod
    def get_instance(path):
        if GeoIPReaderSingleton._instance is None:
            GeoIPReaderSingleton._instance = geoip2.database.Reader(path)
        return GeoIPReaderSingleton._instance

# Geolocation lookup function (unchanged)
def get_geolocation(ip):
    try:
        reader = GeoIPReaderSingleton.get_instance(broadcast_geoip_db_path.value)
        response = reader.city(ip)
        return [
            str(response.location.latitude),
            str(response.location.longitude),
            response.city.name
        ]
    except Exception as e:
        return [None, None, None]

# Register UDF (unchanged)
get_geolocation_udf = udf(get_geolocation, ArrayType(StringType()))

# Kafka message schema (unchanged)
kafka_message_schema = StructType([StructField("message", StringType(), True)])

# Read from Kafka (unchanged)
kafka_df = spark \
    .readStream \
    .format("kafka") \
    .option("kafka.bootstrap.servers", "kafka:9092") \
    .option("subscribe", "lubuntu_tshark") \
    .option("startingOffsets", "latest") \
    .option("kafka.session.timeout.ms", "10000") \
    .option("kafka.heartbeat.interval.ms", "3000") \
    .option("kafka.max.poll.records", "500") \
    .load()

# Parse Kafka message (unchanged)
parsed_df = kafka_df.select(
    from_json(col("value").cast("string"), kafka_message_schema).alias("data")
).select("data.message")

# Extract fields and enrich with geolocation (unchanged)
enriched_df = parsed_df \
    .withColumn("fields", split(col("message"), "\t")) \
    .filter(size(col("fields")) == 6) \
    .withColumn("src_geo", get_geolocation_udf(col("fields").getItem(1))) \
    .withColumn("dst_geo", get_geolocation_udf(col("fields").getItem(2))) \
    .select(
        col("fields").getItem(0).alias("frame_time"),
        col("fields").getItem(1).alias("ip_src"),
        col("fields").getItem(2).alias("ip_dst"),
        col("fields").getItem(3).alias("udp_port"),
        col("fields").getItem(4).alias("tcp_port"),
        col("fields").getItem(5).alias("ip_proto"),
        col("src_geo").getItem(0).alias("src_latitude"),
        col("src_geo").getItem(1).alias("src_longitude"),
        col("src_geo").getItem(2).alias("src_city"),
        col("dst_geo").getItem(0).alias("dst_latitude"),
        col("dst_geo").getItem(1).alias("dst_longitude"),
        col("dst_geo").getItem(2).alias("dst_city")
    )

# Convert frame_time to timestamp and decompose it
# Convert frame_time to timestamp
enriched_df = enriched_df.withColumn(
    "frame_time",
    to_timestamp(col("frame_time"), "MMM dd, yyyy HH:mm:ss.SSSSSSSSS z")
)
# Decompose frame_time into components
enriched_df = enriched_df \
    .withColumn("year", year(col("frame_time"))) \
    .withColumn("month", month(col("frame_time"))) \
    .withColumn("day", dayofmonth(col("frame_time"))) \
    .withColumn("hour", hour(col("frame_time"))) \
    .withColumn("minute", minute(col("frame_time"))) \
    .withColumn("second", second(col("frame_time")))

# Add port classification logic
def classify_traffic(tcp_ports, udp_ports):
    tcp_mappings = {
        "20": "FTP-DATA",
        "21": "FTP",
        "22": "SSH",
        "23": "TELNET",
        "25": "SMTP",
        "53": "DNS",
        "80": "HTTP",
        "110": "POP3",
        "143": "IMAP",
        "443": "HTTPS",
        "445": "SMB",
        "3389": "RDP",
        "8080": "HTTP-ALT",
        "8443": "HTTPS-ALT"
    }
    
    udp_mappings = {
        "53": "DNS",
        "67": "DHCP-SERVER",
        "68": "DHCP-CLIENT",
        "123": "NTP",
        "161": "SNMP",
        "162": "SNMP-TRAP",
        "137": "NETBIOS-NS",
        "138": "NETBIOS-DGM",
        "514": "SYSLOG"
    }
    
    primary_classification = "OTHER"
    
    try:
        # Handle None or empty inputs
        tcp_ports = [str(port) for port in (tcp_ports or []) if str(port).isdigit()]
        udp_ports = [str(port) for port in (udp_ports or []) if str(port).isdigit()]
        
        # Check TCP ports
        for port in tcp_ports:
            if port in tcp_mappings:
                # Prioritize certain protocols
                if primary_classification == "OTHER" or tcp_mappings[port] in ["HTTP", "HTTPS", "SSH"]:
                    primary_classification = tcp_mappings[port]
        
        # Check UDP ports
        for port in udp_ports:
            if port in udp_mappings:
                # Only override if no prioritized TCP protocol found
                if primary_classification == "OTHER":
                    primary_classification = udp_mappings[port]
    
    except Exception as e:
        logger.error(f"Error processing ports: {e}")
        return "ERROR"
    
    return primary_classification

# Register UDF for traffic classification
classify_udf = udf(classify_traffic, StringType())

# Apply traffic classification
enriched_df = enriched_df.withColumn(
    "traffic_type",
    classify_udf(
        when(col("tcp_port").isNotNull(), split(col("tcp_port"), ",")),
        when(col("udp_port").isNotNull(), split(col("udp_port"), ","))
    )
)


snowflake_options = {
    "sfURL": "https://WYIBXQD-NP85910.snowflakecomputing.com",
    "sfAccount": "NP85910",
    "sfUser": "MEDANISOUESLATI",
    "sfPassword": "REDIphone11;:REDIphone11;:",
    "sfDatabase": "spark_db",
    "sfSchema": "spark_schema",
    "sfWarehouse": "COMPUTE_WH",  # Default warehouse
    "dbtable": "LOG_data",
    "sfRole": "ACCOUNTADMIN"
}


# Output to console
def write_to_snowflake(batch_df, batch_id):
    batch_df.write \
        .format("snowflake") \
        .options(**snowflake_options) \
        .option("dbtable", "LOG_data") \
        .mode("append") \
        .save()

query = enriched_df.writeStream \
    .outputMode("append") \
    .foreachBatch(write_to_snowflake) \
    .start()

try:
    query.awaitTermination()
except Exception as e:
    logger.error(f"Streaming query failed: {e}")
finally:
    spark.stop()