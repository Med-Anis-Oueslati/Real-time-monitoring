from pyspark.sql import SparkSession
from pyspark.sql.functions import col, split, udf, from_json
from pyspark.sql.types import StructType, StructField, StringType, FloatType, ArrayType
import geoip2.database

# Initialize Spark session
spark = SparkSession.builder \
    .appName("LogProcessing") \
    .config("spark.executor.memory", "2g") \
    .config("spark.executor.cores", "2") \
    .config("spark.driver.memory", "2g") \
    .config("spark.jars", "/opt/spark/jars/spark-sql-kafka-0-10_2.12-3.5.0.jar") \
    .getOrCreate()

# Broadcast GeoLite2 database path
geoip_db_path = "/opt/spark/GeoLite2-City.mmdb"
broadcast_geoip_db_path = spark.sparkContext.broadcast(geoip_db_path)

# Geolocation lookup function
def get_geolocation(ip):
    try:
        reader = geoip2.database.Reader(broadcast_geoip_db_path.value)
        response = reader.city(ip)
        return [
            response.location.latitude,
            response.location.longitude,
            response.city.name  # Include city name
        ]
    except Exception:
        return [None, None, None]  # Return None values for invalid IPs

# Register UDF
get_geolocation_udf = udf(get_geolocation, ArrayType(StringType()))  # Use StringType for city name

# Kafka message schema
kafka_message_schema = StructType([StructField("message", StringType(), True)])

# Read from Kafka
kafka_df = spark \
    .readStream \
    .format("kafka") \
    .option("kafka.bootstrap.servers", "kafka:9092") \
    .option("subscribe", "lubuntu_tshark") \
    .option("startingOffsets", "latest") \
    .load()

# Parse Kafka message
parsed_df = kafka_df.select(
    from_json(col("value").cast("string"), kafka_message_schema).alias("data")
).select("data.message")

# Extract fields and enrich with geolocation
enriched_df = parsed_df \
    .withColumn("fields", split(col("message"), "\t")) \
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
        col("src_geo").getItem(2).alias("src_city"),  # Add source city
        col("dst_geo").getItem(0).alias("dst_latitude"),
        col("dst_geo").getItem(1).alias("dst_longitude"),
        col("dst_geo").getItem(2).alias("dst_city")   # Add destination city
    )

# Output to console
query = enriched_df.writeStream \
    .outputMode("append") \
    .format("console") \
    .start()

query.awaitTermination()