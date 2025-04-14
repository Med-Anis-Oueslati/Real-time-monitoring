from pyspark.sql import SparkSession
from pyspark.sql.functions import col, split, from_json
from pyspark.sql.types import StructType, StructField, StringType

# Initialize Spark session
spark = SparkSession.builder \
    .appName("LogProcessing") \
    .config("spark.executor.memory", "2g") \
    .config("spark.executor.cores", "2") \
    .config("spark.driver.memory", "2g") \
    .getOrCreate()

# Define schema for the Kafka message
kafka_message_schema = StructType([
    StructField("message", StringType(), True)
])

# Read logs from Kafka
kafka_df = spark \
    .readStream \
    .format("kafka") \
    .option("kafka.bootstrap.servers", "kafka:9092") \
    .option("subscribe", "lubuntu_tshark") \
    .option("startingOffsets", "latest") \
    .load()

# Parse the Kafka message into a structured format
parsed_kafka_df = kafka_df.select(
    from_json(col("value").cast("string"), kafka_message_schema).alias("data")
).select("data.*")

# Split the message into individual fields
parsed_logs = parsed_kafka_df.withColumn("fields", split(col("message"), "\t")) \
    .select(
        col("fields").getItem(0).alias("frame_time"),
        col("fields").getItem(1).alias("ip_src"),
        col("fields").getItem(2).alias("ip_dst"),
        col("fields").getItem(3).alias("udp_port"),
        col("fields").getItem(4).alias("tcp_port"),
        col("fields").getItem(5).alias("ip_proto")
    )

# Print the parsed logs to the terminal
query = parsed_logs.writeStream \
    .outputMode("append") \
    .format("console") \
    .start()

query.awaitTermination()