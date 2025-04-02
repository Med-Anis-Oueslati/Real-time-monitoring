from pyspark.sql import SparkSession
from pyspark.sql.functions import col

# Initialize Spark session
spark = SparkSession.builder \
    .appName("KafkaToSparkStreaming") \
    .master("spark://spark:7077") \
    .getOrCreate()

# Read from Kafka
kafka_df = spark \
    .readStream \
    .format("kafka") \
    .option("kafka.bootstrap.servers", "kafka:9092") \
    .option("subscribe", "lubuntu_auth") \
    .option("startingOffsets", "latest") \
    .load()

# Extract value (log message) and cast to string
logs_df = kafka_df.select(col("value").cast("string"))

# Print to console
query = logs_df \
    .writeStream \
    .outputMode("append") \
    .format("console") \
    .start()

# Keep the stream running
query.awaitTermination()