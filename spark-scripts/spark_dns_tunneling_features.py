from pyspark.sql import SparkSession
from pyspark.sql.functions import col, window, count, count_distinct, avg, length, udf
from pyspark.sql.types import FloatType
from scipy.stats import entropy
import numpy as np
import logging
from dotenv import load_dotenv
import os

# Initialize logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# Initialize Spark session
spark_jars = [
    "/opt/spark/jars/snowflake-jdbc-3.23.2.jar",
    "/opt/spark/jars/spark-snowflake_2.12-3.1.1.jar",
    "/opt/spark/jars/jackson-databind-2.15.2.jar",
    "/opt/spark/jars/jackson-core-2.15.2.jar",
    "/opt/spark/jars/jackson-annotations-2.15.2.jar",
    "/opt/spark/jars/parquet-avro-1.12.3.jar",
    "/opt/spark/jars/parquet-hadoop-1.12.3.jar",
    "/opt/spark/jars/parquet-column-1.12.3.jar",
    "/opt/spark/jars/parquet-common-1.12.3.jar",
    "/opt/spark/jars/avro-1.11.3.jar"
]

spark = SparkSession.builder \
    .appName("DNSTunnelingFeatures") \
    .config("spark.jars", ",".join(spark_jars)) \
    .config("spark.dynamicAllocation.enabled", "true") \
    .config("spark.ui.port", "4052") \
    .getOrCreate()

# Rest of the script remains unchanged
# UDF for computing entropy
def compute_entropy(query):
    if not query or query.isspace():
        return 0.0
    try:
        char_counts = np.array([query.count(c) for c in set(query)])
        probs = char_counts / len(query)
        return float(entropy(probs, base=2))
    except Exception as e:
        logger.warning(f"Entropy computation failed for query '{query}': {e}")
        return 0.0

entropy_udf = udf(compute_entropy, FloatType())

# Snowflake connection options
snowflake_options = {
    "sfURL": os.getenv("SNOWFLAKE_URL"),
    "sfAccount": os.getenv("SNOWFLAKE_ACCOUNT"),
    "sfUser": os.getenv("SNOWFLAKE_USER"),
    "sfPassword": os.getenv("SNOWFLAKE_PASSWORD"),
    "sfDatabase": "SPARK_DB",
    "sfSchema": "SPARK_SCHEMA",
    "sfWarehouse": os.getenv("SNOWFLAKE_WAREHOUSE"),
    "sfRole": os.getenv("SNOWFLAKE_ROLE")
}

# Read from Snowflake
dns_query = """
SELECT TIMESTAMP, UID, ID_ORIG_H, ID_ORIG_P, ID_RESP_H, ID_RESP_P, PROTO, RTT, 
       QUERY, QTYPE, QTYPE_NAME, ANSWERS, TTLS, VM_ID
FROM SPARK_DB.SPARK_SCHEMA.ZEEK_DNS
WHERE TIMESTAMP >= DATEADD(MINUTE, -15, CURRENT_TIMESTAMP)
"""
dns_df = spark.read \
    .format("snowflake") \
    .options(**snowflake_options) \
    .option("query", dns_query) \
    .load()

notice_query = """
SELECT TIMESTAMP, UID, ID_ORIG_H, ID_ORIG_P, ID_RESP_H, ID_RESP_P, PROTO, 
       NOTE, MSG, SRC, DST, VM_ID
FROM SPARK_DB.SPARK_SCHEMA.ZEEK_NOTICE
WHERE TIMESTAMP >= DATEADD(MINUTE, -15, CURRENT_TIMESTAMP)
"""
notice_df = spark.read \
    .format("snowflake") \
    .options(**snowflake_options) \
    .option("query", notice_query) \
    .load()

# Feature engineering: DNS features
# Feature engineering: DNS features
dns_features_df = dns_df \
    .groupBy(
        window(col("TIMESTAMP"), "5 minutes").alias("TS_WINDOW"),
        col("ID_ORIG_H").cast("string").alias("ID_ORIG_H"),
        col("VM_ID")
    ) \
    .agg(
        (count("*") / 300.0).alias("QUERY_RATE"),
        count_distinct("QUERY").alias("UNIQUE_QUERIES"),
        avg(length("QUERY")).alias("AVG_QUERY_LEN"),
        avg(entropy_udf("QUERY")).alias("QUERY_NAME_ENTROPY")
    ) \
    .select(
        col("TS_WINDOW.start").cast("string").alias("TS_WINDOW_START"),
        col("ID_ORIG_H"),  # Now references the aliased ID_ORIG_H
        col("QUERY_RATE"),
        col("UNIQUE_QUERIES"),
        col("AVG_QUERY_LEN"),
        col("QUERY_NAME_ENTROPY"),
        col("VM_ID")
    )

# Feature engineering: Notice features
notice_features_df = notice_df \
    .filter(col("NOTE") == "Custom::DNS_Tunneling") \
    .groupBy(
        window(col("TIMESTAMP"), "5 minutes").alias("TS_WINDOW"),
        col("ID_ORIG_H").cast("string").alias("ID_ORIG_H"),
        col("VM_ID")
    ) \
    .agg(
        count("*").alias("DNS_TUNNELING_NOTICES"),
        avg(length("MSG")).alias("AVG_NOTICE_MSG_LEN")
    ) \
    .select(
        col("TS_WINDOW.start").cast("string").alias("TS_WINDOW_START"),
        col("ID_ORIG_H"),  # Now references the aliased ID_ORIG_H
        col("DNS_TUNNELING_NOTICES"),
        col("AVG_NOTICE_MSG_LEN"),
        col("VM_ID")
    )

dns_features_df.write \
    .format("snowflake") \
    .options(**snowflake_options) \
    .option("dbtable", "DNS_FEATURES") \
    .option("sfOnError", "CONTINUE") \
    .mode("append") \
    .save()

notice_features_df.write \
    .format("snowflake") \
    .options(**snowflake_options) \
    .option("dbtable", "NOTICE_FEATURES") \
    .option("sfOnError", "CONTINUE") \
    .mode("append") \
    .save()

spark.stop()