from pyspark.sql import SparkSession
from pyspark.sql.functions import col, when, concat_ws, current_timestamp,concat, lit
from dotenv import load_dotenv
import os

load_dotenv()
spark = SparkSession.builder.appName("DNSTunnelingDetection").getOrCreate()

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

# Read features
df = spark.read.format("snowflake").options(**snowflake_options) \
    .option("query", """
        SELECT d.TS_WINDOW_START, d.ID_ORIG_H, d.VM_ID, d.QUERY_RATE, d.UNIQUE_QUERIES, 
               d.AVG_QUERY_LEN, d.QUERY_NAME_ENTROPY, n.DNS_TUNNELING_NOTICES, n.AVG_NOTICE_MSG_LEN
        FROM SPARK_DB.SPARK_SCHEMA.DNS_FEATURES d
        LEFT JOIN SPARK_DB.SPARK_SCHEMA.NOTICE_FEATURES n
        ON d.TS_WINDOW_START = n.TS_WINDOW_START 
        AND d.ID_ORIG_H = n.ID_ORIG_H 
        AND d.VM_ID = n.VM_ID
        WHERE d.TS_WINDOW_START >= '2025-05-21 16:45:00'
    """).load()

# Detect anomalies
anomalies_df = df.withColumn(
    "SCORE",
    when(
        (col("DNS_TUNNELING_NOTICES") > 3) | 
        (col("AVG_QUERY_LEN") > 50) | 
        (col("QUERY_NAME_ENTROPY") > 4.0),
        0.4 * when(col("AVG_QUERY_LEN") > 50, 1).otherwise(0) +
        0.4 * when(col("DNS_TUNNELING_NOTICES") > 3, 1).otherwise(0) +
        0.2 * when(col("QUERY_NAME_ENTROPY") > 4.0, 1).otherwise(0)
    ).otherwise(0)
).withColumn(
    "ANOMALY_TYPE",
    when(col("SCORE") > 0, "DNS_Tunneling").otherwise(None)
).withColumn(
    "DETAILS",
    when(
        col("SCORE") > 0,
        concat_ws(", ",
            when(col("AVG_QUERY_LEN") > 50, concat(lit("High AVG_QUERY_LEN="), col("AVG_QUERY_LEN"))).otherwise(None),
            when(col("DNS_TUNNELING_NOTICES") > 3, concat(lit("DNS_TUNNELING_NOTICES="), col("DNS_TUNNELING_NOTICES"))).otherwise(None),
            when(col("QUERY_NAME_ENTROPY") > 4.0, concat(lit("QUERY_NAME_ENTROPY="), col("QUERY_NAME_ENTROPY"))).otherwise(None)
        )
    ).otherwise(None)
).select(
    current_timestamp().alias("TIMESTAMP"),
    col("ID_ORIG_H"),
    col("VM_ID"),
    col("ANOMALY_TYPE"),
    col("SCORE"),
    col("DETAILS")
).filter(col("ANOMALY_TYPE").isNotNull())

# Write to ANOMALIES
anomalies_df.write.format("snowflake").options(**snowflake_options) \
    .option("dbtable", "ANOMALIES").mode("append").save()

spark.stop()