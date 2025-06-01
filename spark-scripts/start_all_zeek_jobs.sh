#!/bin/bash

# This script submits all Spark applications in cluster mode.

# Wait for the Spark master to be ready.
# In a real-world scenario, you might use a more robust wait mechanism.
# For Docker Compose, a simple sleep after depends_on might be sufficient,
# but waiting for the master port is more reliable.
echo "Waiting for Spark master..."
# Wait for the Spark master's UI port to be open (or 7077, but 8080 is easier to check)
# Using netcat (nc) to check if the port is listening

# Give workers a moment to connect
echo "Giving workers time to connect..."
sleep 5

# List of your 6 Spark script filenames
# **IMPORTANT: Replace these with the actual names of your 6 scripts**
SPARK_SCRIPTS=(
  # "zeek_capture_loss_transform.py" # Example: zeek_capture_loss_transform.py
  # "zeek_conn_transform.py" # Example: zeek_conn_transform.py
  # "zeek_dns_transform.py" # Example: zeek_dns_transform.py
  # "zeek_http_transform.py" # Example: zeek_http_transform.py
  # "zeek_notice_transform.py" # Example: zeek_notice_transform.py
  # "zeek_ssl_transform.py" # Example: zeek_ssl_transform.py
  # "system_metrics.py"
  # "transform_tshark.py"
  "transform_auth.py" # Example: transform_tshark.py
)

# Common Spark submission parameters for cluster mode
MASTER_URL="spark://spark:7077"
DEPLOY_MODE="client" # <-- Key change here!
DRIVER_MEMORY="512m"  # Adjust based on how lightweight your scripts are
EXECUTOR_MEMORY="512m" # Adjust based on how lightweight your scripts are
EXECUTOR_CORES="1"     # Match your worker config, or less if needed

# Pass necessary jars (these should be available on the worker nodes via volume mounts)
# Listing them here is still good practice for --jars arg.  "zeek_capture_loss_transform.py" # Example: zeek_capture_loss_transform.py
  "zeek_conn_transform.py" # Example: zeek_conn_transform.py
  "zeek_dns_transform.py" # Example: zeek_dns_transform.py
  "zeek_http_transform.py" # Example: zeek_http_transform.py
  "zeek_notice_transform.py" # Example: zeek_notice_transform.py
  "zeek_ssl_transform.py" # Example: zeek_ssl_transform.py
# Make sure this list is complete and matches your docker-compose volumes.
SPARK_JARS="/opt/spark/jars/spark-sql-kafka-0-10_2.12-3.5.0.jar,\
/opt/spark/jars/kafka-clients-3.4.1.jar,\
/opt/spark/jars/spark-streaming_2.12-3.5.0.jar,\
/opt/spark/jars/spark-token-provider-kafka-0-10_2.12-3.5.0.jar,\
/opt/spark/jars/commons-pool2-2.11.1.jar,\
/opt/spark/jars/snowflake-jdbc-3.23.2.jar,\
/opt/spark/jars/spark-snowflake_2.12-3.1.1.jar,\
/opt/spark/jars/jackson-databind-2.15.2.jar,\
/opt/spark/jars/jackson-core-2.15.2.jar,\
/opt/spark/jars/jackson-annotations-2.15.2.jar,\
/opt/spark/jars/parquet-avro-1.12.3.jar,\
/opt/spark/jars/parquet-hadoop-1.12.3.jar,\
/opt/spark/jars/avro-1.11.3.jar"

# Optional: Log4j configuration for the driver logs (will appear on the worker node logs)
LOG4J_CONF="/opt/spark/conf/log4j.properties"
SPARK_CONF="spark.driver.extraJavaOptions=-Dlog4j.configuration=file:$LOG4J_CONF"


echo "Submitting Spark applications in cluster mode..."

# Loop through each script and submit it
PORT=4050
for script in "${SPARK_SCRIPTS[@]}"; do
  echo "Submitting $script..."
  /opt/bitnami/spark/bin/spark-submit \
    --master "$MASTER_URL" \
    --deploy-mode "$DEPLOY_MODE" \
    --driver-memory "$DRIVER_MEMORY" \
    --executor-memory "$EXECUTOR_MEMORY" \
    --executor-cores "$EXECUTOR_CORES" \
    --jars "$SPARK_JARS" \
    --conf "spark.dynamicAllocation.enabled=true" \
    --conf "spark.dynamicAllocation.minExecutors=1" \
    --conf "spark.dynamicAllocation.maxExecutors=2" \
    --conf "spark.dynamicAllocation.initialExecutors=1" \
    --conf "spark.ui.port=$PORT" \
    "/spark-scripts/$script" &
  PORT=$((PORT + 1))
  sleep 2
done

echo "All Spark applications submitted. Check the Spark UI (spark:8080) and worker logs for status."

# The submitter container will exit once this script finishes.
# This is expected for cluster mode submissions.
exit 0