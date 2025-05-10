import subprocess
import logging
import os
from concurrent.futures import ThreadPoolExecutor
from typing import List
import psutil
import time

# Initialize logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# List of transformation scripts
TRANSFORM_SCRIPTS = [
    "zeek_capture_loss_transform.py",
    "zeek_conn_transform.py",
    "zeek_dns_transform.py",
    "zeek_http_transform.py",
    "zeek_notice_transform.py",
    "zeek_ssl_transform.py"
]

# Spark master URL
SPARK_MASTER = "spark://spark:7077"

# Path to spark-submit
SPARK_SUBMIT = "/opt/bitnami/spark/bin/spark-submit"

# JAR dependencies
JARS = [
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

def check_system_resources() -> bool:
    """
    Checks available system resources (CPU and memory) to ensure safe job submission.
    
    Returns:
        bool: True if resources are sufficient, False otherwise.
    """
    try:
        cpu_usage = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        available_memory = memory.available / (1024 ** 3)  # Convert to GB
        
        logger.info(f"CPU Usage: {cpu_usage}% | Available Memory: {available_memory:.2f} GB")
        
        # Thresholds: Less than 80% CPU usage and at least 1 GB free memory
        if cpu_usage > 80 or available_memory < 1:
            logger.warning("Insufficient system resources to submit more jobs")
            return False
        return True
    except Exception as e:
        logger.error(f"Error checking system resources: {str(e)}")
        return False

def submit_spark_job(script: str) -> None:
    """
    Submits a single Spark job for the given script using spark-submit.
    
    Args:
        script (str): Name of the Python script to run.
    """
    try:
        if not check_system_resources():
            logger.error(f"Skipping {script} due to insufficient resources")
            return
            
        script_path = f"/spark-scripts/{script}"
        if not os.path.exists(script_path):
            logger.error(f"Script {script} not found at {script_path}")
            return

        command = [
            SPARK_SUBMIT,
            "--master", SPARK_MASTER,
            "--deploy-mode", "client",
            "--driver-memory", "1g",  # Updated to match transformation script
            "--executor-memory", "1g",  # Updated to match transformation script
            "--executor-cores", "2",  # Updated to match transformation script
            "--jars", ",".join(JARS),
            "--conf", "spark.driver.extraJavaOptions=-Dlog4j.configuration=file:/opt/spark/conf/log4j.properties",
            "--conf", "spark.dynamicAllocation.enabled=false",  # Updated to match transformation script
            "--conf", "spark.executor.instances=1",  # Updated to match transformation script
            "--conf", "spark.shuffle.service.enabled=false",  # Simplified for fixed executors
            "--conf", "spark.sql.shuffle.partitions=4",  # Consistent with transformation script
            script_path
        ]
        
        logger.info(f"Submitting Spark job for {script}")
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
        
        stdout, stderr = process.communicate()
        
        if process.returncode == 0:
            logger.info(f"Successfully submitted {script}")
            logger.debug(f"Output for {script}:\n{stdout}")
        else:
            logger.error(f"Failed to submit {script}. Return code: {process.returncode}")
            logger.error(f"Error output:\n{stderr}")
            
    except Exception as e:
        logger.error(f"Exception while submitting {script}: {str(e)}")

def run_all_transforms(scripts: List[str]) -> None:
    """
    Runs all transformation scripts concurrently using ThreadPoolExecutor.
    
    Args:
        scripts (List[str]): List of script names to run.
    """
    logger.info("Starting submission of all Zeek transformation scripts")
    
    # Limit concurrency to avoid resource contention
    with ThreadPoolExecutor(max_workers=2) as executor:  # Reduced to 2 concurrent jobs
        executor.map(submit_spark_job, scripts)
    
    logger.info("All transformation scripts have been submitted")

if __name__ == "__main__":
    try:
        run_all_transforms(TRANSFORM_SCRIPTS)
    except Exception as e:
        logger.error(f"Failed to run transformations: {str(e)}")