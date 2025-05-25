import pika
import json
from typing import List, Dict
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AnomalyPublisher:
    def __init__(self, rabbitmq_host: str = "localhost", queue_name: str = "anomaly_queue"):
        self.rabbitmq_host = rabbitmq_host
        self.queue_name = queue_name
        self.connection = None
        self.channel = None
        self._connect()

    def _connect(self):
        """Establish connection to RabbitMQ server."""
        try:
            self.connection = pika.BlockingConnection(
                pika.ConnectionParameters(host=self.rabbitmq_host)
            )
            self.channel = self.connection.channel()
            self.channel.queue_declare(queue=self.queue_name, durable=True)
            logger.info(f"Connected to RabbitMQ at {self.rabbitmq_host}")
        except Exception as e:
            logger.error(f"Error connecting to RabbitMQ: {e}")
            raise

    def publish_anomalies(self, summaries: List[Dict]):
        """Publish anomaly summaries to RabbitMQ queue."""
        if not summaries:
            logger.warning("No summaries to publish")
            return

        for summary in summaries:
            try:
                message = json.dumps(summary)
                self.channel.basic_publish(
                    exchange="",
                    routing_key=self.queue_name,
                    body=message,
                    properties=pika.BasicProperties(delivery_mode=2)  # Persistent messages
                )
                logger.info(f"Published anomaly: {message}")
            except Exception as e:
                logger.error(f"Error publishing anomaly: {e}")

    def close(self):
        """Close RabbitMQ connection."""
        if self.connection and not self.connection.is_closed:
            self.connection.close()
            logger.info("RabbitMQ connection closed")

def format_summaries_for_publishing(log_lines: List[str]) -> List[Dict]:
    """Format cyber attack summaries from log lines for RabbitMQ publishing."""
    summaries = []
    current_summary = None
    for line in log_lines:
        line = line.strip()
        if line.startswith("Attack Type:"):
            if current_summary:
                summaries.append(current_summary)
            current_summary = {"attack_type": line.split(": ")[1].strip()}
        elif current_summary and line.startswith("  - "):
            key, value = line[4:].split(": ", 1)
            current_summary[key.lower().replace(" ", "_")] = value.strip()
        elif line.startswith("2025-") and "Summary for" in line:
            if current_summary:
                summaries.append(current_summary)
                current_summary = None
    if current_summary:
        summaries.append(current_summary)
    return summaries

# Example integration (to be added to anomaly_detection_agent.py)
if __name__ == "__main__":
    # Sample logs from your output
    sample_logs = [
        "2025-05-22 14:55:44,862 - INFO - Generating cyber attack summaries",
        "Attack Type: System_Strain",
        "  - Incident Count: 100",
        "  - Time Range: 2025-05-22 10 to 2025-05-22 10",
        "  - Source IPs: None",
        "  - Destination IPs: None",
        "  - Details: Max CPU: 67.74%, Max Memory: 100.00%",
        "  - Recommended Mitigation: Investigate system resource usage and potential DoS attacks.",
        "2025-05-22 14:55:44,862 - INFO - Summary for System_Strain: ",
        "Attack Type: Unauthorized_Access",
        "  - Incident Count: 27",
        "  - Time Range: 2025-05-22 10 to 2025-05-22 10",
        "  - Source IPs: 10.71.0.100, 10.71.0.17, 10.71.0.41, ...",
        "  - Destination IPs: 255.255.255.255, 34.120.195.249, ...",
        "  - Details: Ports targeted: 0.00000, 67.00000, 3.00000, ...",
        "  - Recommended Mitigation: Restrict access to non-standard ports and monitor ...",
        "2025-05-22 14:55:44,862 - INFO - Summary for Unauthorized_Access: ",
    ]

    summaries = format_summaries_for_publishing(sample_logs)
    publisher = AnomalyPublisher()
    publisher.publish_anomalies(summaries)
    publisher.close()