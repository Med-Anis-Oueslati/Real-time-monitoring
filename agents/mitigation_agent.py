import paramiko
from langchain_openai import ChatOpenAI
from langchain.prompts import ChatPromptTemplate
from langchain.output_parsers import PydanticOutputParser
from pydantic import BaseModel, Field
from typing import List
from dotenv import load_dotenv
import re
import os
import pika
import json
import logging
import time

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# Static configuration
ATTACKED_VM_IP = "172.20.10.5"
SUDO_PASSWORD = "root"
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
RABBITMQ_HOST = "localhost"
QUEUE_NAME = "anomaly_queue"

class MitigationAction(BaseModel):
    commands: List[str] = Field(description="List of Linux commands to execute for mitigation")
    description: str = Field(description="Brief description of the mitigation action")

class MitigationAgent:
    def __init__(self):
        # Initialize SSH connection to the attacked VM
        self.ssh_client = paramiko.SSHClient()
        self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            self.ssh_client.connect(ATTACKED_VM_IP, username="anis", key_filename="/home/anis/.ssh/id_rsa")
            logger.info(f"SSH connection to {ATTACKED_VM_IP} established successfully.")
        except Exception as e:
            logger.error(f"Error connecting to VM: {e}")
            raise

        if not OPENAI_API_KEY:
            raise ValueError("OpenAI API Key not found. Please set OPENAI_API_KEY environment variable.")

        # Initialize RabbitMQ connection
        self.rabbitmq_connection = None
        self.rabbitmq_channel = None
        self._connect_rabbitmq()

        # Initialize LangChain with OpenAI
        self.llm = ChatOpenAI(model="gpt-4o-mini", api_key=OPENAI_API_KEY)
        self.parser = PydanticOutputParser(pydantic_object=MitigationAction)
        self.prompt = self._create_prompt()

    def _connect_rabbitmq(self):
        """Establish connection to RabbitMQ server with retry logic."""
        max_retries = 3
        retry_delay = 5  # seconds
        for attempt in range(max_retries):
            try:
                self.rabbitmq_connection = pika.BlockingConnection(
                    pika.ConnectionParameters(host=RABBITMQ_HOST)
                )
                self.rabbitmq_channel = self.rabbitmq_connection.channel()
                self.rabbitmq_channel.queue_declare(queue=QUEUE_NAME, durable=True)
                logger.info(f"Connected to RabbitMQ at {RABBITMQ_HOST}")
                return
            except Exception as e:
                logger.error(f"Error connecting to RabbitMQ (attempt {attempt + 1}/{max_retries}): {e}")
                if attempt < max_retries - 1:
                    logger.info(f"Retrying in {retry_delay} seconds...")
                    time.sleep(retry_delay)
                else:
                    logger.error("Max retries reached. Failed to connect to RabbitMQ.")
                    raise

    def _create_prompt(self):
        """
        Create a LangChain prompt for generating mitigation actions as Linux commands.
        """
        template = """
            You are a cybersecurity assistant tasked with analyzing descriptions of security incidents on a Linux system running UFW (Uncomplicated Firewall) as the primary firewall manager.
            Your goal is to propose a set of safe and effective Linux commands to mitigate or investigate the described incident.
            The commands will be executed via SSH on a Linux VM. The agent will automatically handle 'sudo' authentication, so do NOT include 'sudo' or password-related prefixes in your commands.

            Guidelines for Proposed Commands:
            - Do NOT include 'sudo' in the commands.
            - Ensure commands are safe and avoid destructive actions (e.g., no 'rm -rf /').
            - Prioritize commands that are reversible where appropriate.
            - Even if the description lacks specific details (e.g., no IP, port), still provide investigation commands to gather more information.
            - When specific blocking isn't possible, focus on investigation and monitoring commands.

            Specific Mitigation Strategies and Commands:

            1. **For SQL Injection Attempts (when IPs are unknown):**
                * **Web Server Log Analysis:**
                    * `grep -i "union.*select" /var/log/apache2/access.log` (Apache)
                    * `grep -i "union.*select" /var/log/nginx/access.log` (Nginx)
                    * `grep -i "sql" /var/log/apache2/access.log` (Apache)
                    * `grep -i "1=1" /var/log/apache2/access.log` (common SQLi pattern)
                    * `tail -n 100 /var/log/apache2/access.log | grep -i "select"`
                * **General Web Server Monitoring:**
                    * `tail -f /var/log/apache2/access.log` (real-time monitoring)
                    * `journalctl -u apache2 --since "1 hour ago"` (systemd logs)
                * **Identify Potential Attackers:**
                    * `awk '{print $1}' /var/log/apache2/access.log | sort | uniq -c | sort -nr` (top IPs)
                    * `grep -i "union.*select" /var/log/apache2/access.log | awk '{print $1}' | sort | uniq -c | sort -nr` (IPs with SQLi attempts)

            2. **For All Incidents (when details are limited):**
                * **General System Investigation:**
                    * `netstat -tuln` (list listening ports)
                    * `ss -tuln` (modern alternative to netstat)
                    * `ps aux` (list all running processes)
                    * `top -b -n 1` (process snapshot)
                    * `df -h` (disk space check)
                    * `free -m` (memory usage)
                * **Security Monitoring:**
                    * `last` (recent logins)
                    * `lastb` (failed login attempts)
                    * `grep "Failed password" /var/log/auth.log` (SSH brute-force)
                    * `cat /var/log/syslog | tail -n 50` (system logs)

            Always provide commands that can help investigate the issue, even if specific mitigation isn't possible.
            For each proposed command, provide a brief description of the proposed mitigation or investigation action.

            Return the result in the following JSON format:
            {format_instructions}

            Input description: {input_description}
        """
        return ChatPromptTemplate.from_template(template).partial(format_instructions=self.parser.get_format_instructions())
    def generate_action(self, incident_description: str) -> MitigationAction:
        """
        Generate a structured mitigation action with Linux commands from the incident description.
        """
        try:
            chain = self.prompt | self.llm | self.parser
            result = chain.invoke({"input_description": incident_description})
            return result
        except Exception as e:
            logger.error(f"Error generating action: {e}")
            return MitigationAction(commands=[], description="Failed to generate mitigation action due to parsing error.")

    def validate_command(self, command: str) -> bool:
        """
        Validate that a command is safe to execute.
        Returns True if safe, False if potentially dangerous.
        """
        dangerous_patterns = [
            r"rm\s+-rf\s+/",  # Prevent 'rm -rf /'
            r"reboot",        # Prevent system reboots
            r"shutdown",      # Prevent system shutdowns
            r"init\s+0",      # Prevent system halts
            r"mkfs\.",        # Prevent filesystem formatting
            r"dd\s+.*of=/dev/",  # Prevent disk wiping
        ]
        for pattern in dangerous_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                logger.warning(f"Command blocked for safety: {command}")
                return False
        return True

    def confirm_action(self, message: str) -> bool:
        """
        Prompt the user to confirm an action.
        Returns True if the user confirms, False otherwise.
        """
        while True:
            choice = input(f"{message} (yes/no): ").strip().lower()
            if choice in ["yes", "y"]:
                return True
            elif choice in ["no", "n"]:
                return False
            logger.warning("Invalid input. Please enter 'yes' or 'no'.")

    def execute_mitigation_action(self, action: MitigationAction):
        """
        Execute the dynamically generated mitigation commands on the VM with sudo password.
        """
        if not action.commands:
            logger.warning(f"No commands to execute: {action.description}")
            return

        logger.info(f"Proposed mitigation: {action.description}")
        logger.info("Commands to execute:")
        for cmd in action.commands:
            logger.info(f"  - {cmd}")

        if not self.confirm_action("Do you want to execute these commands?"):
            logger.info("Mitigation action canceled.")
            return

        safe_password = SUDO_PASSWORD.replace("'", "'\\''")
        for command in action.commands:
            if not self.validate_command(command):
                logger.warning(f"Skipping unsafe command: {command}")
                continue

            # Skip ufw reload if disk space is likely an issue
            if command == "ufw reload":
                try:
                    stdin, stdout, stderr = self.ssh_client.exec_command("df -h /tmp")
                    output = stdout.read().decode()
                    error = stderr.read().decode()
                    if error or "100%" in output:
                        logger.warning("Skipping 'ufw reload' due to potential disk space issues.")
                        continue
                except Exception as e:
                    logger.error(f"Error checking disk space: {e}")
                    continue

            full_command = f"echo '{safe_password}' | sudo -S {command}"
            logger.info(f"Executing command: {full_command.replace(safe_password, '****')}")
            try:
                stdin, stdout, stderr = self.ssh_client.exec_command(full_command)
                exit_status = stdout.channel.recv_exit_status()
                output = stdout.read().decode()
                error = stderr.read().decode()
                if exit_status != 0:
                    logger.error(f"Command failed with exit status {exit_status}: {error}")
                else:
                    logger.info(f"Command executed successfully: {output or 'No output'}")
            except Exception as e:
                logger.error(f"Error executing command: {e}")

    def callback(self, ch, method, properties, body):
        """Callback function to process messages from RabbitMQ."""
        try:
            message = json.loads(body.decode())
            logger.info(f"Received anomaly: {message}")

            # Determine if it's a summary or incident message
            if message.get('type') == 'summary':
                incident_description = (
                    f"Summary Report:\n"
                    f"Description: {message.get('summary', 'No summary provided')}\n"
                    f"Timestamp: {message.get('timestamp', 'N/A')}"
                )
            else:
                incident_description = (
                    f"Attack Type: {message.get('type', 'Unknown')}\n"
                    f"Description: {message.get('description', 'No description provided')}\n"
                    f"Source IP: {message.get('src_ip', 'None')}\n"
                    f"Destination IP: {message.get('dst_ip', 'None')}\n"
                    f"Details: {json.dumps(message.get('details', {}), indent=2)}\n"
                    f"Timestamp: {message.get('timestamp', 'N/A')}"
                )

            logger.info(f"Processing incident: {incident_description}")
            if self.confirm_action("Do you want to proceed with analyzing this incident?"):
                action = self.generate_action(incident_description)
                logger.info(f"Inferred mitigation: {action.description}")
                if action.commands:
                    logger.info("Proposed commands:")
                    for cmd in action.commands:
                        logger.info(f"  - {cmd}")
                else:
                    logger.warning("No mitigation commands proposed.")

                if action.commands and self.confirm_action("Do you want to execute these mitigation commands?"):
                    self.execute_mitigation_action(action)
                else:
                    logger.info("Mitigation action skipped.")
            else:
                logger.info("Incident analysis canceled.")

            ch.basic_ack(delivery_tag=method.delivery_tag)
        except Exception as e:
            logger.error(f"Error processing message: {e}")
            ch.basic_nack(delivery_tag=method.delivery_tag, requeue=True)
            # Attempt to reconnect to RabbitMQ
            logger.info("Attempting to reconnect to RabbitMQ...")
            try:
                self._connect_rabbitmq()
            except Exception as reconnect_e:
                logger.error(f"Reconnection failed: {reconnect_e}")
                raise

    def run(self):
        """
        Main loop to consume incident descriptions from RabbitMQ and generate mitigation actions.
        """
        try:
            logger.info(f"Connected to VM at {ATTACKED_VM_IP} and RabbitMQ at {RABBITMQ_HOST}. Listening for anomalies...")
            self.rabbitmq_channel.basic_consume(
                queue=QUEUE_NAME,
                on_message_callback=self.callback
            )
            self.rabbitmq_channel.start_consuming()
        except KeyboardInterrupt:
            logger.info("Stopping mitigation agent...")
        except Exception as e:
            logger.error(f"Error in main loop: {e}")
        finally:
            if self.rabbitmq_connection and not self.rabbitmq_connection.is_closed:
                self.rabbitmq_connection.close()
                logger.info("RabbitMQ connection closed")
            self.ssh_client.close()
            logger.info("SSH connection closed")
if __name__ == "__main__":
    try:
        agent = MitigationAgent()
        agent.run()
    except Exception as e:
        logger.error(f"Failed to initialize mitigation agent: {e}")