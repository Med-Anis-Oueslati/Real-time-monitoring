import paramiko
from langchain_openai import ChatOpenAI
from langchain.prompts import ChatPromptTemplate
from langchain.output_parsers import PydanticOutputParser
from pydantic import BaseModel, Field
from typing import List, Tuple, Optional
import re
import os
import logging

# Configure logging for this utility
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO) # Set level to INFO for production, DEBUG for development

# Define the Pydantic model for structured output from the LLM
class MitigationAction(BaseModel):
    commands: List[str] = Field(description="List of Linux commands to execute for mitigation")
    description: str = Field(description="Brief description of the mitigation action")

class MitigationUtility:
    """
    A utility class to interact with the LLM for generating mitigation commands
    and executing them via SSH. Designed to be called from Flask routes.
    """
    def __init__(self, openai_api_key: str):
        """
        Initializes the LLM and parser.
        """
        if not openai_api_key:
            raise ValueError("OpenAI API Key not found. Please provide OPENAI_API_KEY.")

        self.llm = ChatOpenAI(model="gpt-4o-mini", api_key=openai_api_key)
        self.parser = PydanticOutputParser(pydantic_object=MitigationAction)
        self.prompt = self._create_prompt()

    def _create_prompt(self):
        """
        Creates a LangChain prompt for generating mitigation actions as Linux commands.
        """
        template = """
        You are a cybersecurity assistant tasked with analyzing descriptions of security incidents on a Linux system running UFW (Uncomplicated Firewall) as the primary firewall manager.
        Your goal is to propose a set of safe and effective Linux commands to mitigate or investigate the described incident.
        The commands will be executed via SSH on a Linux VM. The agent will automatically handle 'sudo' authentication, so do NOT include 'sudo' or password-related prefixes in your commands.

        Guidelines for Proposed Commands:
        - Do NOT include 'sudo' in the commands.
        - Ensure commands are safe and avoid destructive actions (e.g., no 'rm -rf /').
        - Prioritize commands that are reversible where appropriate.
        - If the description lacks sufficient details (e.g., no IP, port, or specific process), return an empty command list and explain why in the description field, suggesting what information is needed.

        Specific Mitigation Strategies and Commands:

        1.  **Network-Based Attacks (e.g., DoS, Port Scans, Unauthorized Access Attempts):**
            * **Blocking IP addresses (general traffic):**
                * `ufw insert 1 deny from <IP>`
                * `ufw reload` (omit if disk space is an issue, but note this in description)
            * **Blocking unauthorized access on specific ports from an IP:**
                * `ufw insert 1 deny from <IP> to any port <PORT>`
                * `ufw reload` (omit if disk space is an issue, but note this in description)
            * **Suspicious HTTP/HTTPS traffic (if IPs provided):**
                * `ufw insert 1 deny from <IP> to any port 80` or `port 443`
                * `ufw reload` (omit if disk space is an issue, but note this in description)
            * **General Network Investigation (if specific IPs/ports are unknown but network activity is suspected):**
                * `netstat -tuln` (list listening ports)
                * `ss -tuln` (modern alternative to netstat for listening ports)
                * `ss -tunap` (show all active connections with process info)
                * `lsof -i` (list open internet files/sockets)

        2.  **Suspicious Process Activity / Malware:**
            * **Identifying suspicious processes (if PID, process name, or unusual behavior is described):**
                * `ps aux` (list all running processes)
                * `top -b -n 1` (snapshot of top processes)
                * `pstree -ap` (process tree with PIDs and arguments)
            * **Stopping a suspicious process (if identified with high confidence):**
                * `kill <PID>` (graceful termination)
                * `kill -9 <PID>` (forceful termination - use with caution)
                * `systemctl stop <service_name>` (if it's a known service)
            * **Investigating suspicious files/directories:**
                * `ls -lah <path>` (list contents with details)
                * `file <path/to/file>` (determine file type)
                * `strings <path/to/binary>` (extract printable strings from binary)
                * `find / -name "<suspicious_file>" -mtime -1` (find recently modified files, example for last 24h)

        3.  **Account Compromise / Brute-Force Attempts (SSH, FTP, etc.):**
            * **Investigating login attempts:**
                * `grep "Failed password" /var/log/auth.log` (for SSH brute-force)
                * `last` (show recent logins)
                * `lastb` (show bad login attempts)
            * **Locking a suspicious user account (if clearly compromised):**
                * `passwd -l <username>` (lock account - user cannot log in)
                * `usermod -L <username>` (alternative method to lock account)
            * **Unlocking a user account (for remediation/post-incident clean-up):**
                * `passwd -u <username>`
                * `usermod -U <username>`
            * **Checking for new/unauthorized users:**
                * `cat /etc/passwd`
                * `cat /etc/shadow` (sensitive, but for identifying new users)

        4.  **Web Application Attacks (if logs or patterns are described, e.g., SQL Injection, XSS):**
            * **Analyzing web server logs (if IPs are not explicitly given, or for deeper analysis):**
                * `grep "<IP>" /var/log/apache2/access.log` (Apache example)
                * `grep "<IP>" /var/log/nginx/access.log` (Nginx example)
                * `grep "sql" /var/log/apache2/access.log` (example for SQLi patterns)
                * `grep "XSS" /var/log/apache2/access.log` (example for XSS patterns)
            * **Blocking IPs (as above):** Use UFW commands as per section 1.

        Return the result in the following JSON format:
        {format_instructions}

        Input description: {input_description}
        """
        return ChatPromptTemplate.from_template(template).partial(format_instructions=self.parser.get_format_instructions())

    def generate_mitigation_action(self, incident_description: str) -> MitigationAction:
        """
        Generates a structured mitigation action with Linux commands from the incident description
        using the configured LLM.
        """
        try:
            chain = self.prompt | self.llm | self.parser
            result = chain.invoke({"input_description": incident_description})
            logger.info(f"LLM generated mitigation: {result.description}, Commands: {result.commands}")
            return result
        except Exception as e:
            logger.error(f"Error generating action with LLM: {e}")
            return MitigationAction(commands=[], description="Failed to generate mitigation action due to LLM error.")

    def validate_command(self, command: str) -> bool:
        """
        Validates that a command is safe to execute.
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

    def execute_ssh_command(self, ip: str, username: str, password: str, command: str, sudo_pass: Optional[str] = None) -> Tuple[bool, str]:
        """
        Executes an SSH command on a remote host.
        Returns a tuple: (success_status: bool, message: str)
        """
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        CONNECT_TIMEOUT = 10
        COMMAND_EXEC_TIMEOUT = 30

        try:
            ssh.connect(ip, username=username, password=password, timeout=CONNECT_TIMEOUT)

            # Build the command string, including sudo if a password is provided
            # Note: The LLM is instructed NOT to include 'sudo', so we add it here if needed.
            full_command = f"echo '{sudo_pass}' | sudo -S {command}" if sudo_pass else command

            logger.info(f"Attempting to execute SSH command on {ip}: {command}")
            stdin, stdout, stderr = ssh.exec_command(full_command, timeout=COMMAND_EXEC_TIMEOUT)

            output = stdout.read().decode().strip()
            error = stderr.read().decode().strip()
            exit_status = stdout.channel.recv_exit_status()

            ssh.close()

            if exit_status == 0:
                logger.info(f"SSH command successful on {ip}. Output: '{output}'")
                return True, output
            else:
                err_msg = f"SSH command failed on {ip} (exit status {exit_status}). Output: '{output}', Error: '{error}'"
                logger.error(err_msg)
                return False, err_msg

        except paramiko.AuthenticationException:
            return False, "Authentication failed. Check username/password for SSH."
        except paramiko.SSHException as e:
            return False, f"SSH connection or command execution failed: {e}"
        except Exception as e:
            return False, f"An unexpected error occurred during SSH operation: {e}"

    def execute_mitigation_commands(self, vm_ip: str, vm_username: str, vm_password: str, commands: List[str]) -> List[Tuple[bool, str]]:
        """
        Executes a list of mitigation commands on the specified VM.
        Returns a list of results for each command.
        """
        results = []
        for command in commands:
            if not self.validate_command(command):
                results.append((False, f"Command '{command}' blocked for safety."))
                continue
            
            # Special handling for 'ufw reload' to check disk space
            if command == "ufw reload":
                try:
                    # Check disk space before reloading ufw
                    check_disk_space_cmd = "df -h /tmp | awk 'NR==2 {print $5}' | sed 's/%//'"
                    success, df_output = self.execute_ssh_command(vm_ip, vm_username, vm_password, check_disk_space_cmd, sudo_pass=vm_password)
                    if success and int(df_output) >= 90: # If /tmp is 90% full or more
                        results.append((False, "Skipping 'ufw reload' due to high disk space usage on /tmp."))
                        continue
                except Exception as e:
                    logger.error(f"Error checking disk space before ufw reload: {e}")
                    results.append((False, f"Error checking disk space before ufw reload: {e}"))
                    continue

            success, message = self.execute_ssh_command(vm_ip, vm_username, vm_password, command, sudo_pass=vm_password)
            results.append((success, message))
        return results

