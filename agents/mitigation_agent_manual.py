import paramiko
from langchain_openai import ChatOpenAI
from langchain.prompts import ChatPromptTemplate
from langchain.output_parsers import PydanticOutputParser
from pydantic import BaseModel, Field
from typing import List
from dotenv import load_dotenv
import re
import os

# Load environment variables
load_dotenv()

# Static configuration
ATTACKED_VM_IP = "10.71.0.162"
SUDO_PASSWORD = "root"
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

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
            print(f"[+] SSH connection to {ATTACKED_VM_IP} established successfully.")
        except Exception as e:
            print(f"[-] Error connecting to VM: {e}")
            raise

        if not OPENAI_API_KEY:
            raise ValueError("OpenAI API Key not found. Please set OPENAI_API_KEY environment variable.")

        # Initialize LangChain with OpenAI
        self.llm = ChatOpenAI(model="gpt-4o-mini", api_key=OPENAI_API_KEY)
        self.parser = PydanticOutputParser(pydantic_object=MitigationAction)
        self.prompt = self._create_prompt()

    def _create_prompt(self):
        """
        Create a LangChain prompt for generating mitigation actions as Linux commands.
        """
        template = """
        You are an advanced cybersecurity assistant tasked with analyzing security incident descriptions on a Linux system and generating precise, safe, and effective mitigation commands to stop attacks, particularly DoS and SYN flood attacks. The system uses UFW (Uncomplicated Firewall) for firewall management and supports iptables for advanced rules. Commands will be executed via SSH on a Linux VM. The agent automatically handles 'sudo' authentication, so do NOT include 'sudo' or password-related prefixes (e.g., 'echo "<password>" | sudo -S') in your commands.

        ### Guidelines:
        - **Attack Types**: Prioritize DoS attacks (e.g., SYN flood, UDP flood, ICMP flood), but also handle:
          - Malware/Processes (e.g., kill processes, quarantine files).
          - Authentication attacks (e.g., lock users, update SSH configs).
          - Resource abuse (e.g., limit processes, check for crypto miners).
          - System vulnerabilities (e.g., close ports, update packages).
        - **Command Specificity**:
          - **DoS Mitigation (e.g., SYN Flood)**:
            - For DoS attacks with a known attacker IP, insert a high-priority UFW rule: `ufw insert 1 deny from <IP> to any` to block all traffic from the IP across all ports and protocols.
            - Use iptables for SYN flood protection, inserting rules at the top: `iptables -I INPUT -p tcp --syn -s <IP> -m connlimit --connlimit-above 20 -j DROP` to limit concurrent connections per IP, and `iptables -I INPUT -p tcp --syn -m limit --limit 5/second --limit-burst 10 -j ACCEPT` with `iptables -I INPUT -p tcp --syn -j DROP` for global SYN rate-limiting.
            - Tune kernel parameters for SYN floods: `sysctl -w net.ipv4.tcp_syncookies=1`, `sysctl -w net.ipv4.tcp_max_syn_backlog=4096`, `sysctl -w net.ipv4.tcp_synack_retries=1`.
            - For UDP or ICMP floods, use `ufw insert 1 deny proto udp from <IP>` or `ufw insert 1 deny proto icmp from <IP>`.
            - Suggest installing Fail2Ban for dynamic blocking: `apt update && apt install -y fail2ban && systemctl enable fail2ban && systemctl start fail2ban`.
            - Suggest diagnostics: `tcpdump -i any -n host <IP> -c 100`, `iptables -L -n -v`, `ufw status`, `netstat -s | grep -i syn`.
          - **IP Blocking (IPv4/IPv6)**:
            - Use `ufw insert 1 deny from <IP> to any` for immediate blocking, ensuring high priority.
            - For specific ports, use `ufw insert 1 deny from <IP> to any port <port> proto <protocol>`.
          - For process mitigation, use `kill -9 <PID>` or `pkill -f <process_name>`.
          - For user mitigation, use `usermod -L <user>` or `passwd -l <user>`.
          - For service issues, use `systemctl stop/restart <service>`.
        - **Safety**:
          - Avoid destructive commands (e.g., `rm -rf /`, `mkfs`, `dd`, `reboot`, `shutdown`).
          - Do not modify critical system files (e.g., `/etc/passwd`, `/etc/shadow`) unless justified.
          - Avoid broad rules (e.g., `ufw deny from 0.0.0.0/0`).
          - Clear conflicting rules: `iptables -F INPUT` and `ufw reset` (with caution) if needed.
          - Validate commands to ensure they target specific threats.
        - **Context Awareness**:
          - Assume common Linux services (e.g., SSH, Apache, Nginx, MySQL).
          - Tailor commands to the incident (e.g., prioritize SYN flood mitigation for TCP-based DoS).
          - If attack details are unclear, include diagnostics (e.g., `tcpdump -i any host <IP> -n -c 100`, `grep <IP> /var/log/syslog`).
        - **Fallback**:
          - If the description is vague, return diagnostic commands (e.g., `tcpdump`, `ss -tuln`, `lsof -i`) and explain in the description.
          - If no mitigation is possible, return an empty command list with an explanation.

        ### JSON Output Format:
        {format_instructions}

        ### Input Description:
        {input_description}
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
            print(f"[-] Error generating action: {e}")
            return MitigationAction(commands=[], description="Failed to generate mitigation action due to parsing error.")

    def validate_command(self, command: str) -> bool:
        """
        Validate that a command is safe to execute.
        Returns True if safe, False if potentially dangerous.
        """
        # Block dangerous patterns (e.g., recursive deletes, reboots, etc.)
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
                print(f"[-] Command blocked for safety: {command}")
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
            print("Invalid input. Please enter 'yes' or 'no'.")

    def execute_mitigation_action(self, action: MitigationAction):
        """
        Execute the dynamically generated mitigation commands on the VM with sudo password.
        """
        if not action.commands:
            print(f"[-] No commands to execute: {action.description}")
            return

        print(f"[+] Proposed mitigation: {action.description}")
        print("[*] Commands to execute:")
        for cmd in action.commands:
            print(f"  - {cmd}")

        if not self.confirm_action("Do you want to execute these commands?"):
            print("[*] Mitigation action canceled.")
            return

        safe_password = SUDO_PASSWORD.replace("'", "'\\''")
        for command in action.commands:
            if not self.validate_command(command):
                print(f"[-] Skipping unsafe command: {command}")
                continue

            # Prefix all commands with sudo and password
            full_command = f"echo '{safe_password}' | sudo -S {command}"

            print(f"[*] Executing command: {full_command.replace(safe_password, '****')}")
            try:
                stdin, stdout, stderr = self.ssh_client.exec_command(full_command)
                exit_status = stdout.channel.recv_exit_status()
                output = stdout.read().decode()
                error = stderr.read().decode()
                if exit_status != 0:
                    print(f"[-] Command failed with exit status {exit_status}: {error}")
                else:
                    print(f"[+] Command executed successfully: {output or 'No output'}")
            except Exception as e:
                print(f"[-] Error executing command: {e}")

    def run(self):
        """
        Main loop to process incident descriptions and generate mitigation actions.
        """
        try:
            print(f"[+] Connected to VM at {ATTACKED_VM_IP}. Waiting for incident descriptions...")
            print("[*] Enter a description of the security incident (e.g., 'Suspicious traffic from 10.71.0.120' or 'Process 1234 is malicious').")
            while True:
                incident_description = input("\nEnter incident description: ").strip()
                if not incident_description:
                    print("[-] Empty input. Please enter a valid description.")
                    continue

                if not self.confirm_action("Do you want to proceed with analyzing this incident?"):
                    print("[*] Incident analysis canceled.")
                    continue

                action = self.generate_action(incident_description)
                print(f"[+] Inferred mitigation: {action.description}")
                if action.commands:
                    print("[*] Proposed commands:")
                    for cmd in action.commands:
                        print(f"  - {cmd}")
                else:
                    print("[-] No mitigation commands proposed.")

                if action.commands and self.confirm_action("Do you want to execute these mitigation commands?"):
                    self.execute_mitigation_action(action)
                else:
                    print("[*] Mitigation action skipped.")
        except KeyboardInterrupt:
            print("\n[!] Stopping mitigation agent...")
        finally:
            self.ssh_client.close()

if __name__ == "__main__":
    try:
        agent = MitigationAgent()
        agent.run()
    except Exception as e:
        print(f"[!] Failed to initialize mitigation agent: {e}")