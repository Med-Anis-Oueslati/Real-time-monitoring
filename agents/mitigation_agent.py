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
        You are a cybersecurity assistant tasked with analyzing descriptions of security incidents on a Linux system running UFW (Uncomplicated Firewall) as the primary firewall manager.
        Your goal is to propose a set of safe and effective Linux commands to mitigate the described incident.
        The commands will be executed via SSH on a Linux VM. The agent will automatically handle 'sudo' authentication for commands requiring elevated privileges, so do NOT include 'sudo' or any password-related prefixes (e.g., 'echo "<password>" | sudo -S') in your commands.

        Guidelines:
        - For blocking IP addresses, use:
          - 'ufw insert 1 deny from <IP>' to block all traffic from the IP.
          - 'ufw insert 1 deny proto icmp from <IP>' to explicitly block ICMP traffic (e.g., pings).
          - Always include 'ufw reload' after modifying UFW rules.
        - If the incident description specifies an IPv6 address, use 'ufw insert 1 deny from <IPv6>' and 'ufw insert 1 deny proto icmp from <IPv6>' for IPv6 blocking.
        - For other mitigations (e.g., killing a process, disabling a user, restarting a service), use appropriate Linux commands (e.g., 'kill -9 <PID>', 'usermod -L <user>', 'systemctl restart <service>').
        - Do NOT include 'sudo' in the commands; the agent will add it as needed.
        - Ensure commands are safe and avoid destructive actions (e.g., do not suggest 'rm -rf /', do not modify critical system files without clear justification).
        - If the description is unclear or insufficient, return an empty list of commands and explain why in the description field.
        - Provide a brief description of the proposed mitigation action.

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