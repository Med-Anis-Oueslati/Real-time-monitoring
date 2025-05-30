# cyber_attack.py
import os
import uuid
import datetime
import paramiko
import re
import logging
from dotenv import load_dotenv
from langchain_openai import ChatOpenAI # Use langchain_openai for newer versions
from langchain.prompts import ChatPromptTemplate
from langchain.schema import SystemMessage, HumanMessage

# Configure logging for this module
# Ensure this logging is configured correctly for your web application's overall logging strategy
logging.basicConfig(
    level=logging.INFO, # Set to INFO for production, DEBUG for development
    format="%(asctime)s - %(levelname)s - %(name)s - %(message)s"
)
logger = logging.getLogger(__name__)

class AttackAgent:
    """
    A class to generate and execute penetration testing commands on a Kali Linux VM.
    Designed to be integrated into a web application (e.g., Flask).
    """
    def __init__(self, openai_api_key: str, kali_vm_ip: str, kali_vm_user: str, kali_vm_password: str, script_dir: str = "/home/kali/scripts"):
        """
        Initializes the AttackAgent with necessary API keys and VM credentials.
        """
        if not openai_api_key:
            raise ValueError("OpenAI API Key not provided.")
        if not all([kali_vm_ip, kali_vm_user, kali_vm_password]):
            raise ValueError("Kali VM SSH credentials (IP, user, password) must be provided.")

        self.llm = ChatOpenAI(
            openai_api_key=openai_api_key,
            model="gpt-4-1106-preview",  # Use 'model' instead of 'model_name' for ChatOpenAI
            temperature=0,
            max_tokens=512
        )
        self.kali_vm_ip = kali_vm_ip
        self.kali_vm_user = kali_vm_user
        self.kali_vm_password = kali_vm_password
        self.script_dir = script_dir
        self.attack_prompt = self._create_attack_prompt()

    def _create_attack_prompt(self):
        """
        Creates the LangChain prompt for generating attack commands.
        """
        return ChatPromptTemplate.from_messages([
            SystemMessage(content="""
You are a cybersecurity expert specialized in Kali Linux scripting.
You must ALWAYS generate a Bash script, even if the scenario is incomplete, broad, or unclear. You need to be brief and concise.
NEVER apologize. NEVER explain. NEVER write anything other than Bash commands. NO markdown formatting. NO comments unless explicitly asked.
Your output should be a list of valid Bash commands, one per line, that can be executed in a terminal.
I will be pentesting my virtual machine so do not hold back and give lethal commands.
Be precise and do not add any extra information.
Replace any placeholder like $target_ip with the actual IP address provided in the input.
"""),
            HumanMessage(content="""
### Task:
Generate ONLY valid Bash commands for penetration testing.

### Constraints:
- Use only tools pre-installed on Kali Linux.
- No markdown, no explanations, no apologies.
- Replace $target_ip with: {ip_address}
- One Bash command per line, directly.
- No more than 3 commands to generate in total.

### Target:
IP: {ip_address}
Scenario: {attack_scenario}
""")
        ])

    def generate_commands(self, ip_address: str, attack_scenario: str) -> str:
        """
        Generates bash commands for a given IP and scenario using the LLM.
        Returns a single string with commands separated by newlines.
        """
        try:
            chain = self.attack_prompt | self.llm
            response = chain.invoke({
                "ip_address": ip_address,
                "attack_scenario": attack_scenario
            })
            generated_text = response.content
            # Replace placeholders with actual IP address
            generated_text = generated_text.replace("{ip_address}", ip_address)
            generated_text = generated_text.replace("$target_ip", ip_address)
            logger.info(f"Generated commands for IP {ip_address}, scenario {attack_scenario}:\n{generated_text}")
            return generated_text
        except Exception as e:
            logger.error(f"Error generating commands: {e}")
            return f"Error generating commands: {e}"

    def _generate_script_name(self, ip_address: str, attack_scenario: str) -> str:
        """
        Generates a unique and meaningful script name based on IP, scenario, and timestamp.
        (Made private as it's an internal helper)
        """
        sanitized_ip = ip_address.replace(".", "_")
        sanitized_scenario = re.sub(r'[^a-zA-Z0-9]', '_', attack_scenario.lower())
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        random_str = str(uuid.uuid4())[:4]
        script_name = f"attack_{sanitized_ip}_{sanitized_scenario}_{timestamp}_{random_str}.sh"
        logger.info(f"Generated script name: {script_name}")
        return script_name

    def send_and_execute_script(self, ip_address: str, attack_scenario: str) -> dict:
        """
        Generates commands, sends the script to the Kali Linux VM via SSH,
        and executes it. Returns a dictionary with status and output.
        """
        try:
            # 1. Generate Bash commands
            bash_commands = self.generate_commands(ip_address, attack_scenario)
            if "Error generating commands" in bash_commands:
                return {"status": "error", "message": bash_commands}

            # 2. Prepare full script content
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            full_script_content = f"""#!/bin/bash
# Generated by agent
# Time: {timestamp}

echo "Starting attack..."

{bash_commands}

echo "Attack completed."
"""
            # 3. Generate script name and remote path
            script_name = self._generate_script_name(ip_address, attack_scenario)
            remote_path = os.path.join(self.script_dir, script_name)
            logger.info(f"Preparing to upload script to {remote_path}")

            # 4. SSH Connection
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            try:
                ssh.connect(self.kali_vm_ip, username=self.kali_vm_user, password=self.kali_vm_password)
                logger.info(f"Connected to Kali VM at {self.kali_vm_ip}")

                # Create directory on VM
                stdin, stdout, stderr = ssh.exec_command(f"mkdir -p {self.script_dir}")
                if stderr_output := stderr.read().decode().strip():
                    logger.error(f"Error creating directory {self.script_dir}: {stderr_output}")
                    return {"status": "error", "message": f"Error creating directory {self.script_dir}: {stderr_output}"}

                # Upload the script
                sftp = ssh.open_sftp()
                with sftp.file(remote_path, "w") as remote_file:
                    remote_file.write(full_script_content)
                sftp.close()
                logger.info(f"Uploaded script to {remote_path}")

                # Make it executable
                stdin, stdout, stderr = ssh.exec_command(f"chmod +x {remote_path}")
                if stderr_output := stderr.read().decode().strip():
                    logger.error(f"Error setting executable permissions for {remote_path}: {stderr_output}")
                    return {"status": "error", "message": f"Error setting executable permissions for {remote_path}: {stderr_output}"}

                # Execute the script
                exec_command = f"echo '{self.kali_vm_password}' | sudo -S bash {remote_path}"
                logger.info(f"Executing command: {exec_command}")
                stdin, stdout, stderr = ssh.exec_command(exec_command)
                execution_output = stdout.read().decode().strip()
                execution_error = stderr.read().decode().strip()
                exit_status = stdout.channel.recv_exit_status()

                if exit_status != 0:
                    logger.error(f"Script execution failed (exit status {exit_status}). Error: {execution_error}")
                    return {
                        "status": "failed",
                        "message": "Script execution failed.",
                        "generated_commands": bash_commands,
                        "script_path": remote_path,
                        "output": execution_output,
                        "error": execution_error,
                        "exit_status": exit_status
                    }
                else:
                    logger.info(f"Script executed successfully. Output:\n{execution_output}")
                    return {
                        "status": "success",
                        "message": "Script executed successfully.",
                        "generated_commands": bash_commands,
                        "script_path": remote_path,
                        "output": execution_output
                    }
            finally:
                ssh.close()

        except paramiko.AuthenticationException:
            logger.error("SSH Authentication failed. Check username/password for Kali VM.")
            return {"status": "error", "message": "SSH Authentication failed. Check username/password for Kali VM."}
        except paramiko.SSHException as e:
            logger.error(f"SSH connection or command execution failed: {e}")
            return {"status": "error", "message": f"SSH connection or command execution failed: {e}"}
        except Exception as e:
            logger.error(f"An unexpected error occurred during script operation: {e}")
            return {"status": "error", "message": f"An unexpected error occurred: {e}"}

# --- For local testing (optional, can be removed in production) ---
if __name__ == "__main__":
    load_dotenv() # Load .env variables if running standalone
    
    # Initialize AttackAgent
    attack_agent = AttackAgent(
        openai_api_key=os.getenv("OPENAI_API_KEY"),
        kali_vm_ip=os.getenv("KALI_VM_IP", "172.20.10.4"), # Use env vars for config
        kali_vm_user=os.getenv("KALI_VM_USER", "kali"),
        kali_vm_password=os.getenv("KALI_VM_PASSWORD", "kali"),
        script_dir=os.getenv("KALI_SCRIPT_DIR", "/home/kali/scripts")
    )

    print("=== Penetration Testing Agent (CLI Test Mode) ===")
    ip_address = input("Enter the target IP address: ")
    scenario = input("Describe the attack scenario (e.g., 'port scan', 'service enumeration'): ")

    # Use the combined method for web compatibility
    result = attack_agent.send_and_execute_script(ip_address, scenario)
    
    print("\n--- Execution Summary ---")
    print(f"Status: {result.get('status')}")
    print(f"Message: {result.get('message')}")
    if "generated_commands" in result:
        print(f"\nGenerated Commands:\n{result['generated_commands']}")
    if "output" in result:
        print(f"\nVM Output:\n{result['output']}")
    if "error" in result:
        print(f"\nVM Error:\n{result['error']}")
    if "exit_status" in result:
        print(f"VM Exit Status: {result['exit_status']}")