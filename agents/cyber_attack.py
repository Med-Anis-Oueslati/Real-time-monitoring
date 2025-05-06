import os
import uuid
import datetime
import paramiko
import re
import logging
from dotenv import load_dotenv
from langchain.chat_models import ChatOpenAI
from langchain.prompts import ChatPromptTemplate
from langchain.agents import initialize_agent, AgentType, Tool
from langchain.schema import SystemMessage, HumanMessage

# Configure logging for debugging
logging.basicConfig(
    filename="attack_simulation.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# Load environment variables
load_dotenv()
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

# SSH Configuration
KALI_VM_IP = "10.71.0.120"
KALI_VM_USER = "kali"
KALI_VM_PASSWORD = "kali"
SCRIPT_DIR = "/home/kali/scripts"

# Initialize LLM for ReAct agent
llm = ChatOpenAI(
    openai_api_key=OPENAI_API_KEY,
    model_name="gpt-4-1106-preview",  # appropriate for ReAct / tool-calling
    temperature=0,
    max_tokens=512
)

# Attack Prompt
attack_prompt = ChatPromptTemplate.from_messages([
    SystemMessage(content="""
You are a cybersecurity expert specialized in Kali Linux scripting.
You must ALWAYS generate a Bash script, even if the scenario is incomplete, broad, or unclear.You need to be brief and concise.
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

### Target:
IP: {ip_address}
Scenario: {attack_scenario}
""")
])

def generate_commands(ip_address: str, attack_scenario: str) -> str:
    """Generate bash commands for a given IP and scenario."""
    try:
        chain = attack_prompt | llm
        response = chain.invoke({
            "ip_address": ip_address,
            "attack_scenario": attack_scenario
        })
        generated_text = response.content
        # Replace placeholders with actual IP address
        generated_text = generated_text.replace("{ip_address}", ip_address)
        generated_text = generated_text.replace("$target_ip", ip_address)  # In case GPT uses $target_ip
        logging.info(f"Generated commands for IP {ip_address}, scenario {attack_scenario}:\n{generated_text}")
        return generated_text
    except Exception as e:
        logging.error(f"Error generating commands: {e}")
        return f"Error generating commands: {e}"

def generate_script_name(ip_address: str, attack_scenario: str) -> str:
    """Generate a unique and meaningful script name based on IP, scenario, and timestamp."""
    # Sanitize IP address (replace dots with underscores)
    sanitized_ip = ip_address.replace(".", "_")
    # Sanitize attack scenario (remove spaces, special characters, convert to lowercase)
    sanitized_scenario = re.sub(r'[^a-zA-Z0-9]', '_', attack_scenario.lower())
    # Get timestamp in YYYYMMDD_HHMMSS format
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    # Generate a short random string for uniqueness (4 characters)
    random_str = str(uuid.uuid4())[:4]
    # Combine components into a meaningful filename
    script_name = f"attack_{sanitized_ip}_{sanitized_scenario}_{timestamp}_{random_str}.sh"
    logging.info(f"Generated script name: {script_name}")
    return script_name

def send_script_to_vm(script_content: str, ip_address: str, attack_scenario: str) -> str:
    """Send the generated script to the Kali Linux VM via SSH and execute it."""
    try:
        # Generate meaningful script name
        script_name = generate_script_name(ip_address, attack_scenario)
        remote_path = os.path.join(SCRIPT_DIR, script_name)
        logging.info(f"Preparing to upload script to {remote_path}")

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(KALI_VM_IP, username=KALI_VM_USER, password=KALI_VM_PASSWORD)
        logging.info(f"Connected to Kali VM at {KALI_VM_IP}")

        # Create directory
        stdin, stdout, stderr = ssh.exec_command(f"mkdir -p {SCRIPT_DIR}")
        if stderr.read().decode():
            logging.error(f"Error creating directory {SCRIPT_DIR}: {stderr.read().decode()}")
            ssh.close()
            return f"Error creating directory {SCRIPT_DIR}"

        # Upload the script
        sftp = ssh.open_sftp()
        with sftp.file(remote_path, "w") as remote_file:
            remote_file.write(script_content)
        sftp.close()
        logging.info(f"Uploaded script to {remote_path}")

        # Make it executable
        stdin, stdout, stderr = ssh.exec_command(f"chmod +x {remote_path}")
        if stderr.read().decode():
            logging.error(f"Error setting executable permissions for {remote_path}: {stderr.read().decode()}")
            ssh.close()
            return f"Error setting executable permissions for {remote_path}"

        # Execute the script
        exec_command = f"echo '{KALI_VM_PASSWORD}' | sudo -S bash {remote_path}"
        logging.info(f"Executing command: {exec_command}")
        stdin, stdout, stderr = ssh.exec_command(exec_command)
        execution_output = stdout.read().decode()
        execution_error = stderr.read().decode()
        exit_status = stdout.channel.recv_exit_status()

        ssh.close()

        if exit_status != 0:
            logging.error(f"Script execution failed: {execution_error}")
            return f"Script execution failed. Error:\n{execution_error}"
        
        logging.info(f"Script executed successfully. Output:\n{execution_output}")
        return f"Script executed successfully. Output:\n{execution_output}"
    except Exception as e:
        logging.error(f"Error sending/executing script: {e}")
        return f"Error sending/executing script: {e}"

# Define Tools
tools = [
    Tool(
        name="Generate_Bash_Commands",
        func=lambda inputs: generate_commands(
            ip_address=inputs.split(",")[0].strip(),
            attack_scenario=inputs.split(",")[1].strip()
        ),
        description="Generate Bash commands for a given IP address and attack scenario. Input format: '<IP_ADDRESS>, <SCENARIO>'"
    ),
    Tool(
        name="Send_Script_to_Kali_VM",
        func=lambda inputs: send_script_to_vm(
            script_content=inputs["script_content"],
            ip_address=inputs["ip_address"],
            attack_scenario=inputs["attack_scenario"]
        ),
        description="Send a generated Bash script to the Kali Linux VM and execute it. Input: a dictionary with 'script_content', 'ip_address', and 'attack_scenario'."
    )
]

# Initialize ReAct agent
agent = initialize_agent(
    tools=tools,
    llm=llm,
    agent=AgentType.OPENAI_FUNCTIONS,  # ReAct style agent with tool selection
    verbose=True,
)

def main():
    print("=== Penetration Testing Agent ===")
    ip_address = input("Enter the target IP address: ")
    scenario = input("Describe the attack scenario (e.g., 'port scan', 'service enumeration'): ")

    # Generate Bash commands
    user_request = f"{ip_address}, {scenario}"
    bash_commands = tools[0].func(user_request)  # Directly calling Generate_Bash_Commands tool
    print("\nGenerated Bash Commands:\n")
    print(bash_commands)

    send_now = input("\nDo you want to send and execute this script on the Kali VM? (y/n): ").strip().lower()
    if send_now == "y":
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        full_script = f"""#!/bin/bash
# Generated by agent
# Time: {timestamp}

echo "Starting attack..."

{bash_commands}

echo "Attack completed."
"""
        # Call Send_Script_to_Kali_VM tool with a dictionary input
        execution_result = tools[1].func({
            "script_content": full_script,
            "ip_address": ip_address,
            "attack_scenario": scenario
        })
        print("\nExecution Result:\n")
        print(execution_result)

if __name__ == "__main__":
    main()