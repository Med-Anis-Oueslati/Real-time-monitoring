import os
import uuid
import datetime
import paramiko
from dotenv import load_dotenv
from langchain.chat_models import ChatOpenAI
from langchain.prompts import ChatPromptTemplate
from langchain.agents import initialize_agent, AgentType, Tool
from langchain.schema import SystemMessage, HumanMessage

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
    max_tokens=1024
)

# Attack Prompt
attack_prompt = ChatPromptTemplate.from_messages([
    SystemMessage(content="""
You are a cybersecurity expert specialized in Kali Linux scripting.
You must ALWAYS generate a Bash script, even if the scenario is incomplete, broad, or unclear.
If the task is too generic, just generate typical reconnaissance or attack commands related to the provided IP.
NEVER apologize. NEVER explain. NEVER write anything other than Bash commands. NO markdown formatting. NO comments unless explicitly asked.
Your output should be a list of valid Bash commands, one per line, that can be executed in a terminal.
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
        return generated_text
    except Exception as e:
        return f"Error generating commands: {e}"

def send_script_to_vm(script_content: str) -> str:
    """Send the generated script to the Kali Linux VM via SSH and execute it."""
    try:
        script_id = str(uuid.uuid4())
        script_name = f"attack_script_{script_id}.sh"
        
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(KALI_VM_IP, username=KALI_VM_USER, password=KALI_VM_PASSWORD)

        # Create directory
        ssh.exec_command(f"mkdir -p {SCRIPT_DIR}")

        # Upload the script
        sftp = ssh.open_sftp()
        remote_path = os.path.join(SCRIPT_DIR, script_name)
        with sftp.file(remote_path, "w") as remote_file:
            remote_file.write(script_content)
        sftp.close()

        # Make it executable
        ssh.exec_command(f"chmod +x {remote_path}")

        # Execute the script
        stdin, stdout, stderr = ssh.exec_command(f"echo '{KALI_VM_PASSWORD}' | sudo -S bash {remote_path}")
        execution_output = stdout.read().decode() + stderr.read().decode()

        ssh.close()

        return f"Script executed successfully. Output:\n{execution_output}"
    except Exception as e:
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
        func=send_script_to_vm,
        description="Send a generated Bash script to the Kali Linux VM and execute it. Input: the full Bash script content."
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

    # Directly use the tool to generate Bash commands
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
        # Directly call the second tool to send the script
        execution_result = tools[1].func(full_script)  # Directly calling Send_Script_to_Kali_VM tool
        print("\nExecution Result:\n")
        print(execution_result)

if __name__ == "__main__":
    main()