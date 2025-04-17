import uuid
import datetime
from llama_cpp import Llama

# Path to your GGUF model
MODEL_PATH = "/home/anis/PFE/models/deepseek-coder-6.7b-base.Q4_K_M.gguf"

def load_llm():
    """Load a local GGUF model using llama-cpp-python."""
    llm = Llama(
        model_path=MODEL_PATH,
        n_ctx=2048,
        n_threads=4,
        n_gpu_layers=20,  # Adjust based on your GPU capacity
        use_mlock=True  # Prevent swapping
    )
    return llm

def generate_commands_with_llm(llm, ip_address, attack_scenario):
    """Generate bash commands using the local LLM."""
    prompt = f"""
### Task:
Generate a bash script for penetration testing.

### Target:
IP: {ip_address}
Scenario: {attack_scenario}

### Output Format:
Just return the bash commands, no explanations.


### Script:
"""

    output = llm(
    prompt,
    max_tokens=256,
    temperature=0.7,
    top_p=0.9,
)
    generated_text = output["choices"][0]["text"]

    commands = generated_text.strip().split("\n")
    return [cmd.strip() for cmd in commands if cmd.strip()]

def generate_bash_script(ip_address, attack_scenario, llm):
    """Generates a bash script for the specified attack."""
    script_id = str(uuid.uuid4())
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    commands = generate_commands_with_llm(llm, ip_address, attack_scenario)

    script_content = [
        "#!/bin/bash",
        f"# Generated Attack Script - ID: {script_id}",
        f"# Target: {ip_address}",
        f"# Scenario: {attack_scenario}",
        f"# Generated on: {timestamp}",
        "",
        "echo 'Starting attack...'"
    ]

    script_content.extend(commands)

    script_content.extend([
        "",
        "echo 'Attack completed.'",
        f"echo 'Results saved for {attack_scenario} on {ip_address}'"
    ])

    return "\n".join(script_content)

def main():
    print("Loading Deepseek-Coder 6.7B model...")
    llm = load_llm()

    ip_address = input("Enter the Lubuntu VM IP address: ")
    attack_scenario = input("Enter the attack scenario (e.g., port_scan, service_enumeration): ")

    bash_script = generate_bash_script(ip_address, attack_scenario, llm)

    print("\nGenerated Bash Script:\n")
    print("```bash")
    print(bash_script)
    print("```")

if __name__ == "__main__":
    main()
