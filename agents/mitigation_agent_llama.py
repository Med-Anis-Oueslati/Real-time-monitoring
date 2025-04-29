import paramiko
from llama_cpp import Llama
import re

class MitigationAgent:
    def __init__(self, vm_ip, model_path, sudo_password):
        # Initialize SSH connection to the attacked VM
        self.vm_ip = vm_ip
        self.sudo_password = sudo_password  # Store sudo password securely
        self.ssh_client = paramiko.SSHClient()
        self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            self.ssh_client.connect(self.vm_ip, username="anis", key_filename="/home/anis/.ssh/id_rsa")
            print(f"SSH connection to {self.vm_ip} established successfully.")
        except Exception as e:
            print(f"Error connecting to VM: {e}")
            raise

        # Load the LLM model
        self.llm = self.load_llm(model_path)

    def load_llm(self, model_path):
        """
        Load the GGUF model using llama-cpp-python.
        """
        try:
            llm = Llama(
                model_path=model_path,
                n_ctx=2048,      # Context size
                n_threads=4,     # Number of CPU threads
                n_gpu_layers=20, # Number of layers to offload to GPU (if applicable)
                use_mlock=True   # Use memory locking to avoid swapping
            )
            print("LLM loaded successfully.")
            return llm
        except Exception as e:
            print(f"Error loading LLM: {e}")
            return None

    def generate_response(self, action_description):
        """
        Generate a response from the LLM, instructing it to extract only the IP address.
        """
        if not self.llm:
            print("LLM is not loaded.")
            return None

        # Craft a prompt that instructs the LLM to return only the IP address
        prompt = (
            "You are a cybersecurity assistant. Given a mitigation action description, "
            "extract and return only the IP address (in the format xxx.xxx.xxx.xxx) "
            "without any additional text or explanation. If no IP address is found, return 'None'. "
            "Example input: 'The mitigation action is to block IP 192.168.1.100.' "
            "Example output: 192.168.1.100\n\n"
            f"Input: {action_description}\nOutput:"
        )

        try:
            response = self.llm(prompt, max_tokens=20, stop=["\n"])  # Limit tokens and stop at newline
            ip_address = response["choices"][0]["text"].strip()
            return ip_address if ip_address != "None" else None
        except Exception as e:
            print(f"Error generating response: {e}")
            return None

    def validate_ip_address(self, ip):
        """
        Validate that the extracted text is a valid IP address.
        """
        ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
        if not re.match(ip_pattern, ip):
            return False
        # Additional validation: ensure each octet is between 0 and 255
        octets = ip.split('.')
        return all(0 <= int(octet) <= 255 for octet in octets)

    def confirm_action(self, message):
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
            else:
                print("Invalid input. Please enter 'yes' or 'no'.")

    def execute_mitigation_action(self, attacker_ip):
        """
        Execute mitigation actions to block the attacker's IP using ufw and iptables.
        Optionally flush iptables and reset ufw to clear conflicting rules.
        """
        print(f"Blocking IP: {attacker_ip}")
        safe_password = self.sudo_password.replace("'", "'\\''")

        # Ask user if they want to flush iptables and reset ufw
        if self.confirm_action("Do you want to flush iptables and reset ufw to avoid conflicts? (Warning: This clears all firewall rules)"):
            commands = [
                f"echo '{safe_password}' | sudo -S iptables -F",  # Flush iptables
                f"echo '{safe_password}' | sudo -S iptables -t nat -F",  # Flush NAT table
                f"echo '{safe_password}' | sudo -S iptables -t mangle -F",  # Flush mangle table
                f"echo '{safe_password}' | sudo -S sh -c 'echo y | ufw reset'",  # Reset ufw with confirmation
                f"echo '{safe_password}' | sudo -S sh -c 'echo y | ufw enable'",  # Enable ufw with confirmation
                f"echo '{safe_password}' | sudo -S ufw deny from {attacker_ip}",  # Block all traffic
                f"echo '{safe_password}' | sudo -S iptables -A INPUT -p icmp -s {attacker_ip} -j DROP",  # Block ICMP via iptables
                f"echo '{safe_password}' | sudo -S ufw logging on"  # Enable logging
            ]
        else:
            commands = [
                f"echo '{safe_password}' | sudo -S ufw reload",  # Reload ufw
                f"echo '{safe_password}' | sudo -S sh -c 'echo y | ufw enable'",  # Enable ufw with confirmation
                f"echo '{safe_password}' | sudo -S ufw deny from {attacker_ip}",  # Block all traffic
                f"echo '{safe_password}' | sudo -S iptables -A INPUT -p icmp -s {attacker_ip} -j DROP",  # Block ICMP via iptables
                f"echo '{safe_password}' | sudo -S ufw logging on"  # Enable logging
            ]

        for command in commands:
            print(f"Executing command: {command.replace(safe_password, '****')}")
            try:
                stdin, stdout, stderr = self.ssh_client.exec_command(command)
                exit_status = stdout.channel.recv_exit_status()  # Get command exit status
                output = stdout.read().decode()
                error = stderr.read().decode()
                if exit_status != 0:
                    print(f"Command failed with exit status {exit_status}: {error}")
                    if "ufw enable" in command:
                        raise RuntimeError("Failed to enable ufw; mitigation aborted to prevent insecure state")
                else:
                    print(f"Command executed successfully: {output or 'No output'}")
            except Exception as e:
                print(f"Error executing command: {e}")
                if "ufw enable" in command:
                    raise RuntimeError("Failed to enable ufw; mitigation aborted to prevent insecure state")

    def run(self):
        try:
            print(f"Connected to VM at {self.vm_ip}. Waiting for mitigation actions...")
            while True:
                # Step 1: Receive mitigation action description
                action_description = input("Enter mitigation action description: ")

                # Step 2: Confirm the action description
                if not self.confirm_action("Do you want to proceed with analyzing this action?"):
                    print("Action analysis canceled.")
                    continue

                # Step 3: Generate LLM response (expecting only the IP address)
                attacker_ip = self.generate_response(action_description)
                if attacker_ip:
                    print(f"Extracted IP to block: {attacker_ip}")

                    # Step 4: Validate the IP address
                    if not self.validate_ip_address(attacker_ip):
                        print("Invalid IP address extracted. Action canceled.")
                        continue

                    # Step 5: Confirm the mitigation action
                    if self.confirm_action(f"Do you want to block IP {attacker_ip}?"):
                        # Step 6: Execute the mitigation action
                        self.execute_mitigation_action(attacker_ip)
                    else:
                        print("Mitigation action canceled.")
                else:
                    print("Could not extract an IP address from the action description.")
        except KeyboardInterrupt:
            print("Stopping mitigation agent...")
        except RuntimeError as e:
            print(f"Mitigation failed: {e}")
        finally:
            self.ssh_client.close()

if __name__ == "__main__":
    # Prompt for the attacked VM's IP address and sudo password
    vm_ip = input("Enter the IP address of the attacked VM: ")
    sudo_password = input("Enter the sudo password for the VM: ")

    # Path to the GGUF model file
    model_path = "/home/anis/PFE/models/llama-2-7b.Q4_K_M.gguf"

    # Initialize and run the mitigation agent
    try:
        agent = MitigationAgent(vm_ip, model_path, sudo_password)
        agent.run()
    except Exception as e:
        print(f"Failed to initialize mitigation agent: {e}")