import os
import json
import logging
from typing import TypedDict, List, Optional, Dict
from langgraph.graph import StateGraph, END
from dotenv import load_dotenv
from datetime import datetime
from langchain_openai import ChatOpenAI
from langchain.prompts import ChatPromptTemplate
from conversational_agent import process_query, AgentState as ConvAgentState
from cyber_attack import generate_commands, send_script_to_vm
from mitigation_agent import MitigationAgent, MitigationAction

# Configure logging for SIEM auditing
logging.basicConfig(
    filename="siem_orchestration.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# Load environment variables
load_dotenv()
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

# Initialize LLM for decision-making
llm = ChatOpenAI(model="gpt-4o-mini", api_key=OPENAI_API_KEY)

# Define the orchestration state
class OrchestrationState(TypedDict):
    user_input: str
    use_case: str  # e.g., "threat_detection", "attack_simulation", "incident_response"
    conversation_output: Optional[Dict]
    attack_output: Optional[str]
    mitigation_output: Optional[str]
    final_report: Optional[str]
    conversation_history: List[dict]
    incident_description: Optional[str]
    target_ip: Optional[str]
    attack_scenario: Optional[str]
    error: Optional[str]

# Decision prompt to classify use case and determine next steps
decision_prompt = ChatPromptTemplate.from_template("""
You are an orchestration agent for a SIEM system coordinating three agents:
1. Conversational Agent: Queries Snowflake logs from a Lubuntu VM.
2. Attack Simulation Agent: Runs attack scripts on a Kali Linux VM.
3. Mitigation Agent: Executes mitigation commands on the Lubuntu VM.

Classify the user's request into a use case and decide the next action. Return a JSON object with:
- "use_case": one of ["threat_detection", "attack_simulation", "incident_response", "combined"]
- "next_action": one of ["query_logs", "simulate_attack", "mitigate_threat", "generate_report", "stop"]
- "target_ip": IP address to use (if applicable, default to "10.71.0.162" for Lubuntu VM)
- "attack_scenario": attack scenario to simulate (if applicable, e.g., "port scan")
- "incident_description": description for mitigation (if applicable)

User Input: {user_input}
Conversation Agent Output: {conversation_output}
Attack Simulation Output: {attack_output}

Guidelines:
- If the user requests log analysis (e.g., "check logs", "suspicious traffic"), set "use_case" to "threat_detection" and "next_action" to "query_logs".
- If the user requests an attack simulation (e.g., "simulate port scan"), set "use_case" to "attack_simulation" and "next_action" to "simulate_attack".
- If the user requests mitigation (e.g., "block IP", "secure system"), set "use_case" to "incident_response" and "next_action" to "mitigate_threat".
- If the user requests a full workflow (e.g., "investigate and secure"), set "use_case" to "combined" and start with "next_action" as "query_logs".
- If logs show suspicious activity (e.g., specific IP or traffic), set "next_action" to "simulate_attack" with extracted "target_ip" and "attack_scenario".
- If attack simulation confirms a threat, set "next_action" to "mitigate_threat" with an "incident_description".
- If no further actions are needed, set "next_action" to "generate_report".
- If the input is invalid or no threats are found, set "next_action" to "stop".
- Default "target_ip" to "10.71.0.162" (Lubuntu VM) unless specified.

Return only the JSON object.
""")

def initialize_mitigation_agent() -> MitigationAgent:
    """Initialize the Mitigation Agent for the Lubuntu VM."""
    try:
        return MitigationAgent()
    except Exception as e:
        logging.error(f"Failed to initialize Mitigation Agent: {e}")
        raise

def validate_ip(ip: str) -> bool:
    """Validate an IP address."""
    import re
    ipv4_pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    ipv6_pattern = r"^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$"
    return bool(re.match(ipv4_pattern, ip) or re.match(ipv6_pattern, ip))

def decide_next_action(state: OrchestrationState) -> OrchestrationState:
    """Decide the use case and next action based on current state."""
    try:
        chain = decision_prompt | llm
        conversation_output = state["conversation_output"] or {}
        attack_output = state["attack_output"] or ""
        response = chain.invoke({
            "user_input": state["user_input"],
            "conversation_output": str(conversation_output.get("output", "")),
            "attack_output": attack_output
        })
        decision = json.loads(response.content)
        state["use_case"] = decision["use_case"]
        state["target_ip"] = decision.get("target_ip", "10.71.0.162")  # Default to Lubuntu VM
        state["attack_scenario"] = decision.get("attack_scenario")
        state["incident_description"] = decision.get("incident_description")
        logging.info(f"Decision: use_case={state['use_case']}, next_action={decision['next_action']}, target_ip={state['target_ip']}")
        return state
    except Exception as e:
        state["error"] = f"Error deciding next action: {str(e)}"
        logging.error(state["error"])
        return state

def query_logs(state: OrchestrationState) -> OrchestrationState:
    """Invoke Conversational Agent to query Snowflake logs from Lubuntu VM."""
    try:
        result = process_query(state["user_input"], state["conversation_history"])
        state["conversation_output"] = result
        state["conversation_history"] = result["conversation_history"]
        logging.info(f"Conversational Agent output: {result['output'][:100]}...")
        return state
    except Exception as e:
        state["conversation_output"] = {"output": f"Error querying logs: {str(e)}"}
        state["error"] = str(e)
        logging.error(f"Error in query_logs: {e}")
        return state

def simulate_attack(state: OrchestrationState) -> OrchestrationState:
    """Invoke Attack Simulation Agent to run attack scripts on Kali VM."""
    target_ip = state["target_ip"]
    attack_scenario = state["attack_scenario"] or "port scan"
    if not target_ip or not validate_ip(target_ip):
        state["attack_output"] = f"Error: Invalid or missing target IP ({target_ip})."
        state["error"] = state["attack_output"]
        logging.error(state["attack_output"])
        return state
    try:
        bash_commands = generate_commands(target_ip, attack_scenario)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        full_script = f"""#!/bin/bash
# Generated by orchestration agent for Kali VM
# Time: {timestamp}

echo "Starting attack on {target_ip}..."

{bash_commands}

echo "Attack completed."
"""
        execution_result = send_script_to_vm(full_script)
        state["attack_output"] = f"Generated Commands:\n{bash_commands}\n\nExecution Result:\n{execution_result}"
        logging.info(f"Attack Simulation output: {execution_result[:100]}...")
    except Exception as e:
        state["attack_output"] = f"Error simulating attack: {str(e)}"
        state["error"] = str(e)
        logging.error(f"Error in simulate_attack: {e}")
    return state

def mitigate_threat(state: OrchestrationState) -> OrchestrationState:
    """Invoke Mitigation Agent to secure the Lubuntu VM."""
    incident_description = state["incident_description"]
    if not incident_description:
        state["mitigation_output"] = "Error: No incident description provided for mitigation."
        state["error"] = state["mitigation_output"]
        logging.error(state["mitigation_output"])
        return state
    try:
        mitigation_agent = initialize_mitigation_agent()
        action = mitigation_agent.generate_action(incident_description)
        if action.commands:
            mitigation_agent.execute_mitigation_action(action)
            state["mitigation_output"] = f"Mitigation: {action.description}\nCommands:\n" + "\n".join([f"  - {cmd}" for cmd in action.commands])
            logging.info(f"Mitigation applied: {action.description}")
        else:
            state["mitigation_output"] = f"No mitigation commands proposed: {action.description}"
            logging.info(state["mitigation_output"])
    except Exception as e:
        state["mitigation_output"] = f"Error mitigating threat: {str(e)}"
        state["error"] = str(e)
        logging.error(f"Error in mitigate_threat: {e}")
    return state

def generate_report(state: OrchestrationState) -> OrchestrationState:
    """Generate a final report summarizing all actions."""
    report = ["=== SIEM Orchestration Report ==="]
    report.append(f"User Request: {state['user_input']}")
    report.append(f"Use Case: {state['use_case']}")
    report.append("\nLog Analysis (Lubuntu VM):")
    conv_output = state["conversation_output"] or {}
    report.append(conv_output.get("output", "No log analysis performed."))
    report.append("\nAttack Simulation (Kali VM):")
    report.append(state["attack_output"] or "No attack simulation performed.")
    report.append("\nMitigation Actions (Lubuntu VM):")
    report.append(state["mitigation_output"] or "No mitigation actions performed.")
    if state["error"]:
        report.append("\nErrors:")
        report.append(state["error"])
    report.append("\n=== End of Report ===")
    state["final_report"] = "\n".join(report)
    logging.info("Final report generated.")
    return state

def build_orchestration_graph():
    """Build the LangGraph workflow for SIEM orchestration."""
    workflow = StateGraph(OrchestrationState)
    
    # Define nodes
    workflow.add_node("decide_next_action", decide_next_action)
    workflow.add_node("query_logs", query_logs)
    workflow.add_node("simulate_attack", simulate_attack)
    workflow.add_node("mitigate_threat", mitigate_threat)
    workflow.add_node("generate_report", generate_report)
    
    # Define conditional edges based on decision
    def route_action(state: OrchestrationState):
        if state.get("error"):
            return "generate_report"  # Generate report if an error occurs
        try:
            decision = json.loads((decision_prompt | llm).invoke({
                "user_input": state["user_input"],
                "conversation_output": str(state["conversation_output"].get("output", "") if state["conversation_output"] else ""),
                "attack_output": state["attack_output"] or ""
            }).content)
            next_action = decision["next_action"]
            logging.info(f"Routing to next_action: {next_action}")
            return next_action
        except Exception as e:
            logging.error(f"Error in routing: {e}")
            return "generate_report"
    
    workflow.add_conditional_edges(
        "decide_next_action",
        route_action,
        {
            "query_logs": "query_logs",
            "simulate_attack": "simulate_attack",
            "mitigate_threat": "mitigate_threat",
            "generate_report": "generate_report",
            "stop": END
        }
    )
    
    # Define sequential edges
    workflow.add_edge("query_logs", "decide_next_action")
    workflow.add_edge("simulate_attack", "decide_next_action")
    workflow.add_edge("mitigate_threat", "decide_next_action")
    workflow.add_edge("generate_report", END)
    
    # Set entry point
    workflow.set_entry_point("decide_next_action")
    
    return workflow.compile()

def main():
    """Main function to run the SIEM orchestration agent."""
    print("=== SIEM Orchestration Agent ===")
    print("Enter a SIEM task (e.g., 'Check for suspicious traffic on Lubuntu VM', 'Simulate port scan on 10.71.0.162', 'Investigate and secure system').")
    print("Type 'exit' to quit.")
    
    conversation_history = []
    graph = build_orchestration_graph()
    
    while True:
        user_input = input("\nEnter your task: ").strip()
        if user_input.lower() == "exit":
            print("Goodbye!")
            logging.info("Orchestration agent stopped.")
            break
        if not user_input:
            print("Please enter a valid task.")
            logging.warning("Empty user input received.")
            continue
        
        state = OrchestrationState(
            user_input=user_input,
            use_case="",
            conversation_output=None,
            attack_output=None,
            mitigation_output=None,
            final_report=None,
            conversation_history=conversation_history,
            incident_description=None,
            target_ip=None,
            attack_scenario=None,
            error=None
        )
        
        try:
            final_state = graph.invoke(state)
            print("\nFinal Report:")
            print(final_state["final_report"])
            conversation_history = final_state["conversation_history"]
            logging.info(f"Task completed: {user_input}")
        except Exception as e:
            error_msg = f"Error processing task: {str(e)}"
            print(error_msg)
            logging.error(error_msg)

if __name__ == "__main__":
    main()