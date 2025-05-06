import os 
from openai import OpenAI
from dotenv import load_dotenv
import snowflake.connector
from langgraph.graph import StateGraph, END
from typing import TypedDict, List, Optional

# Load environment variables
load_dotenv()

# Configure OpenAI API
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# Schema description for the LOG_DATA table
SCHEMA_DESCRIPTION = """
The Snowflake database contains one table:

1. LOG_DATA (in SPARK_DB.SPARK_SCHEMA)
   - FRAME_TIME (TIMESTAMP_NTZ): Timestamp of the log entry
   - IP_SRC (VARCHAR): Source IP address
   - IP_DST (VARCHAR): Destination IP address
   - UDP_PORT (VARCHAR): UDP port used
   - TCP_PORT (VARCHAR): TCP port used
   - IP_PROTO (VARCHAR): IP protocol (e.g., TCP, UDP)
   - SRC_LATITUDE (VARCHAR): Latitude of source location
   - SRC_LONGITUDE (VARCHAR): Longitude of source location
   - SRC_CITY (VARCHAR): City of source location
   - DST_LATITUDE (VARCHAR): Latitude of destination location
   - DST_LONGITUDE (VARCHAR): Longitude of destination location
   - DST_CITY (VARCHAR): City of destination location
   - YEAR (NUMBER): Year of the log entry
   - MONTH (NUMBER): Month of the log entry
   - DAY (NUMBER): Day of the log entry
   - HOUR (NUMBER): Hour of the log entry
   - MINUTE (NUMBER): Minute of the log entry
   - SECOND (NUMBER): Second of the log entry
   - TRAFFIC_TYPE (VARCHAR): Type of traffic (e.g., HTTP, FTP)
"""

# Define the state for the LangGraph workflow
class AgentState(TypedDict):
    user_input: str
    conversation_history: List[dict]
    sql_query: Optional[str]
    columns: Optional[List[str]]
    results: Optional[List]
    output: Optional[str]

# Snowflake connection parameters
SNOWFLAKE_CONFIG = {
    "user": os.getenv("SNOWFLAKE_USER"),
    "password": os.getenv("SNOWFLAKE_PASSWORD"),
    "account": os.getenv("SNOWFLAKE_ACCOUNT"),
    "warehouse": os.getenv("SNOWFLAKE_WAREHOUSE"),
    "database": "SPARK_DB",
    "schema": "SPARK_SCHEMA"
}

def get_sql_query_from_nlp(state: AgentState) -> AgentState:
    """Generate SQL query from user input using OpenAI."""
    user_input = state["user_input"]
    conversation_history = state["conversation_history"]

    # Create a prompt with conversation context
    history_text = "\n".join([f"User: {msg['user']}\nSQL Query: {msg.get('sql', 'None')}" for msg in conversation_history])
    prompt = f"""
You are an expert SQL query generator for a Snowflake database.
Based on the following schema and conversation history, convert the user's natural language query into a valid SQL query.
Consider the context from previous queries for follow-up questions. Return only the SQL query as a string.
Schema:
{SCHEMA_DESCRIPTION}

Conversation History:
{history_text}

User Query: {user_input}

SQL Query:
"""
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": "You are a SQL query generator. Provide only the SQL query."},
            {"role": "user", "content": prompt}
        ],
        max_tokens=200
    )
    sql_query = response.choices[0].message.content.strip()

    # Remove any Markdown-style backticks (`sql`) from the query
    if sql_query.startswith("```") and sql_query.endswith("```"):
        sql_query = sql_query[3:-3].strip()  # Strip the triple backticks

    state["sql_query"] = sql_query
    return state

def execute_snowflake_query(state: AgentState) -> AgentState:
    """Execute SQL query on Snowflake and return results."""
    sql_query = state["sql_query"]
    try:
        conn = snowflake.connector.connect(**SNOWFLAKE_CONFIG)
        cursor = conn.cursor()
        cursor.execute(sql_query)
        results = cursor.fetchall()
        columns = [desc[0] for desc in cursor.description]
        conn.close()
        state["columns"] = columns
        state["results"] = results
    except Exception as e:
        state["results"] = f"Error executing query: {str(e)}"
        state["columns"] = None
    return state

def generate_natural_language_response(state: AgentState) -> AgentState:
    """Generate a natural language response from the query results."""
    columns = state["columns"]
    results = state["results"]
    sql_query = state["sql_query"]

    if isinstance(results, str):
        # Handle errors gracefully
        state["output"] = f"Error: {results}"
        return state

    if not results:
        state["output"] = "No results were found for your query."
        return state

    # Prepare the data for the prompt
    result_summary = "\n".join([f"{columns[i]}: {row[i]}" for row in results for i in range(len(columns))])
    prompt = f"""
You are an expert at interpreting database query results and providing concise, human-readable summaries. 
Given the SQL query and the results below, provide a clear explanation of what the data means in plain English.

SQL Query:
{sql_query}

Results:
{result_summary}

Summary:
"""
    response = client.chat.completions.create(  # Fixed: Removed incorrect .create
        model="gpt-4",
        messages=[
            {"role": "system", "content": "You are a data interpreter. Provide a concise summary of the query results."},
            {"role": "user", "content": prompt}
        ],
        max_tokens=200
    )
    natural_language_response = response.choices[0].message.content.strip()
    state["output"] = natural_language_response
    return state

def format_results(state: AgentState) -> AgentState:
    """Format query results into a readable string and generate a natural language response."""
    columns = state["columns"]
    results = state["results"]

    if isinstance(results, str):
        state["output"] = results  # Error message is already handled
    elif not results:
        state["output"] = "No results found."
    else:
        # Format the table output
        formatted = []
        formatted.append(" | ".join(columns))
        formatted.append("-" * (len(" | ".join(columns))))
        for row in results:
            formatted.append(" | ".join(str(item) for item in row))
        table_output = "\n".join(formatted)

        # Generate a natural language response
        state = generate_natural_language_response(state)
        state["output"] = f"Query Results:\n\n{table_output}\n\nSummary:\n{state['output']}"

    # Update conversation history
    state["conversation_history"].append({
        "user": state["user_input"],
        "sql": state["sql_query"],
        "output": state["output"]
    })
    return state

def build_graph():
    """Build the LangGraph workflow."""
    workflow = StateGraph(AgentState)

    # Define nodes
    workflow.add_node("generate_sql", get_sql_query_from_nlp)
    workflow.add_node("execute_query", execute_snowflake_query)
    workflow.add_node("format_results", format_results)

    # Define edges
    workflow.add_edge("generate_sql", "execute_query")
    workflow.add_edge("execute_query", "format_results")
    workflow.add_edge("format_results", END)

    # Set entry point
    workflow.set_entry_point("generate_sql")

    return workflow.compile()

def process_query(user_input: str, conversation_history: List[dict]) -> dict:
    """Process a single user query and return the results."""
    if not user_input:
        return {"sql_query": "", "output": "Please enter a valid query."}

    # Initialize the graph
    graph = build_graph()
    state = AgentState(
        user_input=user_input,
        conversation_history=conversation_history,
        sql_query=None,
        columns=None,
        results=None,
        output=None
    )

    # Run the graph
    final_state = graph.invoke(state)
    return {
        "sql_query": final_state["sql_query"],
        "output": final_state["output"],
        "conversation_history": final_state["conversation_history"]
    }

def main():
    """Main function to handle user interaction and query processing."""
    conversation_history = []
    print("Welcome to the Snowflake Query Agent! Type 'exit' to quit.")

    while True:
        user_input = input("\nEnter your query: ").strip()
        if user_input.lower() == "exit":
            print("Goodbye!")
            break

        result = process_query(user_input, conversation_history)
        print("\nSQL Query:")
        print(result["sql_query"])
        print("\nResults:")
        print(result["output"])

        # Update conversation history
        conversation_history = result["conversation_history"]

if __name__ == "__main__":
    main()