import snowflake.connector
from openai import OpenAI
import os
from dotenv import load_dotenv
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
    reflection_feedback: Optional[str]
    refinement_count: int  # Track number of refinement iterations
    max_refinements: int  # Maximum allowed refinements

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
You are an expert SQL query generator for a Snowflake database. Based on the following schema and conversation history, convert the user's natural language query into a valid SQL query. Consider the context from previous queries for follow-up questions. Return only the SQL query as a string.
Schema:
{SCHEMA_DESCRIPTION}

Conversation History:
{history_text}

User Query: {user_input}

SQL Query:
"""
    response = client.chat.completions.create(model="gpt-4",
    messages=[
        {"role": "system", "content": "You are a SQL query generator. Provide only the SQL query."},
        {"role": "user", "content": prompt}
    ],
    max_tokens=200)
    sql_query = response.choices[0].message.content.strip()

    # Remove any Markdown-style backticks (`sql`) from the query
    if sql_query.startswith("```") and sql_query.endswith("```"):
        sql_query = sql_query[3:-3].strip()

    state["sql_query"] = sql_query
    state["reflection_feedback"] = None  # Reset reflection feedback
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

def reflect_on_query_and_results(state: AgentState) -> AgentState:
    """Reflect on the SQL query and results, providing feedback and suggesting refinements."""
    sql_query = state["sql_query"]
    results = state["results"]
    user_input = state["user_input"]
    columns = state["columns"]

    # Prepare result summary for reflection
    result_summary = "Error: No results" if isinstance(results, str) else (
        "No results found" if not results else f"Returned {len(results)} rows with columns: {', '.join(columns)}"
    )

    prompt = f"""
You are an expert SQL query reviewer. Your task is to evaluate the generated SQL query and its results for correctness and relevance to the user's intent. Provide feedback on:
1. Does the SQL query accurately reflect the user's natural language query?
2. Are the results meaningful, or do they indicate a problem (e.g., no results, too many results, irrelevant data)?
3. If the query or results are suboptimal, suggest a refined SQL query or explain why refinement is not needed.

Schema:
{SCHEMA_DESCRIPTION}

User Query: {user_input}
SQL Query: {sql_query}
Results: {result_summary}

Feedback and Refined Query (if needed, otherwise return 'No refinement needed'):
"""
    response = client.chat.completions.create(model="gpt-4",
    messages=[
        {"role": "system", "content": "You are a SQL query reviewer. Provide feedback and, if needed, a refined SQL query."},
        {"role": "user", "content": prompt}
    ],
    max_tokens=300)
    reflection_feedback = response.choices[0].message.content.strip()

    # Extract refined query if provided
    refined_query = None
    if "Refined Query:" in reflection_feedback:
        refined_query = reflection_feedback.split("Refined Query:")[-1].strip()
        if refined_query.startswith("```") and refined_query.endswith("```"):
            refined_query = refined_query[3:-3].strip()

    state["reflection_feedback"] = reflection_feedback
    if refined_query and state["refinement_count"] < state["max_refinements"]:
        state["sql_query"] = refined_query
        state["refinement_count"] += 1
    else:
        state["sql_query"] = None  # Signal no further refinements

    return state

def generate_natural_language_response(state: AgentState) -> AgentState:
    """Generate a natural language response from the query results."""
    columns = state["columns"]
    results = state["results"]
    sql_query = state["sql_query"]

    if isinstance(results, str):
        state["output"] = f"Error: {results}"
        return state

    if not results:
        state["output"] = "No results were found for your query."
        return state

    result_summary = "\n".join([f"{columns[i]}: {row[i]}" for row in results for i in range(len(columns))])
    prompt = f"""
You are an expert at interpreting database query results. Provide a concise, human-readable summary of what the data means in plain English.

SQL Query:
{sql_query}

Results:
{result_summary}

Summary:
"""
    response = client.chat.completions.create(model="gpt-4",
    messages=[
        {"role": "system", "content": "You are a data interpreter. Provide a concise summary of the query results."},
        {"role": "user", "content": prompt}
    ],
    max_tokens=200)
    natural_language_response = response.choices[0].message.content.strip()
    state["output"] = natural_language_response
    return state

def format_results(state: AgentState) -> AgentState:
    """Format query results and include reflection feedback."""
    columns = state["columns"]
    results = state["results"]
    reflection_feedback = state["reflection_feedback"]

    if isinstance(results, str):
        state["output"] = f"{results}\n\nReflection Feedback:\n{reflection_feedback}"
    elif not results:
        state["output"] = f"No results found.\n\nReflection Feedback:\n{reflection_feedback}"
    else:
        formatted = []
        formatted.append(" | ".join(columns))
        formatted.append("-" * (len(" | ".join(columns))))
        for row in results:
            formatted.append(" | ".join(str(item) for item in row))
        table_output = "\n".join(formatted)

        state = generate_natural_language_response(state)
        state["output"] = (
            f"Query Results:\n\n{table_output}\n\nSummary:\n{state['output']}\n\n"
            f"Reflection Feedback:\n{reflection_feedback}"
        )

    state["conversation_history"].append({
        "user": state["user_input"],
        "sql": state["sql_query"],
        "output": state["output"],
        "reflection": reflection_feedback
    })
    return state

def build_graph():
    """Build the LangGraph workflow for a reflection agent."""
    workflow = StateGraph(AgentState)

    # Define nodes
    workflow.add_node("generate_sql", get_sql_query_from_nlp)
    workflow.add_node("execute_query", execute_snowflake_query)
    workflow.add_node("reflect", reflect_on_query_and_results)
    workflow.add_node("format_results", format_results)

    # Define edges and conditional logic
    def should_refine(state: AgentState):
        return state["sql_query"] is not None and state["refinement_count"] < state["max_refinements"]

    workflow.add_edge("generate_sql", "execute_query")
    workflow.add_edge("execute_query", "reflect")
    workflow.add_conditional_edges(
        "reflect",
        should_refine,
        {
            True: "execute_query",  # Loop back to execute refined query
            False: "format_results"  # Proceed to format results
        }
    )
    workflow.add_edge("format_results", END)

    # Set entry point
    workflow.set_entry_point("generate_sql")

    return workflow.compile()

def process_query(user_input: str, conversation_history: List[dict]) -> dict:
    """Process a single user query with reflection and return the results."""
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
        output=None,
        reflection_feedback=None,
        refinement_count=0,
        max_refinements=2  # Limit to 2 refinements to avoid infinite loops
    )

    # Run the graph
    final_state = graph.invoke(state)
    return {
        "sql_query": final_state["sql_query"],
        "output": final_state["output"],
        "conversation_history": final_state["conversation_history"],
        "reflection_feedback": final_state["reflection_feedback"]
    }

# Example usage
if __name__ == "__main__":
    user_input = "Show me all HTTP traffic from New York"
    conversation_history = []
    result = process_query(user_input, conversation_history)
    print("SQL Query:", result["sql_query"])
    print("Output:", result["output"])
    print("Reflection Feedback:", result["reflection_feedback"])