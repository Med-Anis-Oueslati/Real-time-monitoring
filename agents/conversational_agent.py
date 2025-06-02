import os
from openai import OpenAI
from dotenv import load_dotenv
import snowflake.connector
from langgraph.graph import StateGraph, END
from typing import TypedDict, List, Optional
from pandas import DataFrame
import pandas as pd

# Assuming SCHEMA_DESCRIPTION is defined in schema_description.py
# For this example, I'll provide a placeholder if it's not available in the environment
from schema_description import SCHEMA_DESCRIPTION


# Load environment variables
load_dotenv()

# Configure OpenAI API
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# Define the state for the LangGraph workflow
class AgentState(TypedDict):
    user_input: str
    conversation_history: List[dict]
    sql_queries: Optional[List[str]]
    columns: Optional[List[List[str]]]
    results: Optional[List[List]]  # Raw rows from DB
    dataframes: Optional[List[DataFrame]]  # New field
    output: Optional[str]  # Markdown summary

# Snowflake connection parameters
SNOWFLAKE_CONFIG = {
    "user": os.getenv("SNOWFLAKE_USER"),
    "password": os.getenv("SNOWFLAKE_PASSWORD"),
    "account": os.getenv("SNOWFLAKE_ACCOUNT"),
    "warehouse": os.getenv("SNOWFLAKE_WAREHOUSE"),
    "database": "SPARK_DB",
    "schema": "SPARK_SCHEMA"
}

def convert_to_dataframe(state: AgentState) -> AgentState:
    """
    Convert query results into pandas DataFrames.
    Ensures a DataFrame is always returned, even if empty or an error occurred.
    """
    columns = state["columns"]
    results = state["results"]
    sql_queries = state["sql_queries"]

    dataframes = []

    for i, (query, cols, res) in enumerate(zip(sql_queries, columns, results)):
        if isinstance(res, str): # This indicates an error message
            # Create an empty DataFrame with a single 'Error' column
            df = pd.DataFrame([{"Error": res}])
            dataframes.append(df)
        elif not res: # Query executed, but no results found
            # Create an empty DataFrame with the correct columns if available, otherwise default
            df = pd.DataFrame(columns=cols if cols else [])
            dataframes.append(df)
        else: # Valid results
            df = pd.DataFrame(res, columns=cols)
            dataframes.append(df)

    state["dataframes"] = dataframes
    return state

def get_sql_query_from_nlp(state: AgentState) -> AgentState:
    """Generate SQL queries from user input using OpenAI."""
    user_input = state["user_input"]
    conversation_history = state["conversation_history"]

    # For this specific case, use predefined queries for first row of each table
    if "first line of each table" in user_input.lower():
        sql_queries = [
            "SELECT * FROM SPARK_DB.SPARK_SCHEMA.ZEEK_CAPTURE_LOSS LIMIT 1",
            "SELECT * FROM SPARK_DB.SPARK_SCHEMA.ZEEK_CONN LIMIT 1",
            "SELECT * FROM SPARK_DB.SPARK_SCHEMA.ZEEK_DNS LIMIT 1",
            "SELECT * FROM SPARK_DB.SPARK_SCHEMA.ZEEK_HTTP LIMIT 1",
            "SELECT * FROM SPARK_DB.SPARK_SCHEMA.ZEEK_NOTICE LIMIT 1",
            "SELECT * FROM SPARK_DB.SPARK_SCHEMA.ZEEK_SSL LIMIT 1"
        ]
    else:
        # Original logic for generating SQL query from NLP
        # Format conversation history for the prompt
        history_text = ""
        for msg in conversation_history:
            history_text += f"User: {msg.get('user', 'N/A')}\n"
            if 'sql' in msg and msg['sql']:
                history_text += f"SQL Query: {msg['sql']}\n"
            if 'output' in msg and msg['output']:
                # Truncate output to avoid exceeding token limits, focus on SQL/summary
                output_lines = msg['output'].split('\n')
                summary_index = -1
                for idx, line in enumerate(output_lines):
                    if line.startswith("Summary:"):
                        summary_index = idx
                        break
                if summary_index != -1:
                    history_text += f"Summary: {' '.join(output_lines[summary_index:])[:200]}...\n" # Limit summary
                else:
                    history_text += f"Output (truncated): {' '.join(output_lines)[:200]}...\n"
            history_text += "\n" # Add a newline for separation

        prompt = f"""
You are an expert SQL query generator for a Snowflake database.
Based on the following schema and conversation history, convert the user's natural language query into a valid SQL query.
Consider the context from previous queries for follow-up questions. Return only the SQL query as a string.
Ensure the SQL query is syntactically correct for Snowflake.
For date/time arithmetic (e.g., 'last 10 minutes', 'yesterday'), use Snowflake's DATEADD function.
For example, to get data from the last 10 minutes, use: `DATEADD(minute, -10, CURRENT_TIMESTAMP())`.
If the user asks for data from multiple tables, generate separate SQL queries for each table.

Schema:
{SCHEMA_DESCRIPTION}

Conversation History:
{history_text}

User Query: {user_input}

SQL Query:
"""
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are a SQL query generator for Snowflake. Provide only the SQL query. If multiple queries are needed, separate them with a semicolon and a newline."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=300 # Increased max_tokens for potentially longer queries or multiple queries
        )
        sql_query_raw = response.choices[0].message.content.strip()
        
        # Clean up markdown code blocks if present
        if sql_query_raw.startswith("```sql") and sql_query_raw.endswith("```"):
            sql_query_raw = sql_query_raw[6:-3].strip()
        elif sql_query_raw.startswith("```") and sql_query_raw.endswith("```"):
            sql_query_raw = sql_query_raw[3:-3].strip()
        
        # Split into multiple queries if present
        sql_queries = [q.strip() for q in sql_query_raw.split(';') if q.strip()]

    state["sql_queries"] = sql_queries
    return state

def execute_snowflake_query(state: AgentState) -> AgentState:
    """Execute SQL queries on Snowflake and return results."""
    sql_queries = state["sql_queries"]
    all_results = []
    all_columns = []

    try:
        conn = snowflake.connector.connect(**SNOWFLAKE_CONFIG)
        cursor = conn.cursor()
        for sql_query in sql_queries:
            try:
                cursor.execute(sql_query)
                results = cursor.fetchall()
                columns = [desc[0] for desc in cursor.description]
                all_results.append(results)
                all_columns.append(columns)
            except Exception as query_e:
                # Handle individual query errors
                all_results.append(f"Error executing query '{sql_query}': {str(query_e)}")
                all_columns.append([]) # Append empty list for columns
        conn.close()
        state["columns"] = all_columns
        state["results"] = all_results
    except Exception as e:
        # Handle connection or broader execution errors
        state["results"] = [f"Global Error: {str(e)}"]
        state["columns"] = [[]] # Ensure columns is a list of lists

    return state

def generate_natural_language_response(state: AgentState) -> AgentState:
    """
    Generate a natural language response from the query results,
    considering the original user input for better context.
    The summary will be narrative and will NOT reproduce raw table data.
    """
    columns = state["columns"]
    results = state["results"]
    sql_queries = state["sql_queries"]
    user_input = state["user_input"] # Get the original user input for context

    output_parts = []
    for i, (query, result, cols) in enumerate(zip(sql_queries, results, columns)):
        # Handle cases where result is an error string
        if isinstance(result, str):
            output_parts.append(f"Error for query '{query}': {result}")
            continue
        
        # Extract table name from query for better summary context
        table_name = "Unknown Table"
        try:
            # Attempt to extract table name from a common SQL pattern
            # e.g., "SELECT * FROM SPARK_DB.SPARK_SCHEMA.ZEEK_CONN LIMIT 1"
            from_clause = query.upper().split("FROM")[1].strip()
            # Split by space, then by dot to get the last part (table name)
            parts = from_clause.split(' ')[0].split('.')
            table_name = parts[-1]
        except Exception:
            pass # Keep "Unknown Table" if parsing fails

        if not result:
            output_parts.append(f"For **{table_name}** (Query: `{query}`):\nNo results found.")
            continue

        # Prepare a structured summary of results for the LLM
        # Limiting to first 5 rows for brevity in the prompt, adjust as needed
        result_display_for_llm = []
        if cols: # Ensure columns exist before trying to join
            result_display_for_llm.append("| " + " | ".join(cols) + " |")
            result_display_for_llm.append("|" + "---|"*len(cols))
            for row_idx, row in enumerate(result):
                if row_idx >= 5: # Limit rows for prompt
                    break
                result_display_for_llm.append("| " + " | ".join(str(item) for item in row) + " |")
        else:
            result_display_for_llm.append("No columns or data to display for summary.")

        result_summary_for_llm_text = "\n".join(result_display_for_llm)

        prompt = f"""
You are an expert at interpreting database query results and providing concise, human-readable summaries.
Given the SQL query, the original user's question, and a sample of the results below, provide a clear explanation of what the data means in plain English.
**DO NOT reproduce the raw table data or its structure in your summary.**
Focus on directly answering the user's original question based on the provided data.
Highlight any important findings, trends, or specific values that directly address the query.
If the result is a count, state the total count clearly.
If the result shows specific entries, describe what they represent and why they are relevant.
If the data is empty, state that no relevant data was found.

Original User Question: {user_input}

SQL Query:
{query}

Sample Results (first few rows for your interpretation, DO NOT include this raw data in your final summary):
{result_summary_for_llm_text}

Summary for {table_name}:
"""
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": "You are a data interpreter. Provide a concise, clear, and relevant narrative summary of the query results, directly addressing the user's question. Focus on actionable insights or direct answers. DO NOT include raw table data or its structure in your summary."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=400 # Increased max_tokens for more detailed summaries
        )
        summary = response.choices[0].message.content.strip()
        output_parts.append(f"**Summary for {table_name}:**\n{summary}")

    state["output"] = "\n\n".join(output_parts)
    return state

def format_results(state: AgentState) -> AgentState:
    """
    Format query results into a readable string and generate a natural language response.
    This function now primarily orchestrates the display and summary generation.
    """
    columns = state["columns"]
    results = state["results"]
    sql_queries = state["sql_queries"]

    # If the first result is a global error string, just set it as output
    if isinstance(results[0], str) and len(results) == 1 and len(columns) == 1 and not columns[0]:
        state["output"] = results[0]
        # Update conversation history with the error
        state["conversation_history"].append({
            "user": state["user_input"],
            "sql": "; ".join(sql_queries),
            "output": state["output"]
        })
        return state

    # Generate natural language response first
    # This will populate state["output"] with the LLM-generated summaries
    state = generate_natural_language_response(state)
    llm_summary_output = state["output"] # Store the LLM summary

    # The raw table formatting below is no longer used for the final 'output' field,
    # as Streamlit handles DataFrame display directly.
    # It's kept here as a placeholder if raw text table output was needed elsewhere.
    # formatted_raw_tables = []
    # for i, (query, result, cols) in enumerate(zip(sql_queries, results, columns)):
    #     table_name = "Unknown Table"
    #     try:
    #         from_clause = query.upper().split("FROM")[1].strip()
    #         parts = from_clause.split(' ')[0].split('.')
    #         table_name = parts[-1]
    #     except Exception:
    #         pass

    #     formatted_raw_tables.append(f"\n--- Raw Data for: {table_name} ---")
    #     if isinstance(result, str): # Error for this specific query
    #         formatted_raw_tables.append(f"Error: {result}")
    #         continue
    #     elif not result:
    #         formatted_raw_tables.append("No raw results found.")
    #         continue

    #     # Format table output
    #     if cols:
    #         formatted = [f" | ".join(cols), "-" * len(f" | ".join(cols))]
    #         for row in result:
    #             formatted.append(f" | ".join(str(item) for item in row))
    #         table_output = "\n".join(formatted)
    #         formatted_raw_tables.append(table_output)
    #     else:
    #         formatted_raw_tables.append("No columns to display raw data.")

    # Combine the formatted raw tables (if desired) and the LLM summary
    # For Streamlit, the raw table formatting here might be redundant as st.dataframe handles it.
    # The primary output for the 'output' field in AgentState should be the LLM summary.
    state["output"] = llm_summary_output # Prioritize the LLM summary for the 'output' field

    # Update conversation history
    state["conversation_history"].append({
        "user": state["user_input"],
        "sql": "; ".join(sql_queries),
        "output": llm_summary_output # Store the LLM-generated summary
    })
    return state

def build_graph():
    """Build the LangGraph workflow with improved structure."""
    workflow = StateGraph(AgentState)

    # Define nodes
    workflow.add_node("generate_sql", get_sql_query_from_nlp)
    workflow.add_node("execute_query", execute_snowflake_query)
    workflow.add_node("convert_to_dataframe", convert_to_dataframe)
    workflow.add_node("format_results", format_results) # This now primarily triggers summary generation

    # Define edges
    workflow.add_edge("generate_sql", "execute_query")
    workflow.add_edge("execute_query", "convert_to_dataframe")
    workflow.add_edge("convert_to_dataframe", "format_results")
    workflow.add_edge("format_results", END)

    # Set entry point
    workflow.set_entry_point("generate_sql")

    return workflow.compile()

def process_query(user_input: str, conversation_history: List[dict]) -> dict:
    """Process a single user query and return the results."""
    if not user_input:
        return {"sql_queries": [], "output": "Please enter a valid query.", "dataframes": [], "conversation_history": conversation_history}

    # Initialize the graph
    graph = build_graph()
    state = AgentState(
        user_input=user_input,
        conversation_history=conversation_history,
        sql_queries=None,
        columns=None,
        results=None,
        dataframes=None,
        output=None
    )

    # Run the graph
    final_state = graph.invoke(state)
    return {
        "sql_queries": final_state.get("sql_queries", []),
        "output": final_state.get("output", "An unexpected error occurred or no output was generated."),
        "dataframes": final_state.get("dataframes", []),
        "conversation_history": final_state.get("conversation_history", [])
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
        print("\nSQL Queries:")
        for query in result["sql_queries"]:
            print(query)
        print("\nResults:")
        print(result["output"])

        # Update conversation history
        conversation_history = result["conversation_history"]

if __name__ == "__main__":
    main()

