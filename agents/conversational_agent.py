import os
from openai import OpenAI
from dotenv import load_dotenv
import snowflake.connector
from langgraph.graph import StateGraph, END
from typing import TypedDict, List, Optional
from schema_description import SCHEMA_DESCRIPTION
from pandas import DataFrame
import pandas as pd
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
    """Convert query results into pandas DataFrames."""
    columns = state["columns"]
    results = state["results"]
    sql_queries = state["sql_queries"]

    dataframes = []

    for i, (query, cols, res) in enumerate(zip(sql_queries, columns, results)):
        if isinstance(res, str) or not res:
            dataframes.append(None)
        else:
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
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are a SQL query generator. Provide only the SQL query."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=200
        )
        sql_query = response.choices[0].message.content.strip()
        if sql_query.startswith("```") and sql_query.endswith("```"):
            sql_query = sql_query[3:-3].strip()
        sql_queries = [sql_query]

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
            cursor.execute(sql_query)
            results = cursor.fetchall()
            columns = [desc[0] for desc in cursor.description]
            all_results.append(results)
            all_columns.append(columns)
        conn.close()
        state["columns"] = all_columns
        state["results"] = all_results
    except Exception as e:
        state["results"] = [f"Error executing query: {str(e)}"]
        state["columns"] = [None]
    return state

def generate_natural_language_response(state: AgentState) -> AgentState:
    """Generate a natural language response from the query results."""
    columns = state["columns"]
    results = state["results"]
    sql_queries = state["sql_queries"]

    if isinstance(results[0], str):
        state["output"] = f"Error: {results[0]}"
        return state

    output_parts = []
    for i, (query, result, cols) in enumerate(zip(sql_queries, results, columns)):
        if not result:
            output_parts.append(f"No results found for query: {query}")
            continue

        result_summary = "\n".join([f"{cols[j]}: {row[j]}" for row in result for j in range(len(cols))])
        prompt = f"""
You are an expert at interpreting database query results and providing concise, human-readable summaries. 
Given the SQL query and the results below, provide a clear explanation of what the data means in plain English.

SQL Query:
{query}

Results:
{result_summary}

Summary:
"""
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are a data interpreter. Provide a concise summary of the query results."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=200
        )
        summary = response.choices[0].message.content.strip()
        output_parts.append(f"Table {i+1} ({query.split('.')[-1].split(' ')[0]}):\n{summary}")

    state["output"] = "\n\n".join(output_parts)
    return state

def format_results(state: AgentState) -> AgentState:
    """Format query results into a readable string and generate a natural language response."""
    columns = state["columns"]
    results = state["results"]
    sql_queries = state["sql_queries"]

    if isinstance(results[0], str):
        state["output"] = results[0]
        return state

    formatted_output = []
    for i, (query, result, cols) in enumerate(zip(sql_queries, results, columns)):
        table_name = query.split('.')[-1].split(' ')[0]
        formatted_output.append(f"\nTable: {table_name}")
        if not result:
            formatted_output.append("No results found.")
            continue

        # Format table output
        formatted = [f" | ".join(cols), "-" * len(f" | ".join(cols))]
        for row in result:
            formatted.append(f" | ".join(str(item) for item in row))
        table_output = "\n".join(formatted)
        formatted_output.append(table_output)

    # Generate natural language response
    state = generate_natural_language_response(state)
    formatted_output.append(f"\nSummary:\n{state['output']}")
    state["output"] = "\n".join(formatted_output)

    # Update conversation history
    state["conversation_history"].append({
        "user": state["user_input"],
        "sql": "; ".join(sql_queries),
        "output": state["output"]
    })
    return state

def build_graph():
    """Build the LangGraph workflow with improved structure."""
    workflow = StateGraph(AgentState)

    # Define nodes
    workflow.add_node("generate_sql", get_sql_query_from_nlp)
    workflow.add_node("execute_query", execute_snowflake_query)
    workflow.add_node("convert_to_dataframe", convert_to_dataframe)
    workflow.add_node("format_results", format_results)

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
        return {"sql_queries": [], "output": "Please enter a valid query."}

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
        "sql_queries": final_state["sql_queries"],
        "output": final_state["output"],
        "dataframes": final_state["dataframes"],  # Now included!
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
        print("\nSQL Queries:")
        for query in result["sql_queries"]:
            print(query)
        print("\nResults:")
        print(result["output"])

        # Update conversation history
        conversation_history = result["conversation_history"]

if __name__ == "__main__":
    main()