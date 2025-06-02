import streamlit as st
import pandas as pd
from conversational_agent import process_query # Ensure this import path is correct

# Initialize session state variables
if "conversation_history" not in st.session_state:
    st.session_state.conversation_history = []
if "messages" not in st.session_state:
    # Each message will now potentially store 'sql_queries' and 'dataframes'
    st.session_state.messages = [
        {"role": "assistant", "content": "Welcome to the Snowflake NLP Query Chatbot! Ask questions about the Zeek log data (e.g., ZEEK_CAPTURE_LOSS, ZEEK_CONN, ZEEK_DNS, ZEEK_HTTP, ZEEK_NOTICE, ZEEK_SSL). I can also provide summaries of detected anomalies."}
    ]
# Add a message counter for unique keys across chat interactions (important for dynamic elements)
if "message_counter" not in st.session_state:
    st.session_state.message_counter = 0

# Streamlit app layout
st.set_page_config(layout="wide") # Use wide layout for better table display
st.title("Snowflake NLP Query Chatbot")
st.write("Ask questions about network log tables (ZEEK_CAPTURE_LOSS, ZEEK_CONN, ZEEK_DNS, ZEEK_HTTP, ZEEK_NOTICE, ZEEK_SSL) and other data like ANOMALIES in the Snowflake database.")

# Helper function to convert DataFrame to CSV for download
@st.cache_data
def convert_df_to_csv(_df):
    """Converts a pandas DataFrame to a CSV string encoded in utf-8."""
    if not _df.empty:
        return _df.to_csv(index=False).encode('utf-8')
    return None # Return None if DataFrame is empty

# Display chat history (now handles persistent tables/buttons)
for msg_idx, message in enumerate(st.session_state.messages):
    with st.chat_message(message["role"]):
        st.markdown(message["content"]) # Display the main textual content

        # Check if this message contains dataframes to display
        if message["role"] == "assistant" and "dataframes" in message and message["dataframes"]:
            sql_queries_for_msg = message.get("sql_queries", [])
            dataframes_for_msg = message["dataframes"]

            # Render each dataframe and its download button for this historical message
            for df_idx, (query, df) in enumerate(zip(sql_queries_for_msg, dataframes_for_msg)):
                table_name = "Unknown Table"
                try:
                    # Attempt to extract table name from a common SQL pattern
                    from_clause = query.upper().split("FROM")[1].strip()
                    parts = from_clause.split(' ')[0].split('.')
                    table_name = parts[-1]
                except Exception:
                    pass
                
                st.markdown(f"---") # Separator for multiple tables or between messages
                st.markdown(f"**Table: {table_name}** (from query: `{query}`)")

                # Check if the DataFrame contains an error message (from convert_to_dataframe)
                if not df.empty and 'Error' in df.columns and len(df.columns) == 1:
                    st.error(f"Error for {table_name}: {df['Error'].iloc[0]}")
                elif df.empty:
                    st.warning(f"No data found for {table_name}.")
                else:
                    st.dataframe(df, use_container_width=True)
                    
                    csv_data = convert_df_to_csv(df)
                    if csv_data:
                        st.download_button(
                            label=f"Download {table_name} as CSV",
                            data=csv_data,
                            file_name=f"{table_name.lower()}_data.csv",
                            mime="text/csv",
                            # Unique key for each download button across all messages
                            key=f"download_{msg_idx}_{df_idx}" 
                        )
                    else:
                        st.info("No data to download for this table.")
            st.markdown("---") # End of tables for this message

# User input
user_input = st.chat_input("Your question:")

if user_input:
    # Increment message counter for the new turn
    st.session_state.message_counter += 1

    # Add user message to chat
    st.session_state.messages.append({"role": "user", "content": user_input})
    with st.chat_message("user"):
        st.markdown(user_input)

    # Process the query
    with st.spinner("Processing your query..."):
        result = process_query(user_input, st.session_state.conversation_history)

        # Update conversation history for the next turn
        st.session_state.conversation_history = result.get("conversation_history", [])

        sql_queries = result.get("sql_queries", [])
        output_summary = result.get("output", "No summary available.")
        dataframes = result.get("dataframes", [])

        # Prepare the content for the new assistant message
        assistant_content_parts = []

        # Part 1: Generated SQL queries
        if sql_queries:
            if len(sql_queries) > 1:
                queries_text = "\n".join([f"{i+1}. {q}" for i, q in enumerate(sql_queries)])
                assistant_content_parts.append(f"**Generated SQL Queries:**\n```sql\n{queries_text}\n```")
            else:
                assistant_content_parts.append(f"**Generated SQL Query:**\n```sql\n{sql_queries[0]}\n```")
        else:
            assistant_content_parts.append("**No SQL queries were generated for your request.**")

        # Part 2: Overall Summary (this will be the main text of the message)
        assistant_content_parts.append(f"\n\n**Overall Summary:**\n\n{output_summary}")
        
        # Add a note indicating that interactive tables are displayed separately
        if dataframes and any(not df.empty for df in dataframes):
            assistant_content_parts.append("\n\n*(Interactive tables and download options are displayed below this message.)*")
        elif dataframes and all(df.empty for df in dataframes):
             assistant_content_parts.append("\n\n*(No data found for the requested tables.)*")


        # Create the new assistant message dictionary, including dataframes and sql_queries
        new_assistant_message = {
            "role": "assistant",
            "content": "\n".join(assistant_content_parts),
            "sql_queries": sql_queries, # Store SQL queries for persistence
            "dataframes": dataframes    # Store DataFrames for persistence
        }
        st.session_state.messages.append(new_assistant_message)

    # After processing, rerun to display the updated history including the new message
    st.rerun()


# Clear chat history button
if st.button("Clear Chat History"):
    st.session_state.conversation_history = []
    st.session_state.messages = [
        {"role": "assistant", "content": "Welcome to the Snowflake NLP Query Chatbot! Ask questions about the Zeek log data (e.g., ZEEK_CAPTURE_LOSS, ZEEK_CONN, ZEEK_DNS, ZEEK_HTTP, ZEEK_NOTICE, ZEEK_SSL). I can also provide summaries of detected anomalies."}
    ]
    st.session_state.message_counter = 0 # Reset message counter
    st.rerun()

