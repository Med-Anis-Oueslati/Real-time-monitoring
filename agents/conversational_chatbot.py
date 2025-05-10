import streamlit as st
import pandas as pd
from conversational_agent import process_query

# Initialize session state
if "conversation_history" not in st.session_state:
    st.session_state.conversation_history = []
if "messages" not in st.session_state:
    st.session_state.messages = [
        {"role": "assistant", "content": "Welcome to the Snowflake NLP Query Chatbot! Ask questions about the Zeek log data (e.g., ZEEK_CAPTURE_LOSS, ZEEK_CONN, ZEEK_DNS, ZEEK_HTTP, ZEEK_NOTICE, ZEEK_SSL)."}
    ]

# Streamlit app layout
st.title("Snowflake NLP Query Chatbot")
st.write("Ask questions about the Zeek log tables (ZEEK_CAPTURE_LOSS, ZEEK_CONN, ZEEK_DNS, ZEEK_HTTP, ZEEK_NOTICE, ZEEK_SSL) in the Snowflake database.")

# Display chat history
for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        st.markdown(message["content"])

# User input
user_input = st.chat_input("Your question:")

if user_input:
    # Add user message to chat
    st.session_state.messages.append({"role": "user", "content": user_input})
    with st.chat_message("user"):
        st.markdown(user_input)

    # Process the query
    with st.spinner("Processing your query..."):
        result = process_query(user_input, st.session_state.conversation_history)

        # Update conversation history
        st.session_state.conversation_history = result.get("conversation_history", [])

        sql_queries = result.get("sql_queries", [])
        output_summary = result.get("output", "No summary available.")
        dataframes = result.get("dataframes", [])  # <-- Now using dataframes

        assistant_response = []

        # Step 1: Show generated SQL queries
        if sql_queries:
            if len(sql_queries) > 1:
                queries_text = "\n".join([f"{i+1}. {q}" for i, q in enumerate(sql_queries)])
                assistant_response.append(f"**Generated SQL Queries:**\n```\n{queries_text}\n```")
            else:
                assistant_response.append(f"**Generated SQL Query:**\n```\n{sql_queries[0]}\n```")

        # Step 2: Display results as DataFrames
        for i, (query, df) in enumerate(zip(sql_queries, dataframes)):
            table_name = query.split('.')[-1].split(' ')[0]

            with st.chat_message("assistant"):
                st.markdown(f"**Table: {table_name}**")

                if df is None or df.empty:
                    st.warning(f"No data found for {table_name}")
                    assistant_response.append(f"\n**Table: {table_name}**: No data found.")
                else:
                    st.dataframe(df, use_container_width=True)
                    assistant_response.append(f"\n**Table: {table_name}**:\n(Interactive table shown above)")

                    # Optional: CSV Download
                    @st.cache_data
                    def convert_df(_df):
                        return _df.to_csv(index=False).encode('utf-8')

                    csv = convert_df(df)
                    st.download_button(
                        label=f"Download {table_name} as CSV",
                        data=csv,
                        file_name=f"{table_name.lower()}_data.csv",
                        mime="text/csv",
                        key=f"download_{i}"
                    )

        # Step 3: Append final summary
        assistant_response.append(f"\n**Summary:**\n\n{output_summary}")

        # Finalize assistant message
        full_response = "\n".join(assistant_response)
        st.session_state.messages.append({"role": "assistant", "content": full_response})
        with st.chat_message("assistant"):
            st.markdown(full_response)

# Clear chat history button
if st.button("Clear Chat History"):
    st.session_state.conversation_history = []
    st.session_state.messages = [
        {"role": "assistant", "content": "Welcome to the Snowflake NLP Query Chatbot! Ask questions about the Zeek log data (e.g., ZEEK_CAPTURE_LOSS, ZEEK_CONN, ZEEK_DNS, ZEEK_HTTP, ZEEK_NOTICE, ZEEK_SSL)."}
    ]
    st.rerun()