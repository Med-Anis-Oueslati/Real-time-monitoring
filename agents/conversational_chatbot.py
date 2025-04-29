import streamlit as st
from conversational_agent import process_query

# Initialize session state
if "conversation_history" not in st.session_state:
    st.session_state.conversation_history = []
if "messages" not in st.session_state:
    st.session_state.messages = [
        {"role": "assistant", "content": "Welcome to the Snowflake NLP Query Chatbot! Ask questions about the log data."}
    ]

# Streamlit app layout
st.title("Snowflake NLP Query Chatbot")
st.write("Ask questions about the LOG_DATA table in the Snowflake database.")

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
        st.session_state.conversation_history = result["conversation_history"]
        
        # Format the response
        response = f"**Generated SQL Query:**\n\n```\n{result['sql_query']}\n```\n\n**Response:**\n\n{result['output']}"
        
        # Add assistant response to chat
        st.session_state.messages.append({"role": "assistant", "content": response})
        with st.chat_message("assistant"):
            st.markdown(response)

# Add a button to clear chat history
if st.button("Clear Chat History"):
    st.session_state.conversation_history = []
    st.session_state.messages = [
        {"role": "assistant", "content": "Welcome to the Snowflake NLP Query Chatbot! Ask questions about the log data."}
    ]
    st.experimental_rerun()