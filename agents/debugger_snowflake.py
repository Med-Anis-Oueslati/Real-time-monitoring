import os
import sys
import snowflake.connector
from openai import OpenAI
from dotenv import load_dotenv
import pkg_resources
import requests
from typing import Optional, Tuple

# Load environment variables
load_dotenv()

# Snowflake configuration from .env
SNOWFLAKE_CONFIG = {
    "user": os.getenv("SNOWFLAKE_USER"),
    "password": os.getenv("SNOWFLAKE_PASSWORD"),
    "account": os.getenv("SNOWFLAKE_ACCOUNT"),
    "warehouse": os.getenv("SNOWFLAKE_WAREHOUSE"),
    "database": os.getenv("SNOWFLAKE_DATABASE", "SPARK_DB"),
    "schema": os.getenv("SNOWFLAKE_SCHEMA", "SPARK_SCHEMA")
}

# Open AI API key
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

def check_environment() -> None:
    """Check Python version and installed packages."""
    print("\n=== Environment Check ===")
    print(f"Python Version: {sys.version}")
    print(f"Python Executable: {sys.executable}")
    
    required_packages = ["snowflake-connector-python", "openai", "python-dotenv", "langgraph", "langchain-core"]
    print("\nInstalled Packages:")
    for pkg in required_packages:
        try:
            version = pkg_resources.get_distribution(pkg).version
            print(f"{pkg}: {version}")
        except pkg_resources.DistributionNotFound:
            print(f"{pkg}: Not installed")
            print(f"  Suggestion: Run 'pip install {pkg}'")

def check_env_variables() -> bool:
    """Check if all required environment variables are set."""
    print("\n=== Environment Variables Check ===")
    all_set = True
    for key, value in SNOWFLAKE_CONFIG.items():
        if not value:
            print(f"ERROR: {key} is not set in .env file")
            all_set = False
        else:
            print(f"{key}: {'<set>' if key in ['password', 'user'] else value}")
    
    if not OPENAI_API_KEY:
        print("ERROR: OPENAI_API_KEY is not set in .env file")
        all_set = False
    else:
        print("OPENAI_API_KEY: <set>")
    
    if not all_set:
        print("Suggestion: Update your .env file with missing values. Example:")
        print("""
OPENAI_API_KEY=sk-...
SNOWFLAKE_USER=your_username
SNOWFLAKE_PASSWORD=your_password
SNOWFLAKE_ACCOUNT=xy123048.us-east-1
SNOWFLAKE_WAREHOUSE=COMPUTE_WH
SNOWFLAKE_DATABASE=SPARK_DB
SNOWFLAKE_SCHEMA=SPARK_SCHEMA
        """)
    return all_set

def test_snowflake_connection() -> Tuple[Optional[snowflake.connector.SnowflakeConnection], Optional[str]]:
    """Test Snowflake connection and return connection object or error message."""
    print("\n=== Snowflake Connection Test ===")
    try:
        conn = snowflake.connector.connect(**SNOWFLAKE_CONFIG)
        print("SUCCESS: Connected to Snowflake!")
        return conn, None
    except Exception as e:
        error_msg = f"ERROR: Failed to connect to Snowflake: {str(e)}"
        print(error_msg)
        if "404 Not Found" in str(e):
            print("  Suggestion: Verify SNOWFLAKE_ACCOUNT (e.g., 'xy123048.us-east-1').")
            print("  Ensure the account exists and the region is correct. Check Snowflake UI URL.")
        if "Authentication" in str(e):
            print("  Suggestion: Verify SNOWFLAKE_USER and SNOWFLAKE_PASSWORD.")
        if "Warehouse" in str(e):
            print("  Suggestion: Verify SNOWFLAKE_WAREHOUSE exists and is active.")
        return None, error_msg

def check_snowflake_objects(conn: snowflake.connector.SnowflakeConnection) -> None:
    """Check if database, schema, and table exist in Snowflake."""
    print("\n=== Snowflake Objects Check ===")
    cursor = conn.cursor()
    
    try:
        # Check database
        cursor.execute(f"SHOW DATABASES LIKE '{SNOWFLAKE_CONFIG['database']}'")
        if cursor.fetchone():
            print(f"SUCCESS: Database {SNOWFLAKE_CONFIG['database']} exists")
        else:
            print(f"ERROR: Database {SNOWFLAKE_CONFIG['database']} does not exist")
            print("  Suggestion: Create the database or update SNOWFLAKE_DATABASE in .env")
        
        # Check schema
        cursor.execute(f"SHOW SCHEMAS LIKE '{SNOWFLAKE_CONFIG['schema']}' IN DATABASE {SNOWFLAKE_CONFIG['database']}")
        if cursor.fetchone():
            print(f"SUCCESS: Schema {SNOWFLAKE_CONFIG['schema']} exists")
        else:
            print(f"ERROR: Schema {SNOWFLAKE_CONFIG['schema']} does not exist")
            print("  Suggestion: Create the schema or update SNOWFLAKE_SCHEMA in .env")
        
        # Check table
        cursor.execute(f"SHOW TABLES LIKE 'LOG_DATA' IN {SNOWFLAKE_CONFIG['database']}.{SNOWFLAKE_CONFIG['schema']}")
        if cursor.fetchone():
            print(f"SUCCESS: Table LOG_DATA exists")
        else:
            print(f"ERROR: Table LOG_DATA does not exist")
            print("  Suggestion: Create the LOG_DATA table or verify the table name")
    
    except Exception as e:
        print(f"ERROR: Failed to check Snowflake objects: {str(e)}")
        print("  Suggestion: Ensure the user has permissions to view databases, schemas, and tables")
    
    finally:
        cursor.close()

def check_warehouse_status(conn: snowflake.connector.SnowflakeConnection) -> None:
    """Check if the warehouse is active."""
    print("\n=== Warehouse Status Check ===")
    cursor = conn.cursor()
    try:
        cursor.execute(f"SHOW WAREHOUSES LIKE '{SNOWFLAKE_CONFIG['warehouse']}'")
        result = cursor.fetchone()
        if result:
            status = result[2]  # Status column in SHOW WAREHOUSES
            print(f"SUCCESS: Warehouse {SNOWFLAKE_CONFIG['warehouse']} exists, Status: {status}")
            if status != "STARTED":
                print("  Warning: Warehouse is not running. Start it with:")
                print(f"  ALTER WAREHOUSE {SNOWFLAKE_CONFIG['warehouse']} RESUME;")
        else:
            print(f"ERROR: Warehouse {SNOWFLAKE_CONFIG['warehouse']} does not exist")
            print("  Suggestion: Verify the warehouse name in Snowflake UI or update SNOWFLAKE_WAREHOUSE")
    except Exception as e:
        print(f"ERROR: Failed to check warehouse status: {str(e)}")
        print("  Suggestion: Ensure the user has permissions to view warehouses")
    finally:
        cursor.close()

def test_openai_api() -> None:
    """Test Open AI API connectivity."""
    print("\n=== Open AI API Test ===")
    # Retrieve API key from environment variable
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
    
    if not OPENAI_API_KEY:
        print("ERROR: OPENAI_API_KEY is not set")
        return
    
    # Initialize the OpenAI client
    client = OpenAI(api_key=OPENAI_API_KEY)
    
    try:
        response = client.chat.completions.create(
            model="gpt-4o",  # Updated model (gpt-4 may not be available; use gpt-4o or gpt-3.5-turbo)
            messages=[{"role": "user", "content": "Test"}],
            max_tokens=10
        )
        print("SUCCESS: Open AI API is accessible")
    except Exception as e:
        print(f"ERROR: Failed to connect to Open AI API: {str(e)}")
        if "authentication" in str(e).lower():
            print("  Suggestion: Verify OPENAI_API_KEY in .env file")
        else:
            print("  Suggestion: Check internet connection or Open AI API status")

def check_network() -> None:
    """Test network connectivity to Snowflake."""
    print("\n=== Network Connectivity Check ===")
    account = SNOWFLAKE_CONFIG["account"]
    if account:
        url = f"https://{account}.snowflakecomputing.com"
        try:
            response = requests.head(url, timeout=5)
            print(f"SUCCESS: Reached {url} (Status: {response.status_code})")
        except requests.RequestException as e:
            print(f"ERROR: Failed to reach {url}: {str(e)}")
            print("  Suggestion: Check firewall, proxy, or network settings")
    else:
        print("ERROR: Cannot test network; SNOWFLAKE_ACCOUNT is not set")

def main():
    """Run all diagnostic checks."""
    print("=== Snowflake Conversational Agent Debugger ===")
    
    # Step 1: Check environment
    check_environment()
    
    # Step 2: Check environment variables
    if not check_env_variables():
        print("\nERROR: Missing environment variables. Fix .env file and rerun.")
        return
    
    # Step 3: Test Snowflake connection
    conn, error = test_snowflake_connection()
    if error:
        print("\nERROR: Cannot proceed without a valid Snowflake connection.")
        return
    
    # Step 4: Check Snowflake objects (database, schema, table)
    check_snowflake_objects(conn)
    
    # Step 5: Check warehouse status
    check_warehouse_status(conn)
    
    # Step 6: Test Open AI API
    test_openai_api()
    
    # Step 7: Test network connectivity
    check_network()
    
    # Close connection
    if conn:
        conn.close()
        print("\n=== Debug Complete ===")
        print("If issues persist, share this output with your administrator or support.")

if __name__ == "__main__":
    main()