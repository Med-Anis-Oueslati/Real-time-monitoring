from dotenv import load_dotenv
import os

print("Before load_dotenv:", os.getenv("OPENAI_API_KEY"))

load_dotenv()

print("After load_dotenv:", os.getenv("OPENAI_API_KEY"))