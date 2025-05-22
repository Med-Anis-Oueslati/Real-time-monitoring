import snowflake.connector
from datetime import datetime, timedelta
from dotenv import load_dotenv
import os
import re
from langchain_openai import ChatOpenAI
from langchain.prompts import ChatPromptTemplate
from langchain.output_parsers import PydanticOutputParser
from pydantic import BaseModel, Field
from typing import List, Optional
import json

# Load environment variables
load_dotenv()

# Snowflake and OpenAI configuration
SNOWFLAKE_USER = os.getenv("SNOWFLAKE_USER")
SNOWFLAKE_PASSWORD = os.getenv("SNOWFLAKE_PASSWORD")
SNOWFLAKE_ACCOUNT = os.getenv("SNOWFLAKE_ACCOUNT")
SNOWFLAKE_WAREHOUSE = os.getenv("SNOWFLAKE_WAREHOUSE")
SNOWFLAKE_DATABASE = os.getenv("SNOWFLAKE_DATABASE")
SNOWFLAKE_SCHEMA = os.getenv("SNOWFLAKE_SCHEMA")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

# File to store last processed timestamp
LAST_TIMESTAMP_FILE = "last_processed_timestamp.txt"

class IncidentDescription(BaseModel):
    description: str = Field(description="Actionable description of the detected anomaly")
    src_ip: Optional[str] = Field(description="Source IP address of the anomaly, if applicable", default=None)
    dst_ip: Optional[str] = Field(description="Destination IP address of the anomaly, if applicable", default=None)
    details: dict = Field(description="Additional details about the anomaly", default={})

class AnomalyDetectionAgent:
    def __init__(self):
        # Initialize Snowflake connection
        try:
            self.conn = snowflake.connector.connect(
                user=SNOWFLAKE_USER,
                password=SNOWFLAKE_PASSWORD,
                account=SNOWFLAKE_ACCOUNT,
                warehouse=SNOWFLAKE_WAREHOUSE,
                database=SNOWFLAKE_DATABASE,
                schema=SNOWFLAKE_SCHEMA
            )
            print("[+] Snowflake connection established successfully.")
        except Exception as e:
            print(f"[-] Error connecting to Snowflake: {e}")
            raise

        # Initialize OpenAI LLM
        if not OPENAI_API_KEY:
            raise ValueError("OpenAI API Key not found.")
        self.llm = ChatOpenAI(model="gpt-4o-mini", api_key=OPENAI_API_KEY)
        self.parser = PydanticOutputParser(pydantic_object=IncidentDescription)
        self.prompt = self._create_prompt()

        # Load last processed timestamp
        self.last_timestamp = self._load_last_timestamp()

    def _create_prompt(self):
        """
        Create a LangChain prompt for LLM-based anomaly detection.
        """
        template = """
        You are a cybersecurity expert analyzing network logs from a SIEM system to detect potential cyberattacks.
        The logs include data from Zeek (zeek_notice, zeek_http, zeek_conn, zeek_capture_loss, zeek_dns) and tshark.
        Your task is to identify anomalies indicating cyberattacks, such as DNS tunneling, data exfiltration, suspicious HTTP traffic, denial-of-service (DoS) attacks, or unauthorized access attempts.
        
        Guidelines:
        - Analyze the provided log data: {log_data}
        - Log fields include:
          - zeek_notice: TIMESTAMP, ID_ORIG_H (source IP), ID_RESP_H (destination IP), NOTE (e.g., Custom::DNS_Tunneling), MSG (details)
          - zeek_http: TIMESTAMP, ID_ORIG_H, ID_RESP_H, RESPONSE_BODY_LEN, USER_AGENT, STATUS_CODE
          - zeek_conn: TIMESTAMP, ID_ORIG_H, ID_RESP_H, RESP_BYTES, DURATION, ID_RESP_P (destination port)
          - zeek_capture_loss: TIMESTAMP, PERCENT_LOST, GAPS, ACKS
          - zeek_dns: TIMESTAMP, ID_ORIG_H, ID_RESP_H, QUERY, QTYPE_NAME
          - tshark: FRAME_TIME, IP_SRC, IP_DST, TCP_PORT, UDP_PORT
        - Detect anomalies based on:
          - DNS tunneling: Long or encoded queries in zeek_notice or zeek_dns.
          - Suspicious HTTP: Large RESPONSE_BODY_LEN (>1MB), empty USER_AGENT, or STATUS_CODE not 200/204.
          - Data exfiltration: High RESP_BYTES (>1MB) in short DURATION (<10s) in zeek_conn.
          - DoS: High PERCENT_LOST (>50%) in zeek_capture_loss or many dropped packets (>1000) in zeek_notice.
          - Unauthorized access: Non-standard ports (not 80, 443, 53) in zeek_conn or tshark.
        - Generate a concise, actionable description for the most severe anomaly, suitable for a mitigation agent (e.g., block an IP).
        - If no anomalies are detected, return an empty description.
        
        Return the result in the following JSON format:
        {format_instructions}
        """
        return ChatPromptTemplate.from_template(template).partial(format_instructions=self.parser.get_format_instructions())

    def _load_last_timestamp(self) -> str:
        """
        Load the last processed timestamp from file, or default to 1 hour ago.
        """
        try:
            if os.path.exists(LAST_TIMESTAMP_FILE):
                with open(LAST_TIMESTAMP_FILE, 'r') as f:
                    return f.read().strip()
        except Exception as e:
            print(f"[-] Error loading last timestamp: {e}")
        return (datetime.now() - timedelta(hours=1)).strftime('%Y-%m-%d %H:%M:%S')

    def _save_last_timestamp(self, timestamp: str):
        """
        Save the latest timestamp to file.
        """
        try:
            with open(LAST_TIMESTAMP_FILE, 'w') as f:
                f.write(timestamp)
        except Exception as e:
            print(f"[-] Error saving last timestamp: {e}")

    def query_dns_tunneling(self, start_time: str, end_time: str) -> list:
        """
        Rule-based detection for DNS tunneling from zeek_notice.
        """
        try:
            cursor = self.conn.cursor()
            query = """
            SELECT TIMESTAMP, ID_ORIG_H, ID_RESP_H, MSG
            FROM zeek_notice
            WHERE NOTE = 'Custom::DNS_Tunneling'
            AND TIMESTAMP BETWEEN %s AND %s
            ORDER BY TIMESTAMP
            LIMIT 100
            """
            cursor.execute(query, (start_time, end_time))
            notices = cursor.fetchall()

            incidents = []
            for notice in notices:
                timestamp, src_ip, dst_ip, msg = notice
                query_match = re.search(r"query=([^\s,]+)", msg)
                query = query_match.group(1) if query_match else "unknown"
                description = (
                    f"Suspicious DNS tunneling traffic from {src_ip} to {dst_ip} "
                    f"at {timestamp} with query {query}"
                )
                incidents.append(IncidentDescription(
                    description=description,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    details={"query": query, "type": "DNS_Tunneling"}
                ))
            return incidents
        except Exception as e:
            print(f"[-] Error querying DNS tunneling: {e}")
            return []
        finally:
            cursor.close()

    def query_suspicious_http(self, start_time: str, end_time: str) -> list:
        """
        Rule-based detection for suspicious HTTP traffic.
        """
        try:
            cursor = self.conn.cursor()
            query = """
            SELECT TIMESTAMP, ID_ORIG_H, ID_RESP_H, RESPONSE_BODY_LEN, USER_AGENT, STATUS_CODE
            FROM zeek_http
            WHERE (RESPONSE_BODY_LEN > 1000000 OR USER_AGENT = '' OR STATUS_CODE NOT IN (200, 204))
            AND TIMESTAMP BETWEEN %s AND %s
            ORDER BY TIMESTAMP
            LIMIT 100
            """
            cursor.execute(query, (start_time, end_time))
            records = cursor.fetchall()

            incidents = []
            for record in records:
                timestamp, src_ip, dst_ip, resp_len, user_agent, status_code = record
                reasons = []
                if resp_len and resp_len > 1000000:
                    reasons.append(f"large response size ({resp_len} bytes)")
                if user_agent == '':
                    reasons.append("missing user agent")
                if status_code and status_code not in (200, 204):
                    reasons.append(f"unusual status code ({status_code})")
                description = (
                    f"Suspicious HTTP traffic from {src_ip} to {dst_ip} at {timestamp}: "
                    f"{', '.join(reasons)}"
                )
                incidents.append(IncidentDescription(
                    description=description,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    details={"response_body_len": resp_len, "user_agent": user_agent, "status_code": status_code, "type": "Suspicious_HTTP"}
                ))
            return incidents
        except Exception as e:
            print(f"[-] Error querying HTTP traffic: {e}")
            return []
        finally:
            cursor.close()

    def query_data_exfiltration(self, start_time: str, end_time: str) -> list:
        """
        Rule-based detection for data exfiltration.
        """
        try:
            cursor = self.conn.cursor()
            query = """
            SELECT TIMESTAMP, ID_ORIG_H, ID_RESP_H, RESP_BYTES, DURATION
            FROM zeek_conn
            WHERE RESP_BYTES > 1000000 AND DURATION < 10
            AND TIMESTAMP BETWEEN %s AND %s
            ORDER BY TIMESTAMP
            LIMIT 100
            """
            cursor.execute(query, (start_time, end_time))
            records = cursor.fetchall()

            incidents = []
            for record in records:
                timestamp, src_ip, dst_ip, resp_bytes, duration = record
                description = (
                    f"Potential data exfiltration from {src_ip} to {dst_ip} at {timestamp}: "
                    f"transferred {resp_bytes} bytes in {duration:.2f} seconds"
                )
                incidents.append(IncidentDescription(
                    description=description,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    details={"resp_bytes": resp_bytes, "duration": duration, "type": "Data_Exfiltration"}
                ))
            return incidents
        except Exception as e:
            print(f"[-] Error querying data exfiltration: {e}")
            return []
        finally:
            cursor.close()

    def query_packet_loss_dos(self, start_time: str, end_time: str) -> list:
        """
        Rule-based detection for packet loss or DoS.
        """
        try:
            cursor = self.conn.cursor()
            incidents = []
            
            # Query zeek_capture_loss for high packet loss
            loss_query = """
            SELECT TIMESTAMP, PERCENT_LOST
            FROM zeek_capture_loss
            WHERE PERCENT_LOST > 50
            AND TIMESTAMP BETWEEN %s AND %s
            ORDER BY TIMESTAMP
            LIMIT 100
            """
            cursor.execute(loss_query, (start_time, end_time))
            loss_records = cursor.fetchall()

            for record in loss_records:
                timestamp, percent_lost = record
                description = (
                    f"High packet loss detected at {timestamp}: {percent_lost:.2f}% loss rate, "
                    f"potential DoS attack"
                )
                incidents.append(IncidentDescription(
                    description=description,
                    src_ip=None,
                    dst_ip=None,
                    details={"percent_lost": percent_lost, "type": "Packet_Loss_DoS"}
                ))

            # Query zeek_notice for dropped packets
            notice_query = """
            SELECT TIMESTAMP, MSG
            FROM zeek_notice
            WHERE NOTE = 'PacketFilter::Dropped_Packets'
            AND MSG LIKE '%dropped after filtering%'
            AND TIMESTAMP BETWEEN %s AND %s
            ORDER BY TIMESTAMP
            LIMIT 100
            """
            cursor.execute(notice_query, (start_time, end_time))
            notice_records = cursor.fetchall()

            for record in notice_records:
                timestamp, msg = record
                dropped_match = re.search(r"(\d+)\s+packets dropped", msg)
                if dropped_match:
                    try:
                        dropped_packets = int(dropped_match.group(1))
                        if dropped_packets > 1000:
                            description = (
                                f"Significant packet drops detected at {timestamp}: {dropped_packets} "
                                f"packets dropped, potential DoS attack"
                            )
                            incidents.append(IncidentDescription(
                                description=description,
                                src_ip=None,
                                dst_ip=None,
                                details={"dropped_packets": dropped_packets, "type": "Packet_Drops_DoS"}
                            ))
                    except ValueError:
                        print(f"[-] Invalid packet count in MSG: {msg}")
                else:
                    print(f"[-] No packet count found in MSG: {msg}")
            return incidents
        except Exception as e:
            print(f"[-] Error querying packet loss/DoS: {e}")
            return []
        finally:
            cursor.close()

    def query_unauthorized_access(self, start_time: str, end_time: str) -> list:
        """
        Rule-based detection for unauthorized access.
        """
        try:
            cursor = self.conn.cursor()
            query = """
            SELECT TIMESTAMP, ID_ORIG_H, ID_RESP_H, ID_RESP_P
            FROM zeek_conn
            WHERE ID_RESP_P NOT IN (80, 443, 53)
            AND TIMESTAMP BETWEEN %s AND %s
            UNION
            SELECT FRAME_TIME, IP_SRC, IP_DST, TCP_PORT
            FROM tshark
            WHERE TCP_PORT NOT IN ('80', '443', '80,80', '443,443')
            AND FRAME_TIME BETWEEN %s AND %s
            ORDER BY TIMESTAMP
            LIMIT 100
            """
            cursor.execute(query, (start_time, end_time, start_time, end_time))
            records = cursor.fetchall()

            incidents = []
            for record in records:
                timestamp, src_ip, dst_ip, port = record
                if isinstance(port, str) and ',' in port:
                    ports = port.split(',')
                    port = ports[1] if ports[0] not in ('80', '443') else ports[0]
                description = (
                    f"Unauthorized access attempt from {src_ip} to {dst_ip} on port {port} "
                    f"at {timestamp}"
                )
                incidents.append(IncidentDescription(
                    description=description,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    details={"dst_port": port, "type": "Unauthorized_Access"}
                ))
            return incidents
        except Exception as e:
            print(f"[-] Error querying unauthorized access: {e}")
            return []
        finally:
            cursor.close()

    def query_logs_for_llm(self, start_time: str, end_time: str) -> dict:
        """
        Query a small, filtered set of logs for LLM analysis.
        """
        try:
            cursor = self.conn.cursor()
            logs = {}

            # Query zeek_notice for suspicious events
            cursor.execute("""
                SELECT TIMESTAMP, ID_ORIG_H, ID_RESP_H, MSG, NOTE
                FROM zeek_notice
                WHERE NOTE IN ('Custom::DNS_Tunneling', 'PacketFilter::Dropped_Packets')
                AND TIMESTAMP BETWEEN %s AND %s
                ORDER BY TIMESTAMP
                LIMIT 10
            """, (start_time, end_time))
            logs["zeek_notice"] = cursor.fetchall()

            # Query zeek_http for suspicious HTTP
            cursor.execute("""
                SELECT TIMESTAMP, ID_ORIG_H, ID_RESP_H, RESPONSE_BODY_LEN, USER_AGENT, STATUS_CODE
                FROM zeek_http
                WHERE (RESPONSE_BODY_LEN > 1000000 OR USER_AGENT = '' OR STATUS_CODE NOT IN (200, 204))
                AND TIMESTAMP BETWEEN %s AND %s
                ORDER BY TIMESTAMP
                LIMIT 10
            """, (start_time, end_time))
            logs["zeek_http"] = cursor.fetchall()

            # Query zeek_conn for high data transfers or non-standard ports
            cursor.execute("""
                SELECT TIMESTAMP, ID_ORIG_H, ID_RESP_H, RESP_BYTES, DURATION, ID_RESP_P
                FROM zeek_conn
                WHERE (RESP_BYTES > 1000000 OR ID_RESP_P NOT IN (80, 443, 53))
                AND TIMESTAMP BETWEEN %s AND %s
                ORDER BY TIMESTAMP
                LIMIT 10
            """, (start_time, end_time))
            logs["zeek_conn"] = cursor.fetchall()

            # Query zeek_capture_loss for high packet loss
            cursor.execute("""
                SELECT TIMESTAMP, PERCENT_LOST
                FROM zeek_capture_loss
                WHERE PERCENT_LOST > 50
                AND TIMESTAMP BETWEEN %s AND %s
                ORDER BY TIMESTAMP
                LIMIT 10
            """, (start_time, end_time))
            logs["zeek_capture_loss"] = cursor.fetchall()

            # Query zeek_dns for long queries
            cursor.execute("""
                SELECT TIMESTAMP, ID_ORIG_H, ID_RESP_H, QUERY
                FROM zeek_dns
                WHERE LENGTH(QUERY) > 50
                AND TIMESTAMP BETWEEN %s AND %s
                ORDER BY TIMESTAMP
                LIMIT 10
            """, (start_time, end_time))
            logs["zeek_dns"] = cursor.fetchall()

            # Query tshark for non-standard ports
            cursor.execute("""
                SELECT FRAME_TIME, IP_SRC, IP_DST, TCP_PORT
                FROM tshark
                WHERE TCP_PORT NOT IN ('80', '443', '80,80', '443,443')
                AND FRAME_TIME BETWEEN %s AND %s
                ORDER BY FRAME_TIME
                LIMIT 10
            """, (start_time, end_time))
            logs["tshark"] = cursor.fetchall()

            return logs
        except Exception as e:
            print(f"[-] Error querying logs for LLM: {e}")
            return {}
        finally:
            cursor.close()

    def llm_analyze_logs(self, log_data: dict) -> IncidentDescription:
        """
        Use LLM to analyze a small set of logs and detect anomalies.
        """
        try:
            chain = self.prompt | self.llm | self.parser
            result = chain.invoke({"log_data": json.dumps(log_data, default=str)})
            return result
        except Exception as e:
            print(f"[-] Error in LLM analysis: {e}")
            return IncidentDescription(description="", src_ip=None, dst_ip=None, details={})

    def detect_anomalies(self, start_time: str, end_time: str):
        """
        Detect anomalies using both rule-based and LLM-based methods.
        """
        # Update last timestamp
        self._save_last_timestamp(end_time)

        # Rule-based detection
        incidents = []
        incidents.extend(self.query_dns_tunneling(start_time, end_time))
        incidents.extend(self.query_suspicious_http(start_time, end_time))
        incidents.extend(self.query_data_exfiltration(start_time, end_time))
        incidents.extend(self.query_packet_loss_dos(start_time, end_time))
        incidents.extend(self.query_unauthorized_access(start_time, end_time))

        # LLM-based detection on filtered logs
        log_data = self.query_logs_for_llm(start_time, end_time)
        if log_data:
            llm_incident = self.llm_analyze_logs(log_data)
            if llm_incident.description:
                incidents.append(llm_incident)

        if not incidents:
            print("[*] No anomalies detected in the specified time range.")
            return

        print("[+] Detected anomalies (prompts for mitigation agent):")
        for incident in incidents:
            print(f"  - {incident.description}")

    def run(self):
        """
        Main loop to monitor logs and detect anomalies.
        """
        try:
            print("[+] Anomaly detection agent started. Monitoring logs...")
            # Use last processed timestamp as start time, end time as now
            end_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            start_time = self.last_timestamp

            self.detect_anomalies(start_time, end_time)

        except KeyboardInterrupt:
            print("\n[!] Stopping anomaly detection agent...")
        finally:
            self.conn.close()

if __name__ == "__main__":
    try:
        agent = AnomalyDetectionAgent()
        agent.run()
    except Exception as e:
        print(f"[!] Failed to initialize anomaly detection agent: {e}")