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
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

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
            logger.info("Snowflake connection established.")
        except Exception as e:
            print(f"[-] Error connecting to Snowflake: {e}")
            logger.error(f"Error connecting to Snowflake: {e}")
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
        - Generate a summary of the anomalies detected without detailing just say what's the type of the cyberattack and the action to take. 
        - Generate a concise, actionable description for the most severe anomaly, suitable for a mitigation agent (e.g., block an IP).
        - If no anomalies are detected, return an empty description.
        
        Return the result in the following JSON format:
        {format_instructions}
        """
        return ChatPromptTemplate.from_template(template).partial(format_instructions=self.parser.get_format_instructions())

    def _load_last_timestamp(self) -> str:
        """
        Load the last processed timestamp from file, or default to 24 hours ago.
        """
        try:
            if os.path.exists(LAST_TIMESTAMP_FILE):
                with open(LAST_TIMESTAMP_FILE, 'r') as f:
                    timestamp = f.read().strip()
                    logger.info(f"Loaded last timestamp: {timestamp}")
                    return timestamp
        except Exception as e:
            logger.error(f"Error loading last timestamp: {e}")
        default_timestamp = (datetime.now() - timedelta(hours=24)).strftime('%Y-%m-%d %H:%M:%S')
        logger.info(f"Using default timestamp: {default_timestamp}")
        return default_timestamp

    def _save_last_timestamp(self, timestamp: str):
        """
        Save the latest timestamp to file.
        """
        try:
            with open(LAST_TIMESTAMP_FILE, 'w') as f:
                f.write(timestamp)
        except Exception as e:
            print(f"[-] Error saving last timestamp: {e}")
    
    def _get_date_filters(self, start_time: str, end_time: str):
        """
        Extract YEAR, MONTH, DAY for query filters based on timestamp range.
        """
        start_dt = datetime.strptime(start_time, '%Y-%m-%d %H:%M:%S')
        end_dt = datetime.strptime(end_time, '%Y-%m-%d %H:%M:%S')
        return {
            'start_year': start_dt.year,
            'start_month': start_dt.month,
            'start_day': start_dt.day,
            'end_year': end_dt.year,
            'end_month': end_dt.month,
            'end_day': end_dt.day
        }

    def query_dns_tunneling(self, start_time: str, end_time: str) -> list:
        """
        Rule-based detection for DNS tunneling from zeek_notice.
        """
        try:
            cursor = self.conn.cursor()
            date_filters = self._get_date_filters(start_time, end_time)
            query = """
            SELECT TIMESTAMP, ID_ORIG_H, ID_RESP_H, MSG
            FROM SPARK_DB.SPARK_SCHEMA.ZEEK_NOTICE
            WHERE NOTE = 'Custom::DNS_Tunneling'
            AND YEAR = %s AND MONTH = %s AND DAY = %s
            AND TIMESTAMP BETWEEN %s AND %s
            ORDER BY TIMESTAMP
            LIMIT 100
            """
            cursor.execute(query, (
                date_filters['start_year'], date_filters['start_month'], date_filters['start_day'],
                start_time, end_time
            ))
            notices = cursor.fetchall()
            logger.info(f"DNS tunneling query returned {len(notices)} records")

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
            logger.error(f"Error querying DNS tunneling: {e}")
            return []
        finally:
            cursor.close()

    def query_suspicious_http(self, start_time: str, end_time: str) -> list:
        """
        Rule-based detection for suspicious HTTP traffic.
        """
        try:
            cursor = self.conn.cursor()
            date_filters = self._get_date_filters(start_time, end_time)
            query = """
            SELECT TIMESTAMP, ID_ORIG_H, ID_RESP_H, RESPONSE_BODY_LEN, USER_AGENT, STATUS_CODE
            FROM SPARK_DB.SPARK_SCHEMA.ZEEK_HTTP
            WHERE (RESPONSE_BODY_LEN > 1000000 OR USER_AGENT = '' OR STATUS_CODE NOT IN (200, 204))
            AND YEAR = %s AND MONTH = %s AND DAY = %s
            AND TIMESTAMP BETWEEN %s AND %s
            ORDER BY TIMESTAMP
            LIMIT 100
            """
            cursor.execute(query, (
                date_filters['start_year'], date_filters['start_month'], date_filters['start_day'],
                start_time, end_time
            ))
            records = cursor.fetchall()
            logger.info(f"Suspicious HTTP query returned {len(records)} records")
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
            logger.error(f"Error querying HTTP traffic: {e}")
            return []
        finally:
            cursor.close()

    def query_data_exfiltration(self, start_time: str, end_time: str) -> list:
        """
        Rule-based detection for data exfiltration.
        """
        try:
            cursor = self.conn.cursor()
            date_filters = self._get_date_filters(start_time, end_time)
            query = """
            SELECT TIMESTAMP, ID_ORIG_H, ID_RESP_H, RESP_BYTES, DURATION
            FROM SPARK_DB.SPARK_SCHEMA.ZEEK_CONN
            WHERE RESP_BYTES > 1000000 AND DURATION < 10
            AND YEAR = %s AND MONTH = %s AND DAY = %s
            AND TIMESTAMP BETWEEN %s AND %s
            ORDER BY TIMESTAMP
            LIMIT 100
            """
            cursor.execute(query, (
                date_filters['start_year'], date_filters['start_month'], date_filters['start_day'],
                start_time, end_time
            ))
            records = cursor.fetchall()
            logger.info(f"Data exfiltration query returned {len(records)} records")

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
            logger.error(f"Error querying data exfiltration: {e}")
            return []
        finally:
            cursor.close()

    def query_packet_loss_dos(self, start_time: str, end_time: str) -> list:
        """
        Rule-based detection for TCP-based DoS attacks in ZEEK_CONN.
        """
        try:
            cursor = self.conn.cursor()
            date_filters = self._get_date_filters(start_time, end_time)
            incidents = []

            # Query ZEEK_CONN for high packet volumes or incomplete handshakes
            dos_query = """
            SELECT 
                DATE_TRUNC('minute', TIMESTAMP) AS minute_timestamp,
                ID_ORIG_H,
                ID_RESP_H,
                SUM(ORIG_PKTS) AS total_packets,
                SUM(CASE WHEN CONN_STATE = 'S0' THEN 1 ELSE 0 END) AS s0_count
            FROM SPARK_DB.SPARK_SCHEMA.ZEEK_CONN
            WHERE PROTO = 'tcp'
            AND (DURATION < 1 OR DURATION IS NULL)
            AND YEAR = %s AND MONTH = %s AND DAY = %s
            AND TIMESTAMP BETWEEN %s AND %s
            GROUP BY DATE_TRUNC('minute', TIMESTAMP), ID_ORIG_H, ID_RESP_H
            HAVING SUM(ORIG_PKTS) > 1000 OR SUM(CASE WHEN CONN_STATE = 'S0' THEN 1 ELSE 0 END) > 50
            ORDER BY minute_timestamp
            LIMIT 100
            """
            cursor.execute(dos_query, (
                date_filters['start_year'], date_filters['start_month'], date_filters['start_day'],
                start_time, end_time
            ))
            dos_records = cursor.fetchall()
            logger.info(f"TCP DoS query returned {len(dos_records)} records")

            for record in dos_records:
                timestamp, src_ip, dst_ip, total_packets, s0_count = record
                description = (
                    f"TCP DoS attack detected at {timestamp} from {src_ip} targeting {dst_ip}: "
                    f"{total_packets} packets sent, {s0_count} incomplete handshakes"
                )
                incidents.append(IncidentDescription(
                    description=description,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    details={
                        "total_packets": total_packets,
                        "s0_count": s0_count,
                        "type": "TCP_DoS"
                    }
                ))

            return incidents
        except Exception as e:
            print(f"[-] Error querying TCP DoS: {e}")
            logger.error(f"Error querying TCP DoS: {e}")
            return []
        finally:
            cursor.close()

    def query_unauthorized_access(self, start_time: str, end_time: str) -> list:
        """
        Rule-based detection for unauthorized access.
        """
        try:
            cursor = self.conn.cursor()
            date_filters = self._get_date_filters(start_time, end_time)
            query = """
            SELECT TIMESTAMP, ID_ORIG_H, ID_RESP_H, ID_RESP_P
            FROM SPARK_DB.SPARK_SCHEMA.ZEEK_CONN
            WHERE ID_RESP_P NOT IN (80, 443, 53)
            AND YEAR = %s AND MONTH = %s AND DAY = %s
            AND TIMESTAMP BETWEEN %s AND %s
            UNION
            SELECT FRAME_TIME, IP_SRC, IP_DST, TCP_PORT
            FROM SPARK_DB.SPARK_SCHEMA.TSHARK
            WHERE TCP_PORT NOT IN ('80', '443', '80,80', '443,443')
            AND YEAR = %s AND MONTH = %s AND DAY = %s
            AND FRAME_TIME BETWEEN %s AND %s
            ORDER BY TIMESTAMP
            LIMIT 100
            """
            cursor.execute(query, (
                date_filters['start_year'], date_filters['start_month'], date_filters['start_day'],
                start_time, end_time,
                date_filters['start_year'], date_filters['start_month'], date_filters['start_day'],
                start_time, end_time
            ))
            records = cursor.fetchall()
            logger.info(f"Unauthorized access query returned {len(records)} records")

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
            logger.error(f"Error querying unauthorized access: {e}")
            return []
        finally:
            cursor.close()

    def query_syn_flood(self, start_time: str, end_time: str) -> list:
        """
        Rule-based detection for SYN flood attacks.
        """
        try:
            cursor = self.conn.cursor()
            date_filters = self._get_date_filters(start_time, end_time)
            query = """
            SELECT TIMESTAMP, ID_ORIG_H, ID_RESP_H, ORIG_PKTS
            FROM SPARK_DB.SPARK_SCHEMA.ZEEK_CONN
            WHERE CONN_STATE = 'S0' AND ORIG_PKTS > 500 AND DURATION < 0.5
            AND YEAR = %s AND MONTH = %s AND DAY = %s
            AND TIMESTAMP BETWEEN %s AND %s
            ORDER BY TIMESTAMP
            LIMIT 100
            """
            cursor.execute(query, (
                date_filters['start_year'], date_filters['start_month'], date_filters['start_day'],
                start_time, end_time
            ))
            records = cursor.fetchall()
            logger.info(f"SYN flood query returned {len(records)} records")
            incidents = []
            for record in records:
                timestamp, src_ip, dst_ip, orig_pkts = record
                description = f"Potential SYN flood from {src_ip} to {dst_ip} at {timestamp}: {orig_pkts} packets"
                incidents.append(IncidentDescription(
                    description=description,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    details={"orig_pkts": orig_pkts, "type": "SYN_Flood"}
                ))
            return incidents
        except Exception as e:
            print(f"[-] Error querying SYN flood: {e}")
            logger.error(f"Error querying SYN flood: {e}")
            return []
        finally:
            cursor.close()

    def query_system_strain(self, start_time: str, end_time: str) -> list:
        """
        Rule-based detection for system strain.
        """
        try:
            cursor = self.conn.cursor()
            date_filters = self._get_date_filters(start_time, end_time)
            query = """
            SELECT TIMESTAMP, CPU_USER, MEM_USED, MEM_TOTAL
            FROM SPARK_DB.SPARK_SCHEMA.SYSTEM_METRICS
            WHERE (CPU_USER > 80 OR (MEM_USED / MEM_TOTAL) > 0.9)
            AND CPU_USER IS NOT NULL AND MEM_USED IS NOT NULL AND MEM_TOTAL IS NOT NULL
            AND YEAR = %s AND MONTH = %s AND DAY = %s
            AND TIMESTAMP BETWEEN %s AND %s
            ORDER BY TIMESTAMP
            LIMIT 100
            """
            cursor.execute(query, (
                date_filters['start_year'], date_filters['start_month'], date_filters['start_day'],
                start_time, end_time
            ))
            records = cursor.fetchall()
            logger.info(f"System strain query returned {len(records)} records")
            incidents = []
            for record in records:
                timestamp, cpu_user, mem_used, mem_total = record
                if all(v is not None for v in [cpu_user, mem_used, mem_total]):
                    mem_percent = (mem_used / mem_total) * 100
                    description = f"System strain detected at {timestamp}: CPU {cpu_user:.2f}%, Memory {mem_percent:.2f}%"
                    incidents.append(IncidentDescription(
                        description=description,
                        src_ip=None,
                        dst_ip=None,
                        details={"cpu_user": cpu_user, "mem_percent": mem_percent, "type": "System_Strain"}
                    ))
            return incidents
        except Exception as e:
            print(f"[-] Error querying system strain: {e}")
            logger.error(f"Error querying system strain: {e}")
            return []
        finally:
            cursor.close()

    def query_logs_for_llm(self, start_time: str, end_time: str) -> dict:
        """
        Query a small, filtered set of logs for LLM analysis.
        """
        try:
            cursor = self.conn.cursor()
            date_filters = self._get_date_filters(start_time, end_time)
            logs = {}

            # Query zeek_notice for suspicious events
            cursor.execute("""
                SELECT TIMESTAMP, ID_ORIG_H, ID_RESP_H, MSG, NOTE
                FROM SPARK_DB.SPARK_SCHEMA.ZEEK_NOTICE
                WHERE NOTE IN ('Custom::DNS_Tunneling', 'PacketFilter::Dropped_Packets')
                AND YEAR = %s AND MONTH = %s AND DAY = %s
                AND TIMESTAMP BETWEEN %s AND %s
                ORDER BY TIMESTAMP
                LIMIT 10
            """, (
                date_filters['start_year'], date_filters['start_month'], date_filters['start_day'],
                start_time, end_time
            ))
            logs["zeek_notice"] = cursor.fetchall()
            logger.info(f"LLM zeek_notice query returned {len(logs['zeek_notice'])} records")

            # Query zeek_http for suspicious HTTP
            cursor.execute("""
                SELECT TIMESTAMP, ID_ORIG_H, ID_RESP_H, RESPONSE_BODY_LEN, USER_AGENT, STATUS_CODE
                FROM SPARK_DB.SPARK_SCHEMA.ZEEK_HTTP
                WHERE (RESPONSE_BODY_LEN > 1000000 OR USER_AGENT = '' OR STATUS_CODE NOT IN (200, 204))
                AND YEAR = %s AND MONTH = %s AND DAY = %s
                AND TIMESTAMP BETWEEN %s AND %s
                ORDER BY TIMESTAMP
                LIMIT 10
            """, (
                date_filters['start_year'], date_filters['start_month'], date_filters['start_day'],
                start_time, end_time
            ))
            logs["zeek_http"] = cursor.fetchall()
            logger.info(f"LLM zeek_http query returned {len(logs['zeek_http'])} records")

            # Query zeek_conn for high data transfers, non-standard ports, or incomplete handshakes
            cursor.execute("""
                SELECT TIMESTAMP, ID_ORIG_H, ID_RESP_H, RESP_BYTES, DURATION, ID_RESP_P
                FROM SPARK_DB.SPARK_SCHEMA.ZEEK_CONN
                WHERE (RESP_BYTES > 1000000 OR ID_RESP_P NOT IN (80, 443, 53) OR CONN_STATE = 'S0')
                AND YEAR = %s AND MONTH = %s AND DAY = %s
                AND TIMESTAMP BETWEEN %s AND %s
                ORDER BY TIMESTAMP
                LIMIT 10
            """, (
                date_filters['start_year'], date_filters['start_month'], date_filters['start_day'],
                start_time, end_time
            ))
            logs["zeek_conn"] = cursor.fetchall()
            logger.info(f"LLM zeek_conn query returned {len(logs['zeek_conn'])} records")

            # Query zeek_capture_loss for high packet loss
            cursor.execute("""
                SELECT TIMESTAMP, PERCENT_LOST
                FROM SPARK_DB.SPARK_SCHEMA.ZEEK_CAPTURE_LOSS
                WHERE PERCENT_LOST > 50
                AND YEAR = %s AND MONTH = %s AND DAY = %s
                AND TIMESTAMP BETWEEN %s AND %s
                ORDER BY TIMESTAMP
                LIMIT 10
            """, (
                date_filters['start_year'], date_filters['start_month'], date_filters['start_day'],
                start_time, end_time
            ))
            logs["zeek_capture_loss"] = cursor.fetchall()
            logger.info(f"LLM zeek_capture_loss query returned {len(logs['zeek_capture_loss'])} records")

            # Query zeek_dns for long queries
            cursor.execute("""
                SELECT TIMESTAMP, ID_ORIG_H, ID_RESP_H, QUERY
                FROM SPARK_DB.SPARK_SCHEMA.ZEEK_DNS
                WHERE LENGTH(QUERY) > 50
                AND YEAR = %s AND MONTH = %s AND DAY = %s
                AND TIMESTAMP BETWEEN %s AND %s
                ORDER BY TIMESTAMP
                LIMIT 10
            """, (
                date_filters['start_year'], date_filters['start_month'], date_filters['start_day'],
                start_time, end_time
            ))
            logs["zeek_dns"] = cursor.fetchall()
            logger.info(f"LLM zeek_dns query returned {len(logs['zeek_dns'])} records")

            # Query tshark for non-standard ports
            cursor.execute("""
                SELECT FRAME_TIME, IP_SRC, IP_DST, TCP_PORT
                FROM SPARK_DB.SPARK_SCHEMA.TSHARK
                WHERE TCP_PORT NOT IN ('80', '443', '80,80', '443,443')
                AND YEAR = %s AND MONTH = %s AND DAY = %s
                AND FRAME_TIME BETWEEN %s AND %s
                ORDER BY FRAME_TIME
                LIMIT 10
            """, (
                date_filters['start_year'], date_filters['start_month'], date_filters['start_day'],
                start_time, end_time
            ))
            logs["tshark"] = cursor.fetchall()
            logger.info(f"LLM tshark query returned {len(logs['tshark'])} records")

            return logs
        except Exception as e:
            print(f"[-] Error querying logs for LLM: {e}")
            logger.error(f"Error querying logs for LLM: {e}")
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
            logger.info("LLM analysis completed successfully")
            return result
        except Exception as e:
            print(f"[-] Error in LLM analysis: {e}")
            logger.error(f"Error in LLM analysis: {e}")
            return IncidentDescription(description="", src_ip=None, dst_ip=None, details={})

    def llm_summarize_incidents(self, incidents: List[IncidentDescription]) -> str:
        """
        Use LLM to generate a natural-language summary of all detected incidents.
        """
        try:
            # Prepare incident data for LLM
            incident_data = [
                {
                    "description": incident.description,
                    "type": incident.details.get("type", "Unknown"),
                    "src_ip": incident.src_ip or "None",
                    "dst_ip": incident.dst_ip or "None",
                    "details": incident.details
                } for incident in incidents
            ]
            
            # Create prompt for summary
            template = """
            You are a cybersecurity expert summarizing detected network anomalies for a mitigation team.
            Given the following list of incidents, generate a concise, actionable summary in natural language:
            - Prioritize severe incidents (e.g., DoS attacks, data exfiltration) over less critical ones (e.g., unauthorized access).
            - Include key details: attack types, source/destination IPs, timestamps, and critical metrics (e.g., packet counts, bytes transferred).
            - Suggest specific mitigations (e.g., block IPs, restrict ports).
            - Keep the summary under 150 words, focusing on the most critical findings.

            Incidents: {incident_data}

            Return the summary as plain text.
            """
            prompt = ChatPromptTemplate.from_template(template)
            chain = prompt | self.llm
            result = chain.invoke({"incident_data": json.dumps(incident_data, default=str)})
            logger.info("LLM summary generated successfully")
            return result.content if hasattr(result, 'content') else str(result)
        except Exception as e:
            print(f"[-] Error in LLM summary: {e}")
            logger.error(f"Error in LLM summary: {e}")
            return "Failed to generate LLM summary due to an error."

    def detect_anomalies(self, start_time: str, end_time: str):
        """
        Detect anomalies using both rule-based and LLM-based methods.
        """
        logger.info(f"Detecting anomalies from {start_time} to {end_time}")

        # Update last timestamp
        self._save_last_timestamp(end_time)

        # Rule-based detection
        incidents = []
        incidents.extend(self.query_dns_tunneling(start_time, end_time))
        incidents.extend(self.query_syn_flood(start_time, end_time))
        incidents.extend(self.query_system_strain(start_time, end_time))
        incidents.extend(self.query_suspicious_http(start_time, end_time))
        incidents.extend(self.query_data_exfiltration(start_time, end_time))
        incidents.extend(self.query_packet_loss_dos(start_time, end_time))
        incidents.extend(self.query_unauthorized_access(start_time, end_time))

        # LLM-based detection on filtered logs
        log_data = self.query_logs_for_llm(start_time, end_time)
        llm_incident = None
        if log_data:
            llm_incident = self.llm_analyze_logs(log_data)
            # Only append if description indicates an actual anomaly
            if llm_incident.description and "no anomalies" not in llm_incident.description.lower():
                # Assign a type to LLM incident based on description
                if "data exfiltration" in llm_incident.description.lower():
                    llm_incident.details["type"] = "Data_Exfiltration"
                    logger.info("Assigned LLM incident type: Data_Exfiltration")
                elif "denial-of-service" in llm_incident.description.lower() or "dos" in llm_incident.description.lower():
                    llm_incident.details["type"] = "TCP_DoS"
                    logger.info("Assigned LLM incident type: TCP_DoS")
                elif "unauthorized access" in llm_incident.description.lower():
                    llm_incident.details["type"] = "Unauthorized_Access"
                    logger.info("Assigned LLM incident type: Unauthorized_Access")
                elif "dns tunneling" in llm_incident.description.lower():
                    llm_incident.details["type"] = "DNS_Tunneling"
                    logger.info("Assigned LLM incident type: DNS_Tunneling")
                else:
                    llm_incident.details["type"] = "Other"
                    logger.info("Assigned LLM incident type: Other")
                incidents.append(llm_incident)

        if not incidents:
            print("[*] No anomalies detected in the specified time range.")
            logger.info("No anomalies detected")
            return

        # # Print detailed incidents
        # print("[+] Detected anomalies (prompts for mitigation agent):")
        # logger.info(f"Detected {len(incidents)} anomalies")
        # for incident in incidents:
        #     print(f"  - {incident.description}")
        #     logger.info(f"Anomaly: {incident.description}")

        # Print LLM-specific summary if an LLM anomaly was detected
        if llm_incident and llm_incident.description and "no anomalies" not in llm_incident.description.lower():
            print("\n[+] LLM Anomaly Summary:")
            print(f"    - Type: {llm_incident.details.get('type', 'Unknown')}")
            print(f"    - Description: {llm_incident.description}")
            print(f"    - Source IP: {llm_incident.src_ip or 'None'}")
            print(f"    - Destination IP: {llm_incident.dst_ip or 'None'}")
            print(f"    - Details: {llm_incident.details}")

        # Generate LLM-based summary for all incidents
        print("\n[+] LLM Cyber Attack Summary:")
        llm_summary = self.llm_summarize_incidents(incidents)
        print(llm_summary)

    def run(self):
        """
        Main loop to monitor logs and detect anomalies.
        """
        try:
            print("[+] Anomaly detection agent started. Monitoring logs...")
            logger.info("Anomaly detection agent started")
            # Use last processed timestamp as start time, end time as now
            end_time = (datetime.now() - timedelta(hours=1)).strftime('%Y-%m-%d %H:%M:%S')
            start_time = self.last_timestamp

            self.detect_anomalies(start_time, end_time)

        except KeyboardInterrupt:
            print("\n[!] Stopping anomaly detection agent...")
            logger.info("Anomaly detection agent stopped by user")
        finally:
            self.conn.close()
            logger.info("Snowflake connection closed")

if __name__ == "__main__":
    try:
        agent = AnomalyDetectionAgent()
        agent.run()
    except Exception as e:
        print(f"[!] Failed to initialize anomaly detection agent: {e}")
        logger.error(f"Failed to initialize anomaly detection agent: {e}")