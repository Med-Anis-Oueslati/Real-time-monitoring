# Real-time Cybersecurity Monitoring and Mitigation Platform

## 1. Overview

This project is a comprehensive, real-time cybersecurity monitoring and threat mitigation platform. It is designed to collect, process, and analyze various types of log data to detect security threats and anomalies. The platform includes a web-based user interface for visualizing data, managing detected anomalies, and interacting with mitigation agents. An advanced conversational AI agent is also integrated to provide natural language interaction with the system.

## 2. Core Features

*   **Real-time Log Ingestion**: Collects system and network logs in real-time from multiple sources using Fluentd.
*   **Distributed Data Streaming**: Utilizes Kafka for a scalable and resilient data pipeline.
*   **Large-scale Data Processing**: Employs Spark for distributed processing and analysis of log data.
*   **Automated Anomaly Detection**: Includes agents to automatically detect security anomalies and potential attacks.
*   **Threat Mitigation**: Features mitigation agents that can take action to respond to detected threats.
*   **Conversational AI Agent**: Allows users to interact with the system, query data, and initiate actions using natural language.
*   **Web-based Dashboard**: A Flask web application provides a user-friendly interface for monitoring, analysis, and interaction.
*   **Distributed and Cloud Storage**: Uses HDFS for large-scale data storage and Snowflake for structured data warehousing.

## 3. System Architecture

The platform is built on a distributed, microservices-based architecture:

1.  **Log Collection**: `Fluentd` agents are deployed on monitored systems to collect logs (`syslog`, `auth.log`, Zeek data, etc.).
2.  **Data Ingestion**: Logs are forwarded to a `Kafka` cluster, which acts as a central, high-throughput message bus.
3.  **Data Processing**: `Spark` jobs consume data from Kafka topics in real-time. These jobs parse, transform, and analyze the data to identify patterns and potential threats.
4.  **Data Storage**: Raw and processed data is stored in a `Hadoop HDFS` cluster for long-term storage and batch analysis. Structured data and analysis results are stored `Snowflake`.
5.  **Backend & Frontend**: A `Flask` application serves as the backend, providing a REST API and managing user interaction. The frontend provides dashboards and interfaces for visualization and control.
6.  **Agent System**: A series of intelligent agents (Anomaly Detection, Mitigation, Conversational, Attack Simulation) run as separate processes, interacting with the data pipeline and backend to perform their tasks.
7.  **Visualization**: `Grafana` is integrated for creating and displaying real-time monitoring dashboards.

## 4. Services

The entire environment is containerized using Docker and managed with `docker-compose`. The primary services include:

| Service         | Description                                                              |
| --------------- | ------------------------------------------------------------------------ |
| `fluentd`       | Log collection agent.                                                    |
| `zookeeper`     | Manages the Kafka cluster.                                               |
| `kafka`         | The core data streaming bus.                                             |
| `kafka-connect` | Moves data from Kafka to other systems, like HDFS.                       |
| `namenode`      | The master node for the HDFS cluster.                                    |
| `datanode1/2`   | Worker nodes for the HDFS cluster.                                       |
| `spark`         | The master node for the Spark processing cluster.                        |
| `spark-worker`  | Worker node for the Spark processing cluster.                            |
| `db`            | PostgreSQL database for application data.                                |
| `grafana`       | Visualization and dashboarding service.                                  |
| `webapp`        | The Flask web application  |

## 5. Prerequisites

*   [Docker](https://docs.docker.com/get-docker/)
*   [Docker Compose](https://docs.docker.com/compose/install/)

## 6. Getting Started

1.  **Clone the repository:**
    ```bash
    git clone <repository-url>
    cd Real-time-monitoring
    ```

2.  **Build and start the services:**
    ```bash
    docker-compose up --build -d
    ```

3.  **Access the services:**
    *   **Spark UI**: `http://localhost:8080`
    *   **HDFS Namenode UI**: `http://localhost:9870`
    *   **Kafka Connect UI**: `http://localhost:8083`
    *   **Grafana**: `http://localhost:3000`
    *   **Web Application**: (Port depends on application configuration)

## 7. Key Technologies

*   **Python**: The primary language for application development, data processing, and agent logic.
*   **Frameworks & Libraries**:
    *   `Flask`: Web backend.
    *   `PySpark`: Spark programming.
    *   `kafka-python`: Kafka integration.
    *   `SQLAlchemy`: Database interaction.
    *   `pandas`, `scikit-learn`: Data analysis and machine learning.
    *   `Langchain`, `OpenAI`/`Google Generative AI`: Conversational AI.
*   **Infrastructure**:
    *   `Docker` & `Docker Compose`
    *   `Apache Kafka`
    *   `Apache Spark`
    *   `Apache Hadoop (HDFS)`
    *   `PostgreSQL`
    *   `Fluentd`
    *   `Grafana`
    *   `Snowflake`
