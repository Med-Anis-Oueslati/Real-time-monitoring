-- Clear old data to avoid duplicates
DELETE FROM SPARK_DB.SPARK_SCHEMA.ZEEK_DNS WHERE TIMESTAMP < '2025-05-21 16:00:00';
DELETE FROM SPARK_DB.SPARK_SCHEMA.ZEEK_NOTICE WHERE TIMESTAMP < '2025-05-21 16:00:00';

-- Insert synthetic data into ZEEK_DNS
INSERT INTO SPARK_DB.SPARK_SCHEMA.ZEEK_DNS (
    YEAR, MONTH, DAY, HOUR, MINUTE, SECOND, TIMESTAMP, UID, ID_ORIG_H, ID_ORIG_P, 
    ID_RESP_H, ID_RESP_P, ORIG_LATITUDE, ORIG_LONGITUDE, ORIG_CITY, RESP_LATITUDE, 
    RESP_LONGITUDE, RESP_CITY, PROTO, TRANS_ID, RTT, QUERY, QCLASS, QCLASS_NAME, 
    QTYPE, QTYPE_NAME, RCODE, RCODE_NAME, AA, TC, RD, RA, Z, ANSWERS, TTLS, 
    REJECTED, HOSTNAME, VM_ID
) VALUES
-- Normal DNS traffic
(2025, 5, 21, 16, 45, 0, '2025-05-21 16:45:00', 'dns1', '192.168.1.100', 12345, '8.8.8.8', 53, NULL, NULL, NULL, NULL, NULL, NULL, 'udp', NULL, 0.01, 'www.google.com', NULL, NULL, 1, 'A', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, FALSE, NULL, 'lubuntu-vm1'),
(2025, 5, 21, 16, 45, 10, '2025-05-21 16:45:10', 'dns2', '192.168.1.100', 12346, '8.8.8.8', 53, NULL, NULL, NULL, NULL, NULL, NULL, 'udp', NULL, 0.02, 'www.example.com', NULL, NULL, 1, 'A', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, FALSE, NULL, 'lubuntu-vm1'),
(2025, 5, 21, 16, 45, 20, '2025-05-21 16:45:20', 'dns3', '192.168.1.100', 12347, '1.1.1.1', 53, NULL, NULL, NULL, NULL, NULL, NULL, 'udp', NULL, 0.015, 'api.github.com', NULL, NULL, 1, 'A', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, FALSE, NULL, 'lubuntu-vm1'),
(2025, 5, 21, 16, 45, 30, '2025-05-21 16:45:30', 'dns4', '192.168.1.100', 12348, '8.8.8.8', 53, NULL, NULL, NULL, NULL, NULL, NULL, 'udp', NULL, 0.03, 'www.amazon.com', NULL, NULL, 1, 'A', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, FALSE, NULL, 'lubuntu-vm1'),
(2025, 5, 21, 16, 45, 40, '2025-05-21 16:45:40', 'dns5', '192.168.1.100', 12349, '1.1.1.1', 53, NULL, NULL, NULL, NULL, NULL, NULL, 'udp', NULL, 0.01, 'cloudflare.com', NULL, NULL, 1, 'A', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, FALSE, NULL, 'lubuntu-vm1'),
(2025, 5, 21, 16, 46, 0, '2025-05-21 16:46:00', 'dns6', '192.168.1.100', 12350, '8.8.8.8', 53, NULL, NULL, NULL, NULL, NULL, NULL, 'udp', NULL, 0.02, 'www.microsoft.com', NULL, NULL, 1, 'A', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, FALSE, NULL, 'lubuntu-vm1'),
(2025, 5, 21, 16, 46, 10, '2025-05-21 16:46:10', 'dns7', '192.168.1.100', 12351, '1.1.1.1', 53, NULL, NULL, NULL, NULL, NULL, NULL, 'udp', NULL, 0.025, 'www.apple.com', NULL, NULL, 1, 'A', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, FALSE, NULL, 'lubuntu-vm1'),
(2025, 5, 21, 16, 46, 20, '2025-05-21 16:46:20', 'dns8', '192.168.1.100', 12352, '8.8.8.8', 53, NULL, NULL, NULL, NULL, NULL, NULL, 'udp', NULL, 0.01, 'www.facebook.com', NULL, NULL, 1, 'A', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, FALSE, NULL, 'lubuntu-vm1'),
(2025, 5, 21, 16, 46, 30, '2025-05-21 16:46:30', 'dns9', '192.168.1.100', 12353, '1.1.1.1', 53, NULL, NULL, NULL, NULL, NULL, NULL, 'udp', NULL, 0.03, 'www.twitter.com', NULL, NULL, 1, 'A', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, FALSE, NULL, 'lubuntu-vm1'),
(2025, 5, 21, 16, 46, 40, '2025-05-21 16:46:40', 'dns10', '192.168.1.100', 12354, '8.8.8.8', 53, NULL, NULL, NULL, NULL, NULL, NULL, 'udp', NULL, 0.02, 'www.linkedin.com', NULL, NULL, 1, 'A', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, FALSE, NULL, 'lubuntu-vm1'),
-- DNS tunneling traffic
(2025, 5, 21, 16, 47, 0, '2025-05-21 16:47:00', 'dns11', '10.71.0.35', 54321, '8.8.8.8', 53, NULL, NULL, NULL, NULL, NULL, NULL, 'udp', NULL, 0.5, 'partition-cname-trouter-abc123xyz789longencodeddata.example.com', NULL, NULL, 16, 'TXT', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, FALSE, NULL, 'lubuntu-vm1'),
(2025, 5, 21, 16, 47, 10, '2025-05-21 16:47:10', 'dns12', '10.71.0.35', 54322, '8.8.8.8', 53, NULL, NULL, NULL, NULL, NULL, NULL, 'udp', NULL, 0.6, 'encoded-987xyztrouter-cname-partition-longdata123.example.com', NULL, NULL, 16, 'TXT', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, FALSE, NULL, 'lubuntu-vm1'),
(2025, 5, 21, 16, 47, 20, '2025-05-21 16:47:20', 'dns13', '10.71.0.35', 54323, '8.8.8.8', 53, NULL, NULL, NULL, NULL, NULL, NULL, 'udp', NULL, 0.55, 'trouter-partition-abc789xyzlongencodedstring456.example.com', NULL, NULL, 16, 'TXT', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, FALSE, NULL, 'lubuntu-vm1'),
(2025, 5, 21, 16, 47, 30, '2025-05-21 16:47:30', 'dns14', '10.71.0.35', 54324, '8.8.8.8', 53, NULL, NULL, NULL, NULL, NULL, NULL, 'udp', NULL, 0.5, 'cname-encoded-123abcxyz789longdata789.example.com', NULL, NULL, 16, 'TXT', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, FALSE, NULL, 'lubuntu-vm1'),
(2025, 5, 21, 16, 47, 40, '2025-05-21 16:47:40', 'dns15', '10.71.0.35', 54325, '8.8.8.8', 53, NULL, NULL, NULL, NULL, NULL, NULL, 'udp', NULL, 0.6, 'partition-trouter-xyz123abc789encodedlongdata.example.com', NULL, NULL, 16, 'TXT', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, FALSE, NULL, 'lubuntu-vm1');

-- Insert synthetic data into ZEEK_NOTICE
INSERT INTO SPARK_DB.SPARK_SCHEMA.ZEEK_NOTICE (
    YEAR, MONTH, DAY, HOUR, MINUTE, SECOND, TIMESTAMP, UID, ID_ORIG_H, ID_ORIG_P, 
    ID_RESP_H, ID_RESP_P, ORIG_LATITUDE, ORIG_LONGITUDE, ORIG_CITY, RESP_LATITUDE, 
    RESP_LONGITUDE, RESP_CITY, PROTO, NOTE, MSG, SRC, DST, P, ACTIONS, EMAIL_DEST, 
    SUPPRESS_FOR, HOSTNAME, VM_ID
) VALUES
-- Tunneling notices
(2025, 5, 21, 16, 47, 5, '2025-05-21 16:47:05', 'notice1', '10.71.0.35', 54321, '8.8.8.8', 53, NULL, NULL, NULL, NULL, NULL, NULL, 'udp', 'Custom::DNS_Tunneling', 'Suspicious long query detected: partition-cname-trouter-...', '10.71.0.35', '8.8.8.8', NULL, NULL, NULL, NULL, NULL, 'lubuntu-vm1'),
(2025, 5, 21, 16, 47, 15, '2025-05-21 16:47:15', 'notice2', '10.71.0.35', 54322, '8.8.8.8', 53, NULL, NULL, NULL, NULL, NULL, NULL, 'udp', 'Custom::DNS_Tunneling', 'High TXT query rate from 10.71.0.35', '10.71.0.35', '8.8.8.8', NULL, NULL, NULL, NULL, NULL, 'lubuntu-vm1'),
(2025, 5, 21, 16, 47, 25, '2025-05-21 16:47:25', 'notice3', '10.71.0.35', 54323, '8.8.8.8', 53, NULL, NULL, NULL, NULL, NULL, NULL, 'udp', 'Custom::DNS_Tunneling', 'Encoded query pattern: trouter-partition-abc789...', '10.71.0.35', '8.8.8.8', NULL, NULL, NULL, NULL, NULL, 'lubuntu-vm1'),
(2025, 5, 21, 16, 47, 35, '2025-05-21 16:47:35', 'notice4', '10.71.0.35', 54324, '8.8.8.8', 53, NULL, NULL, NULL, NULL, NULL, NULL, 'udp', 'Custom::DNS_Tunneling', 'Potential DNS tunneling: cname-encoded-123abc...', '10.71.0.35', '8.8.8.8', NULL, NULL, NULL, NULL, NULL, 'lubuntu-vm1'),
-- Other notices
(2025, 5, 21, 16, 45, 15, '2025-05-21 16:45:15', 'notice5', '192.168.1.100', 12345, '8.8.8.8', 53, NULL, NULL, NULL, NULL, NULL, NULL, 'udp', 'Other', 'Normal DNS query observed', '192.168.1.100', '8.8.8.8', NULL, NULL, NULL, NULL, NULL, 'lubuntu-vm1'),
(2025, 5, 21, 16, 46, 15, '2025-05-21 16:46:15', 'notice6', '192.168.1.100', 12346, '1.1.1.1', 53, NULL, NULL, NULL, NULL, NULL, NULL, 'udp', 'Other', 'Standard query to cloudflare.com', '192.168.1.100', '1.1.1.1', NULL, NULL, NULL, NULL, NULL, 'lubuntu-vm1');