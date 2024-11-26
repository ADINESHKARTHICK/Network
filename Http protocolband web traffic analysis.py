#1. Web Traffic Logging and HTTP Protocol Monitoring
from flask import Flask, request, jsonify
import logging
app = Flask(__name__)
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(message)s")
logger = logging.getLogger()
@app.before_request
def log_request():
    logger.info(f"Request Method: {request.method} | URL: {request.url} | Headers: {request.headers}")
@app.route('/api/data', methods=['GET'])
def get_data():
    logger.info("GET request received on /api/data")
    return jsonify({"message": "Data fetched successfully!"}), 200
@app.route('/api/data', methods=['POST'])
def post_data():
    data = request.get_json()
    logger.info(f"POST request received with data: {data}")
    return jsonify({"message": "Data received successfully!"}), 201
@app.route('/api/traffic', methods=['GET'])
def analyze_traffic():
    # Simulated traffic analysis
    traffic_data = {
        "total_requests": 5000,
        "error_rate": 2.5,
        "traffic_source": "Organic Search"
    }
    logger.info(f"Traffic analysis data: {traffic_data}")
    return jsonify(traffic_data), 200
if __name__ == '__main__':
    app.run(debug=True)
#2. Performance Testing and Load Simulation with Locust
from locust import HttpUser, task, between
class TrafficLoadTest(HttpUser):
    wait_time = between(1, 2)
    @task
    def get_data(self):
        self.client.get("/api/data")
    @task
    def post_data(self):
        self.client.post("/api/data", json={"name": "Sample", "description": "Test item"})
    @task
    def analyze_traffic(self):
        self.client.get("/api/traffic")
if __name__ == "__main__":

#3. Traffic Log Analysis with Elasticsearch
from elasticsearch import Elasticsearch
import json
es = Elasticsearch([{'host': 'localhost', 'port': 9200}])
def index_traffic_data(data):
    es.index(index="http-traffic", doc_type="_doc", body=data)
def analyze_traffic_data():
    query = {
        "query": {
            "match_all": {}
        }
    }
    response = es.search(index="http-traffic", body=query)
    for hit in response['hits']['hits']:
        print(json.dumps(hit['_source'], indent=4))
if __name__ == "__main__":
    # Example of traffic data to be indexed
    traffic_data = {
        "timestamp": "2024-11-26T10:00:00",
        "request_method": "GET",
        "url": "/api/data",
        "response_time": 120,  # in ms
        "status_code": 200
    }
    index_traffic_data(traffic_data)
    analyze_traffic_data()

#4. Traffic Security with HTTPS
from flask import Flask, jsonify
from OpenSSL import SSL
app = Flask(__name__)
context = SSL.Context(SSL.TLSv1_2_METHOD)
context.use_certificate_file('path/to/cert.pem')  # Path to your SSL certificate
context.use_privatekey_file('path/to/private.key')  # Path to your private key
@app.route('/secure-data', methods=['GET'])
def secure_data():
    return jsonify({"message": "Secure data accessed successfully!"}), 200
if __name__ == '__main__':
    app.run(ssl_context=context, debug=True)

#5. Web Traffic Analysis Using Python's Pyshark (Packet Sniffing)
import pyshark
def analyze_traffic():
    cap = pyshark.LiveCapture(interface='eth0')  # Specify your network interface (e.g., 'eth0')
    cap.sniff(timeout=50)  # Capture packets for 50 seconds
    for packet in cap:
        if 'HTTP' in packet:
            print(f"HTTP Packet: {packet.http}")
if __name__ == '__main__':
    analyze_traffic()



