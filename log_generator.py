import random
import os
import datetime
import argparse
from pathlib import Path

# Log levels with their approximate distribution weights
LOG_LEVELS = {
    "INFO": 70,
    "WARN": 25,
    "ERROR": 4,
    "DEBUG": 1
}

# Components that might appear in log messages
COMPONENTS = [
    "QuorumPeer", "QuorumCnxManager$Listener", "SendWorker", 
    "RecvWorker", "FastLeaderElection", "ZooKeeperServer",
    "ServerCnxnFactory", "NIOServerCnxn", "DataTree", "ZKDatabase"
]

# Message templates
MESSAGE_TEMPLATES = [
    "Received connection request {ip}:{port}",
    "Connection broken for id {id}, my id = {myid}, error = ",
    "Send worker leaving thread",
    "Interrupted while waiting for message on queue",
    "Interrupting SendWorker",
    "Notification time out: {timeout}",
    "Processing request: {operation}",
    "Session closed for client {clientid}",
    "Created server with tickTime {tick} minSessionTimeout {min} maxSessionTimeout {max}",
    "Established session with client {ip}:{port}"
]

def generate_random_ip():
    return f"10.10.{random.randint(1, 255)}.{random.randint(1, 255)}"

def generate_random_port():
    return random.randint(30000, 65000)

def generate_random_id():
    return random.randint(100000000000, 999999999999)

def generate_log_message():
    template = random.choice(MESSAGE_TEMPLATES)
    
    # Replace placeholders with random values
    if "{ip}" in template:
        template = template.replace("{ip}", generate_random_ip())
    if "{port}" in template:
        template = template.replace("{port}", str(generate_random_port()))
    if "{id}" in template:
        template = template.replace("{id}", str(generate_random_id()))
    if "{myid}" in template:
        template = template.replace("{myid}", str(random.randint(1, 5)))
    if "{timeout}" in template:
        template = template.replace("{timeout}", str(random.randint(1000, 5000)))
    if "{operation}" in template:
        template = template.replace("{operation}", random.choice(["create", "delete", "set data", "get data", "get children"]))
    if "{clientid}" in template:
        template = template.replace("{clientid}", str(generate_random_id()))
    if "{tick}" in template:
        template = template.replace("{tick}", str(random.randint(1000, 3000)))
    if "{min}" in template:
        template = template.replace("{min}", str(random.randint(2000, 4000)))
    if "{max}" in template:
        template = template.replace("{max}", str(random.randint(4000, 8000)))
        
    return template

def generate_log_entry():
    # Generate timestamp
    start_date = datetime.datetime(2015, 7, 29)
    end_date = datetime.datetime(2015, 8, 2)
    random_date = start_date + datetime.timedelta(
        seconds=random.randint(0, int((end_date - start_date).total_seconds()))
    )
    timestamp = random_date.strftime("%Y-%m-%d %H:%M:%S,%f")[:-3]
    
    # Generate log level based on weighted distribution
    log_level = random.choices(
        list(LOG_LEVELS.keys()), 
        weights=list(LOG_LEVELS.values())
    )[0]
    
    # Generate component
    component = random.choice(COMPONENTS)
    random_id = generate_random_id()
    ip = generate_random_ip()
    port = generate_random_port()
    
    # Format the log entry
    log_entry = f"{timestamp} - {log_level}  [{component}[myid={random.randint(1,5)}]/{ip}:{port}:{component}@{random.randint(100, 999)}] - {generate_log_message()}"
    
    return log_entry

def create_log_file(filename, lines=1000):
    with open(filename, 'w') as f:
        for _ in range(lines):
            f.write(generate_log_entry() + '\n')

def main():
    parser = argparse.ArgumentParser(description='Generate random log files in ZooKeeper format')
    parser.add_argument('--num_files', type=int, default=1, help='Number of log files to generate')
    parser.add_argument('--lines_per_file', type=int, default=1000, help='Number of lines per log file')
    parser.add_argument('--output_dir', type=str, default='./logs', help='Directory to store log files')
    
    args = parser.parse_args()
    
    # Create output directory if it doesn't exist
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    print(f"Generating {args.num_files} log files with {args.lines_per_file} lines each in {output_dir}")
    
    for i in range(args.num_files):
        filename = output_dir / f"zookeeper_log_{i+1}.log"
        create_log_file(filename, args.lines_per_file)
        print(f"Created {filename}")
    
    print("Log file generation complete!")

if __name__ == "__main__":
    main()