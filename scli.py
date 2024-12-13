import re
import os
import argparse
from datetime import datetime, timedelta
import pytz
import subprocess

def check_ssh_logs():
    """
    Automatically check SSH logs for suspicious activities such as login attempts or sensitive operations.

    Returns:
        dict: A dictionary with keywords as keys and a tuple (count, average interval) as values.
    """
    log_file_path = "/var/log/auth.log"
    if not os.path.exists(log_file_path):
        print(f"Log file {log_file_path} does not exist!")
        return {}

    keywords = ["Failed password", "Accepted password", "Invalid user", "sudo"]
    keyword_data = {keyword: [] for keyword in keywords}

    try:
        now = datetime.now(pytz.utc)
        with open(log_file_path, 'r') as log_file:
            for line in log_file:
                for keyword in keywords:
                    if keyword in line:
                        try:
                            # Attempt to parse timestamp with the detected format
                            timestamp_str = line.split()[0]
                            log_time = datetime.fromisoformat(timestamp_str)

                            # Make log_time timezone-aware if it is naive
                            if log_time.tzinfo is None:
                                log_time = pytz.utc.localize(log_time)

                        except ValueError:
                            print(f"Skipping line due to unrecognized timestamp: {line.strip()}")
                            continue

                        # Only include logs within the last 24 hours
                        if now - log_time <= timedelta(hours=24):
                            keyword_data[keyword].append(log_time)
    except Exception as e:
        print(f"Error reading log file: {e}")
        return {}

    # Calculate statistics
    result = {}
    for keyword, timestamps in keyword_data.items():
        if timestamps:
            timestamps.sort()
            intervals = [
                (timestamps[i] - timestamps[i - 1]).total_seconds()
                for i in range(1, len(timestamps))
            ]
            average_interval = sum(intervals) / len(intervals) if intervals else 0
            result[keyword] = (len(timestamps), average_interval)
        else:
            result[keyword] = (0, 0)

    return result

def install_fail2ban():
    """
    Install and enable Fail2Ban on the server.
    """
    try:
        # Check if Fail2Ban is already installed
        check_install = subprocess.run(["dpkg", "-l", "fail2ban"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if check_install.returncode == 0:
            print("Fail2Ban is already installed.")
        else:
            print("Installing Fail2Ban...")
            subprocess.run(["sudo", "apt-get", "update"], check=True)
            subprocess.run(["sudo", "apt-get", "install", "-y", "fail2ban"], check=True)

        # Check if Fail2Ban service is active
        check_status = subprocess.run(["sudo", "systemctl", "is-active", "fail2ban"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if check_status.returncode == 0:
            print("Fail2Ban is already running.")
        else:
            print("Enabling and starting Fail2Ban service...")
            subprocess.run(["sudo", "systemctl", "enable", "fail2ban"], check=True)
            subprocess.run(["sudo", "systemctl", "start", "fail2ban"], check=True)
            print("Fail2Ban has been successfully started.")
    except subprocess.CalledProcessError as e:
        print(f"An error occurred during Fail2Ban installation or setup: {e}")

def list_risky_ports():
    """
    List all open ports on the server and identify potentially risky ones.
    """
    try:
        print("Scanning for open ports...")
        result = subprocess.run(["sudo", "netstat", "-tuln"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode != 0:
            print("Error fetching port information:")
            print(result.stderr)
            return

        print("Open ports detected:")
        lines = result.stdout.strip().split("\n")
        for line in lines[2:]:  # Skip headers
            print(line)

        print("\nReview open ports for potential risks, such as unnecessary services or default ports.")
    except Exception as e:
        print(f"An error occurred while listing ports: {e}")

def main():
    parser = argparse.ArgumentParser(description="Server Security Tool")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Sub-command: csl (Check SSH Logs)
    log_parser = subparsers.add_parser("csl", help="Check SSH logs for suspicious activities")

    # Sub-command: if2 (Install Fail2Ban)
    fail2ban_parser = subparsers.add_parser("if2", help="Install and enable Fail2Ban")

    # Sub-command: list_ports (List risky ports)
    ports_parser = subparsers.add_parser("list_ports", help="List all open ports and identify potentially risky ones")

    args = parser.parse_args()

    if args.command == "csl":
        statistics = check_ssh_logs()
        if statistics:
            print("Suspicious SSH activity in the last 24 hours:")
            for keyword, (count, avg_interval) in statistics.items():
                print(f"Keyword: {keyword}, Count: {count}, Average Interval: {avg_interval:.2f} seconds")
        else:
            print("No suspicious SSH log entries found in the last 24 hours.")
    elif args.command == "if2":
        install_fail2ban()
    elif args.command == "list_ports":
        list_risky_ports()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
