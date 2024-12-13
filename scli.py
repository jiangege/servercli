import re
import os
import argparse
from datetime import datetime, timedelta
import pytz
import subprocess


def check_security_logs():
    """
    Check system logs for suspicious and dangerous activities including SSH attempts,
    system modifications, and security-related operations.

    Returns:
        dict: A dictionary with keywords as keys and a tuple (count, average interval) as values.
    """
    log_files = {
        "/var/log/auth.log": [
            "Failed password",
            "Accepted password",
            "Invalid user",
            "sudo",
            "root login",
            "permission denied",
            "authentication failure",
            "SECURITY VIOLATION",
        ],
        "/var/log/syslog": [
            "error",
            "warning",
            "critical",
            "emergency",
            "firewall",
            "iptables",
        ],
        "/var/log/kern.log": ["segfault", "error", "fail", "denied"],
    }

    keyword_data = {}
    for log_file, keywords in log_files.items():
        for keyword in keywords:
            keyword_data[f"{log_file}:{keyword}"] = []

    try:
        now = datetime.now(pytz.utc)
        for log_file in log_files:
            if not os.path.exists(log_file):
                print(f"Log file {log_file} does not exist!")
                continue

            with open(log_file, "r") as file:
                for line in file:
                    for keyword in log_files[log_file]:
                        if keyword.lower() in line.lower():
                            try:
                                timestamp_str = line.split()[0]
                                log_time = datetime.fromisoformat(timestamp_str)

                                if log_time.tzinfo is None:
                                    log_time = pytz.utc.localize(log_time)

                                if now - log_time <= timedelta(hours=24):
                                    keyword_data[f"{log_file}:{keyword}"].append(
                                        log_time
                                    )
                            except ValueError:
                                print(
                                    f"Skipping line due to unrecognized timestamp: {line.strip()}"
                                )
                                continue
    except Exception as e:
        print(f"Error reading log files: {e}")
        return {}

    # Calculate statistics
    result = {}
    for key, timestamps in keyword_data.items():
        if timestamps:
            timestamps.sort()
            intervals = [
                (timestamps[i] - timestamps[i - 1]).total_seconds()
                for i in range(1, len(timestamps))
            ]
            average_interval = sum(intervals) / len(intervals) if intervals else 0
            result[key] = (len(timestamps), average_interval)
        else:
            result[key] = (0, 0)

    return result


def install_fail2ban():
    """
    Install and enable Fail2Ban on the server.
    """
    try:
        # Check if Fail2Ban is already installed
        check_install = subprocess.run(
            ["dpkg", "-l", "fail2ban"], stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        if check_install.returncode == 0:
            print("Fail2Ban is already installed.")
        else:
            print("Installing Fail2Ban...")
            subprocess.run(["sudo", "apt-get", "update"], check=True)
            subprocess.run(["sudo", "apt-get", "install", "-y", "fail2ban"], check=True)

        # Check if Fail2Ban service is active
        check_status = subprocess.run(
            ["sudo", "systemctl", "is-active", "fail2ban"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
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
        result = subprocess.run(
            ["sudo", "netstat", "-tuln"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if result.returncode != 0:
            print("Error fetching port information:")
            print(result.stderr)
            return

        print("Open ports detected:")
        lines = result.stdout.strip().split("\n")
        for line in lines[2:]:  # Skip headers
            print(line)

        print(
            "\nReview open ports for potential risks, such as unnecessary services or default ports."
        )
    except Exception as e:
        print(f"An error occurred while listing ports: {e}")


def install_basic_tools():
    """
    Install common system tools and utilities.
    """
    tools = {
        "net-tools": "Network tools (includes netstat)",
        "python3": "Python 3",
        "python3-pip": "Python package manager",
        "htop": "System monitoring tool",
        "curl": "File transfer tool",
        "wget": "File download utility",
        "vim": "Text editor",
        "tmux": "Terminal multiplexer",
    }

    try:
        print("Updating package list...")
        subprocess.run(["sudo", "apt-get", "update"], check=True)

        for tool, description in tools.items():
            print(f"\nInstalling {tool} ({description})...")
            try:
                subprocess.run(["sudo", "apt-get", "install", "-y", tool], check=True)
                print(f"{tool} installed successfully")
            except subprocess.CalledProcessError as e:
                print(f"Failed to install {tool}: {e}")

    except subprocess.CalledProcessError as e:
        print(f"Error updating package list: {e}")


def clean_privacy_logs():
    """
    Clean sensitive information from log files and display SSH login records.
    """
    try:
        log_files = [
            "/var/log/auth.log",
            "/var/log/btmp",
            "/var/log/wtmp",
            "/var/log/lastlog",
        ]

        # Display SSH login records
        print("Recent SSH login records:")
        try:
            last_output = subprocess.run(
                ["last"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )
            print(last_output.stdout)
        except subprocess.CalledProcessError as e:
            print(f"Error fetching SSH records: {e}")

        # Ask for confirmation before cleaning
        confirm = input("Do you want to clean privacy logs? (y/N): ")
        if confirm.lower() != "y":
            print("Operation cancelled.")
            return

        # Clean logs
        for log_file in log_files:
            if os.path.exists(log_file):
                try:
                    open(log_file, "w").close()  # Truncate file
                    print(f"Cleaned {log_file}")
                except PermissionError:
                    print(f"Permission denied for {log_file}. Try running with sudo.")
            else:
                print(f"Log file {log_file} not found")

        print("Privacy logs cleaned successfully")

    except Exception as e:
        print(f"Error during privacy cleaning: {e}")


def main():
    parser = argparse.ArgumentParser(description="Server Security Tool")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Sub-command: cl (Check system security logs)
    log_parser = subparsers.add_parser(
        "cl", help="Check system security logs for suspicious activities"
    )

    # Sub-command: if2 (Install Fail2Ban)
    fail2ban_parser = subparsers.add_parser("if2", help="Install and enable Fail2Ban")

    # Sub-command: lp (List risky ports)
    ports_parser = subparsers.add_parser(
        "lp", help="List all open ports and identify potentially risky ones"
    )

    # New subcommand: it (Install Tools)
    tools_parser = subparsers.add_parser("it", help="Install common system utilities")

    # Add new subcommand: cp (Clean Privacy)
    privacy_parser = subparsers.add_parser(
        "cp", help="Clean privacy logs and display SSH login records"
    )

    args = parser.parse_args()

    if args.command == "cl":
        statistics = check_security_logs()
        if statistics:
            print("Suspicious activities in the last 24 hours:")
            for key, (count, avg_interval) in statistics.items():
                log_file, keyword = key.split(":", 1)
                if count > 0:
                    print(f"Log: {log_file}")
                    print(f"  Keyword: {keyword}")
                    print(f"  Count: {count}")
                    print(f"  Average Interval: {avg_interval:.2f} seconds\n")
        else:
            print("No suspicious log entries found in the last 24 hours.")
    elif args.command == "if2":
        install_fail2ban()
    elif args.command == "lp":
        list_risky_ports()
    elif args.command == "it":
        install_basic_tools()
    elif args.command == "cp":
        clean_privacy_logs()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
