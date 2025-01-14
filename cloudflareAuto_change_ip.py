import socket
import json
import os
import requests
import time
from ping3 import ping
from dotenv import load_dotenv
import traceback


def initialize_env():
    """
    اگر فایل .env وجود نداشته باشد یا خالی باشد،
    اطلاعات مورد نیاز (Zone ID، IP سرورها، و غیره) پرسیده می‌شود و در .env ذخیره می‌گردد.
    """
    if not os.path.exists('.env') or os.path.getsize('.env') == 0:
        print("No valid .env file found. Let's create one...")
        with open('.env', 'w') as env_file:
            num_zones = int(input("How many domains (zones) do you have? "))
            for i in range(1, num_zones + 1):
                zone_id = input(f"Enter the Zone ID for domain {i}: ")
                env_file.write(f"ZONE_{i}_ID={zone_id}\n")

            num_servers = int(input("How many servers do you have? "))
            for i in range(1, num_servers + 1):
                ip = input(f"Enter the IP of server {i}: ")
                port = input(f"Enter the TCP port for server {i}: ")
                priority = input(f"Enter the priority for server {i} (1 = highest priority): ")
                env_file.write(f"SERVER_{i}_IP={ip}\n")
                env_file.write(f"SERVER_{i}_PORT={port}\n")
                env_file.write(f"SERVER_{i}_PRIORITY={priority}\n")

            email = input("Enter your Cloudflare Email (for Global API Key): ")
            env_file.write(f"CLOUDFLARE_EMAIL={email}\n")

            api_key = input("Enter your Cloudflare Global API Key: ")
            env_file.write(f"CLOUDFLARE_API_KEY={api_key}\n")

            telegram_token = input("Enter your Telegram bot token: ")
            env_file.write(f"TELEGRAM_TOKEN={telegram_token}\n")

            chat_id = input("Enter your Telegram chat ID: ")
            env_file.write(f"CHAT_ID={chat_id}\n")

            interval = input("Enter the interval for checking servers (in seconds, default 120): ")
            env_file.write(f"INTERVAL={interval or 120}\n")
        print(".env file created successfully.")


initialize_env()
load_dotenv()

EMAIL = os.getenv('CLOUDFLARE_EMAIL')
API_KEY = os.getenv('CLOUDFLARE_API_KEY')
TELEGRAM_TOKEN = os.getenv('TELEGRAM_TOKEN')
CHAT_ID = os.getenv('CHAT_ID')
STATUS_FILE = 'status.json'
ERROR_LOG_FILE = 'error_log.txt'
ADDRESSES = []
ZONE_IDS = []
MAX_ATTEMPTS = 3
INTERVAL = int(os.getenv('INTERVAL', 120))

for i in range(1, 100):
    zone_id = os.getenv(f"ZONE_{i}_ID")
    if not zone_id:
        break
    ZONE_IDS.append(zone_id)

for i in range(1, 100):
    ip = os.getenv(f"SERVER_{i}_IP")
    port = os.getenv(f"SERVER_{i}_PORT")
    priority = os.getenv(f"SERVER_{i}_PRIORITY")
    if not ip or not port or not priority:
        break
    ADDRESSES.append((int(port), ip, int(priority)))


def log_error(error_message):
    with open(ERROR_LOG_FILE, 'a') as file:
        file.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {error_message}\n")


def get_subdomains(zone_id):
    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records"
    headers = {
        'X-Auth-Email': EMAIL,
        'X-Auth-Key': API_KEY,
        'Content-Type': 'application/json'
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        records = response.json()['result']
        allowed_ips = {ip for _, ip, _ in ADDRESSES}
        return {
            record['name']: record['content']
            for record in records
            if record['type'] == 'A' and record['content'] in allowed_ips
        }
    else:
        error_message = f"Error fetching subdomains for zone {zone_id}: {response.status_code}"
        print(error_message)
        log_error(error_message)
        return {}


def check_ping(ip):
    try:
        response_time = ping(ip, timeout=2)
        if response_time is not None:
            response_time *= 1000
            response_time = round(response_time, 2)
        return response_time
    except Exception as e:
        error_message = f"Error pinging {ip}: {e}"
        print(error_message)
        log_error(error_message)
        return None


def check_tcp(ip, port):
    try:
        with socket.create_connection((ip, port), timeout=5):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        error_message = f"TCP connection to {ip}:{port} failed: {e}"
        print(error_message)
        log_error(error_message)
        return False


def update_dns_record(zone_id, record_id, name, new_ip):
    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_id}"
    headers = {
        'X-Auth-Email': EMAIL,
        'X-Auth-Key': API_KEY,
        'Content-Type': 'application/json'
    }
    data = {
        'type': 'A',
        'name': name,
        'content': new_ip,
    }
    response = requests.put(url, json=data, headers=headers)
    if response.status_code == 200:
        return True
    else:
        error_message = f"Error updating DNS record for {name} to {new_ip} in zone {zone_id}: {response.status_code}"
        print(error_message)
        log_error(error_message)
        return False


def send_telegram_message(message):
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    data = {
        'chat_id': CHAT_ID,
        'text': message,
        'parse_mode': 'HTML'
    }
    response = requests.post(url, data=data)
    print("Telegram Status Code:", response.status_code)
    print("Telegram Response JSON:", response.json())


def read_status_file():
    if os.path.exists(STATUS_FILE):
        with open(STATUS_FILE, 'r') as file:
            return json.load(file)
    return {}


def write_status_file(status):
    with open(STATUS_FILE, 'w') as file:
        json.dump(status, file, indent=4)


def check_subdomain_status(zone_id, subdomain, ip, last_status, change_summary, status_summary):
    ping_time = check_ping(ip)
    if subdomain not in last_status:
        last_status[subdomain] = {
            'original_ip': ip,
            'ping_failures': 0,
            'tcp_failures': 0,
            'new_ip': None,
            'is_restored': False
        }
    subdomain_status = last_status[subdomain]
    if ping_time is None:
        subdomain_status['ping_failures'] += 1
        if subdomain_status['ping_failures'] >= MAX_ATTEMPTS:
            new_ip = None
            sorted_addresses = sorted(ADDRESSES, key=lambda x: x[2])
            for port, address, priority in sorted_addresses:
                if address != subdomain_status['original_ip'] and address != subdomain_status['new_ip'] and check_ping(address) is not None:
                    new_ip = address
                    break
            if new_ip:
                update_ip_for_subdomain(zone_id, subdomain, new_ip, subdomain_status, last_status, change_summary)
            else:
                change_summary.append(
                    f"❌ {subdomain} (IP: {ip}) - Ping: None ms | Ping Failed after {MAX_ATTEMPTS} attempts. No alternative IP found."
                )
        else:
            status_summary.append(
                f"⚠️ {subdomain} (IP: {ip}) - Ping: None ms | Ping Failed (Attempt {subdomain_status['ping_failures']}/{MAX_ATTEMPTS})"
            )
    else:
        subdomain_status['ping_failures'] = 0
        tcp_status = None
        for port, address, priority in ADDRESSES:
            if address == ip:
                tcp_status = check_tcp(ip, port)
                break
        if tcp_status:
            subdomain_status['tcp_failures'] = 0
            status_summary.append(f"✅ {subdomain} (IP: {ip}) - Ping: {ping_time} ms | TCP: Success")
        else:
            subdomain_status['tcp_failures'] += 1
            if subdomain_status['tcp_failures'] >= MAX_ATTEMPTS:
                new_ip = None
                sorted_addresses = sorted(ADDRESSES, key=lambda x: x[2])
                for port, address, priority in sorted_addresses:
                    if address != subdomain_status['original_ip'] and address != subdomain_status['new_ip'] and check_ping(address) is not None:
                        new_ip = address
                        break
                if new_ip:
                    update_ip_for_subdomain(zone_id, subdomain, new_ip, subdomain_status, last_status, change_summary)
                else:
                    change_summary.append(
                        f"❌ {subdomain} (IP: {ip}) - TCP: Failed after {MAX_ATTEMPTS} attempts. No alternative IP found."
                    )
            else:
                status_summary.append(
                    f"⚠️ {subdomain} (IP: {ip}) - Ping: {ping_time} ms | TCP: Failed (Attempt {subdomain_status['tcp_failures']}/{MAX_ATTEMPTS})"
                )
        write_status_file(last_status)


def check_for_revert_to_original_ip(zone_id, subdomain, last_status, change_summary):
    subdomain_status = last_status[subdomain]
    original_ip = subdomain_status['original_ip']
    if subdomain_status['new_ip'] is not None:
        successful_pings = all(check_ping(original_ip) is not None for _ in range(3))
        successful_tcps = all(check_tcp(original_ip, port) for port, ip, _ in ADDRESSES if ip == original_ip)
        if successful_pings and successful_tcps:
            update_ip_for_subdomain(zone_id, subdomain, original_ip, subdomain_status, last_status, change_summary)
            subdomain_status['new_ip'] = None
            change_summary.append(
                f"✅ {subdomain} (IP: {original_ip}) - Successfully reverted to original IP after recovery."
            )
            write_status_file(last_status)


def update_ip_for_subdomain(zone_id, subdomain, new_ip, subdomain_status, last_status, change_summary):
    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records"
    headers = {
        'X-Auth-Email': EMAIL,
        'X-Auth-Key': API_KEY,
        'Content-Type': 'application/json'
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        records = response.json()['result']
        for record in records:
            if record['name'] == subdomain:
                record_id = record['id']
                if update_dns_record(zone_id, record_id, subdomain, new_ip):
                    if new_ip == subdomain_status['original_ip']:
                        subdomain_status['new_ip'] = None
                        change_summary.append(
                            f"✅ {subdomain} (IP: {new_ip}) - Successfully reverted to original IP after 3 successful ping and TCP tests."
                        )
                    else:
                        old_ip = subdomain_status['original_ip']
                        subdomain_status['new_ip'] = new_ip
                        change_summary.append(
                            f"❌ {subdomain} (IP: {old_ip}) - Updated to new IP: {new_ip}"
                        )
                    break
        write_status_file(last_status)
    else:
        log_error(f"Error fetching DNS records for zone {zone_id}. Response Code: {response.status_code}")


def main():
    last_status = read_status_file()
    while True:
        try:
            start_time = time.time()
            for zone_id in ZONE_IDS:
                subdomains = get_subdomains(zone_id)
                if not subdomains:
                    print(f"No subdomains found for zone {zone_id}.")
                    continue
                status_summary = []
                change_summary = []
                for subdomain, ip in subdomains.items():
                    check_subdomain_status(zone_id, subdomain, ip, last_status, change_summary, status_summary)
                    check_for_revert_to_original_ip(zone_id, subdomain, last_status, change_summary)
                if change_summary:
                    message = f"Zone ID: {zone_id}\n" + "\n".join(change_summary)
                    send_telegram_message(message)
                if status_summary:
                    message = f"Zone ID: {zone_id}\n" + "\n".join(status_summary)
                    send_telegram_message(message)
            elapsed_time = time.time() - start_time
            sleep_time = max(0, INTERVAL - elapsed_time)
            time.sleep(sleep_time)
        except Exception as e:
            error_message = traceback.format_exc()
            log_error(error_message)
            print(f"An error occurred: {error_message}")


if __name__ == "__main__":
    main()
