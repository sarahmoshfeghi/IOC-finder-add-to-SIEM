import os
import pandas as pd
import paramiko
from getpass import getpass
import re

def load_credentials(file_path):
    import json
    with open(file_path, 'r') as file:
        return json.load(file)

def get_credentials():
    remote_server = {}
    credentials = load_credentials('credentials.json')
    if credentials:
        remote_server = credentials.get('remote_server', {})
    else:
        remote_server['hostname'] = input('Enter remote server hostname: ')
        remote_server['port'] = int(input('Enter remote server port: ') or 22)
        remote_server['username'] = input('Enter remote server username: ')
        remote_server['password'] = getpass('Enter remote server password: ')

    return remote_server

def check_ssh_connectivity(remote_server):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(remote_server['hostname'], port=remote_server['port'], username=remote_server['username'], password=remote_server['password'])
        ssh.close()
        return True
    except Exception as e:
        print(f"SSH connectivity check failed: {e}")
        return False

def is_valid_ip(ip):
    pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    return bool(pattern.match(ip))

def is_valid_hash(hash_value):
    pattern = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")
    return bool(pattern.match(hash_value))

def append_to_remote_files(remote_server, remote_dir, local_ip_file, local_hash_file):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(remote_server['hostname'], port=remote_server['port'], username=remote_server['username'], password=remote_server['password'])

        sftp = ssh.open_sftp()

        # Define remote file paths
        remote_ip_file = os.path.join(remote_dir, 'iplist.csv')
        remote_hash_file = os.path.join(remote_dir, 'hash.csv')

        # Read local reference files
        local_ip_df = pd.read_csv(local_ip_file)
        local_hash_df = pd.read_csv(local_hash_file)

        # Read new entries
        new_ip_df = pd.read_csv('ips.csv')
        new_hash_df = pd.read_csv('hashes.csv')

        # Filter valid entries
        new_ip_df = new_ip_df[new_ip_df.iloc[:, 0].apply(is_valid_ip)]
        new_hash_df = new_hash_df[new_hash_df.iloc[:, 0].apply(is_valid_hash)]

        # Remove duplicates
        filtered_ip_df = new_ip_df[~new_ip_df.apply(tuple, 1).isin(local_ip_df.apply(tuple, 1))]
        filtered_hash_df = new_hash_df[~new_hash_df.apply(tuple, 1).isin(local_hash_df.apply(tuple, 1))]

        # Append new entries to remote files
        if not filtered_ip_df.empty:
            with sftp.file(remote_ip_file, 'a') as remote_file:
                filtered_ip_df.to_csv(remote_file, header=False, index=False)
            print(f"Appended new IPs to {remote_ip_file}")
        else:
            print("No new IPs to append")

        if not filtered_hash_df.empty:
            with sftp.file(remote_hash_file, 'a') as remote_file:
                filtered_hash_df.to_csv(remote_file, header=False, index=False)
            print(f"Appended new hashes to {remote_hash_file}")
        else:
            print("No new hashes to append")

        # Append new entries to local reference files
        if not filtered_ip_df.empty:
            filtered_ip_df.to_csv(local_ip_file, mode='a', header=False, index=False)
            print(f"Appended new IPs to local file {local_ip_file}")

        if not filtered_hash_df.empty:
            filtered_hash_df.to_csv(local_hash_file, mode='a', header=False, index=False)
            print(f"Appended new hashes to local file {local_hash_file}")

        sftp.close()
        ssh.close()
    except Exception as e:
        print(f"Failed to process and update files: {e}")

def main():
    remote_server = get_credentials()
    if not check_ssh_connectivity(remote_server):
        print("Failed to connect to the remote server. Exiting...")
        return

    remote_dir_path = r'pathtothesplunk\etc\apps\search\lookups\\'
    local_ip_file_path = 'remote_iplist.csv'
    local_hash_file_path = 'remote_hash.csv'

    append_to_remote_files(remote_server, remote_dir_path, local_ip_file_path, local_hash_file_path)

if __name__ == "__main__":
    main()
