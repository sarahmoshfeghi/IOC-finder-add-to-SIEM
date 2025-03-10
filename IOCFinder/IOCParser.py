import re
import csv
import requests
from pymongo import MongoClient
from urllib.parse import urlparse

# MongoDB setup
client = MongoClient('mongodb://localhost:27017/')
db = client['ioc_database']
hashes_collection = db['hashes']
ips_collection = db['ips']
urls_collection = db['urls']

# Create collections if they do not exist
if 'hashes' not in db.list_collection_names():
    db.create_collection('hashes')
if 'ips' not in db.list_collection_names():
    db.create_collection('ips')
if 'urls' not in db.list_collection_names():
    db.create_collection('urls')

# Function to download content from a URL
def download_content(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.text
    except requests.RequestException as e:
        print(f"Error downloading {url}: {e}")
        return None

# Function to extract URLs from text
def extract_urls(text):
    url_pattern = r'hxxps\[:\]//\S+'
    base_urls = set()  # Create a set to store unique base URLs
    for match in re.finditer(url_pattern, text):
        url = match.group()
        url = url.replace("hxxps[:]//", "https://").replace("[.]", ".")
        base_url = urlparse(url).netloc  # Extract the domain name
        base_urls.add(base_url)  # Add the base URL to the set
    return base_urls

# Function to extract hashes from text
def extract_hashes(text):
    hash_pattern = r'([a-fA-F\d]{64})'
    return re.findall(hash_pattern, text)

# Function to check if an IP is public and not localhost
def is_valid_ip(ip):
    private_ip_regex = re.compile(
        r'\b(?!(?:127\.\d{1,3}\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|169\                                                                    .254\.\d{1,3}\.\d{1,3}|100\.64\.\d{1,3}\.\d{1,3}))'
        r'(?:[1-9]\d?|1\d\d|2[01]\d|22[0-3])(?:\.(?:1?\d{1,2}|2[0-4]\d|25[0-5])){3}\b')
    return private_ip_regex.match(ip) is not None

# Function to extract IP addresses from text with port as delimiter
def extract_ips(text):
    ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'  # Pattern to match IP addresses
    ips = re.findall(ip_pattern, text)
    ips = [ip for ip in ips if is_valid_ip(ip)]
    return ips

# Function to extract all information from text
def extract_information(text):
    urls = extract_urls(text)
    hashes = extract_hashes(text)
    ips = extract_ips(text)
    return urls, hashes, ips

# Function to process each link, extract information, and save to MongoDB and CSV files without headers
def extract_information_to_csv_no_headers(links_file_path):
    unique_urls = set()
    unique_hashes = set()
    unique_ips = set()

    with open(links_file_path, 'r') as links_file:
        for link in links_file:
            link = link.strip()
            content = download_content(link)
            if content:
                urls, hashes, ips = extract_information(content)

                unique_urls.update(urls)
                unique_hashes.update(hashes)
                unique_ips.update(ips)

    # Write URLs to a CSV file without headers and insert into MongoDB
    with open('url.csv', 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        for url in unique_urls:
            writer.writerow([url])
            if not urls_collection.find_one({"url": url}):
                urls_collection.insert_one({"url": url})

    # Write hashes to a CSV file without headers and insert into MongoDB
    with open('hashes.csv', 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        for hash_val in unique_hashes:
            writer.writerow([hash_val])
            if not hashes_collection.find_one({"hash": hash_val}):
                hashes_collection.insert_one({"hash": hash_val})

    # Write IP addresses to a CSV file without headers and insert into MongoDB
    with open('ips.csv', 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        for ip in unique_ips:
            writer.writerow([ip])
            if not ips_collection.find_one({"ip": ip}):
                ips_collection.insert_one({"ip": ip})

# Example usage
extract_information_to_csv_no_headers('ioc_report.txt')
