
import requests
import re
import csv
from pymongo import MongoClient
from ipaddress import ip_address, ip_network
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

def is_valid_url(url):
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except ValueError:
        return False

# Function to check if IP is private or localhost
def is_valid_ip(ip):
    private_ip_regex = re.compile(r'\b(?!(?:127\.0\.0\.1|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|169\.254\.\d{1,3}\.\d{1,3}|100\.64\.\d{1,3}\.\d{1,3}))(?:[1-9]\d?|1\d\d|2[01]\d|22[0-3])(?:\.(?:1?\d{1,2}|2[0-4]\d|25[0-5])){3}\b')
    return private_ip_regex.match(ip) is None

# Function to download content from a URL
def download_content(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.text
    except requests.RequestException as e:
        print(f"Error downloading {url}: {e}")
        return None

# Function to extract base URLs from text and omit certain domain

def extract_urls(text):
    url_pattern = r'hxxps\[:\]//\S+'
    exclude_domains = {'telegram.org', 't.me','www.dropbox.com', 'api.ipify.org', 'twitter.com', 'linkedin.com'}
    base_urls = set()
    for match in re.finditer(url_pattern, text):
        url = match.group()
        parsed_url = urlparse(url)
        base_url = parsed_url.netloc  # Extract the domain name
        if base_url not in exclude_domains:
            base_urls.add(base_url)
    return base_urls
# Patterns for matching
ip_pattern = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
sha256_pattern = re.compile(r'\b([a-f0-9]{64}|[A-F0-9]{64})\b')

# Function to process each link, extract information, and save to MongoDB and CSV
def extract_information(links_file_path):
    unique_hashes = set()
    unique_ips = set()
    unique_urls = set()

    with open(links_file_path, 'r') as links_file:
        for link in links_file:
            link = link.strip()
            content = download_content(link)
            if content:
                extracted_hashes = set(re.findall(sha256_pattern, content))
                extracted_ips = set(re.findall(ip_pattern, content))
                extracted_urls = extract_urls(content)

                unique_hashes.update(extracted_hashes)
                unique_ips.update(extracted_ips)
                unique_urls.update(extracted_urls)

    # Insert hashes into MongoDB
    for hash_value in unique_hashes:
        if not hashes_collection.find_one({"hash": hash_value}):
            hashes_collection.insert_one({"hash": hash_value})

    # Insert IPs into MongoDB
    for ip_address_value in unique_ips:
        if is_valid_ip(ip_address_value) and not ips_collection.find_one({"ip": ip_address_value}):
            ips_collection.insert_one({"ip": ip_address_value})

    # Insert URLs into MongoDB
    for url in unique_urls:
        if is_valid_url(url) and not urls_collection.find_one({"url": url}):
            urls_collection.insert_one({"url": url})

    # Write hashes to CSV file
    with open('hashes.csv', 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        for hash_value in unique_hashes:
            writer.writerow([hash_value])

    # Write IPs to CSV file
    with open('ips.csv', 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        for ip_address_value in unique_ips:
            writer.writerow([ip_address_value])

    # Write URLs to CSV file
    with open('url.csv', 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        for url in unique_urls:
            writer.writerow([url])

# Example usage for a single file
extract_information('ioc_report.txt')
