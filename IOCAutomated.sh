
#!/bin/bash

# Function to check if a file is not empty
file_not_empty() {
  [[ -s "$1" ]]
}
# Run IOCFinder.py
echo "Running IOCFinder.py..."
source /etc/venv/bin/activate
python3 /pathtotheiocfinder/IOCFinder.py
# Check if ioc_report.txt is not empty
if file_not_empty "ioc_report.txt"; then
  echo "ioc_report.txt is not empty, running IOC_Parser.py..."

  # Run IOC_Parser.py to generate ips.csv, hashes.csv, and urls.csv
  #source /etc/venv/bin/activate
  python3 /pathtoiocparser/IOC_Parser.py

  # Check if ips.csv and hashes.csv are not empty
  if file_not_empty "ips.csv" || file_not_empty "hashes.csv" ; then
    echo "ips.csv or hashes.csv are not empty, running QradarAPIRefrence.py..."

    # Run QradarAPIRefrence.py to add data to Qradar
    # source /etc/venv/bin/activate
    python3 /pathtothepythoncode/Qradar-Refrenceset-Add.py
    python3 /pathtothepythoncode/splunk-dataset-add.py
    echo "These ips and hases have been added to Qradar splunk  Refrence set" | mutt -s "IOCReport" -a /pathtothepythoncode/*.csv *.txt  -- emailaddress
  else
    echo "ips.csv and/or hashes.csv are empty. Skipping Qradar-Refrenceset-Add.py."
  fi
else
  echo "ioc_report.txt is empty. Skipping IOC_Parser.py and Qradar-Refrenceset-Add.py."
fi
