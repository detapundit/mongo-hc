from pymongo import MongoClient
from json2html import json2html
from datetime import timedelta


# Replace with your MongoDB connection string
uri = "mongodb://34.201.41.73:27017/?authSource=admin"  # Default URI for local MongoDB
client = MongoClient(uri)

# Connect to a database (if it doesn't exist, it will be created)
db = client["admin"]

# Host info and stats retrieval
host_info = client.admin.command('hostInfo')

# Extract the hostname from the response
hostname = host_info['system']['hostname']
print(hostname)

# Stats for the sampledb database
db1 = client["sampledb"]
stats = db1.command('dbstats')
filtered_stats = {key: stats[key] for key in ['db', 'collection', 'dataSize', 'storageSize', 'indexes', 'indexSize', 'totalSize'] if key in stats}

#print(converted_stats)
print(filtered_stats)

# Server status retrieval
server_status = db.command('serverStatus')
filtered_status = {
    "host": server_status.get("host"),
    "version": server_status.get("version"),
    "uptime": str(timedelta(seconds=server_status.get("uptime"))),
    "connections": server_status.get("connections"),
    "catalogStats": server_status.get("catalogStats"),
    "featureCompatibilityVersion": server_status.get("featureCompatibilityVersion"),
    "globalLock": server_status.get("globalLock"),
    "indexStats": server_status.get("indexStats"),
    "opcounters": server_status.get("opcounters"),
    "concurrentTransactions": {
        "writeAvailable": server_status.get("wiredTiger", {}).get("concurrentTransactions", {}).get("write", {}).get("available"),
        "readAvailable": server_status.get("wiredTiger", {}).get("concurrentTransactions", {}).get("read", {}).get("available"),
    }
}

print(filtered_status)

# Function to convert dictionary to visually appealing HTML table
def dict_to_html_table(data):
    html = '''
    <style>
        table {
            width: 100%;
            border-collapse: collapse;
        }
        table, th, td {
            border: 1px solid #ddd;
        }
        th, td {
            padding: 10px;
            text-align: left;
        }
        tr:nth-child(odd) {
            background-color: #f9f9f9;
        }
        tr:nth-child(even) {
            background-color: #f2f2f2;
        }
        th {
            background-color: #4CAF50;
            color: white;
        }
        td {
            background-color: #fafafa;
        }
        h2 {
            color: #333;
        }
        .container {
            width: 80%;
            margin: auto;
            font-family: Arial, sans-serif;
        }
        .title {
            text-align: center;
            color: #333;
        }
    </style>
    <div class="container">
        <h2 class="title">MongoDB Status & Statistics</h2>
        <table>
            <tr><th>Key</th><th>Value</th></tr>'''

    for key, value in data.items():
        if isinstance(value, dict):  # Handle nested dictionaries
            html += f'<tr><td colspan="2"><strong>{key}</strong></td></tr>'
            for sub_key, sub_value in value.items():
                html += f'<tr><td>{sub_key}</td><td>{sub_value}</td></tr>'
        else:
            html += f'<tr><td>{key}</td><td>{value}</td></tr>'

    html += '</table></div>'
    return html

# Convert both filtered data to HTML tables
html_output1 = dict_to_html_table(filtered_status)
html_output2 = dict_to_html_table(filtered_stats)

# Combine both HTML tables and print or save to file
final_html = html_output1 + "<hr>" + html_output2

# Print the final HTML content
print(final_html)

# Optionally, save to an HTML file
with open('server_status.html', 'w') as file:
    file.write(final_html)

# Close the connection (optional, as it gets closed automatically at the end of the script)
client.close()
