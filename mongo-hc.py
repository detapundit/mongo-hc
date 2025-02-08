from pymongo import MongoClient
from json2html import json2html


# Replace with your MongoDB connection string
uri = "mongodb://root:password@localhost:27017/?authSource=admin"  # Default URI for local MongoDB
client = MongoClient(uri)

# Connect to a database (if it doesn't exist, it will be created)
db = client["admin"]

# Connect to a collection in the database (if it doesn't exist, it will be created)
#collection = db["samplecoll"]

# Example: Insert a document
# document = {"name": "Alice", "age": 25}
# collection.insert_one(document)

# Example: Find a document
#result = collection.find_one({"name": "Alice"})
#print(result)
db1 = client["sampledb"]
stats = db1.command('dbstats')
filtered_stats = {key: stats[key] for key in ['db','collection','dataSize','storageSize','indexes','indexSize','totalSize'] if key in stats}
print(filtered_stats)

status = db.command('serverStatus')
filtered_status = {key: status[key] for key in ['version', 'uptime','connections','catalogStats','opcounters','globalLock','queues'] if key in status}
print(filtered_status)

def dict_to_html_table(data):
    html = '<table border="1" cellpadding="5" cellspacing="0">'
    html += '<tr><th>Key</th><th>Value</th></tr>'

    for key, value in data.items():
        if isinstance(value, dict):  # Handle nested dictionary (like 'connections')
            html += f'<tr><td colspan="2"><strong>{key}</strong></td></tr>'
            for sub_key, sub_value in value.items():
                html += f'<tr><td>{sub_key}</td><td>{sub_value}</td></tr>'
        else:
            html += f'<tr><td>{key}</td><td>{value}</td></tr>'

    html += '</table>'
    return html

# Example: Convert the server status to HTML table
html_output1 = dict_to_html_table(filtered_status)
html_output2 = dict_to_html_table(filtered_stats)

# Print or save the HTML table
print(html_output1)
print(html_output2)
# json2html

# Convert the dictionary to HTML using json2html
html_output1 = json2html.convert(json=filtered_status)

# Print the HTML table
print(html_output1)

# Optionally, save to an HTML file
with open('server_status.html', 'w') as file:
    file.write(html_output1)


# Close the connection (optional, as it gets closed automatically at the end of the script)
client.close()
