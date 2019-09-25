import json
with open('resources/messages.json') as data_file:
    data_item = json.load(data_file)
cod="12"

print(data_item[cod][0]['message'])
print(data_item[cod][0]['color'])


