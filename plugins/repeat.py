import time
crontable = []
outputs = []

def process_message(data):
    print("\nIncoming: {}".format(data))
    outputs.append([data['channel'], "from repeat1 \"{}\" in channel {}".format(data['text'], data['channel']) ])
