import requests

# set up the request headers

headers = {"x-apikey": "API_KEY"}

# scan a file for malware

with open("PATH", "rb") as file:

    response = requests.post("https://www.virustotal.com/api/v3/files", headers=headers, files={"file": file})

    response.raise_for_status() # raise an exception if the status code is not in the 2xx range

    data = response.json()

    analysis_id = data["data"]["id"]

    

response = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers)

response.raise_for_status()

print(response.json())

# scan a domain for malware

response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, json={"url": "URL"})

response.raise_for_status()

data = response.json()

analysis_id = data["data"]["id"]

response = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers)

response.raise_for_status()

print(response.json())

# scan an ip-address for malware

response = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers=headers)

response.raise_for_status()

print(response.json())

