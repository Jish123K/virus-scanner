import hashlib

import os

from base64 import urlsafe_b64encode

import httpx

class vtError(Exception):

    def __init__(self, response):

        self.resp = response

    def __str__(self):

        try:

            return f"Error {self.error().get('code')} {self.resp.status_code}\n{self.error().get('message', '')}"

        except:

            return "Unknown Error"

    def error(self):

        return self.resp.json().get("error")

class Virustotal:

    def __init__(self, api_key):

        self.api_key = api_key

    async def api_request(self, method, path=None, url=None, ip=None, hash=None):

        BASE_URL = "https://www.virustotal.com/api/v3/"

        headers = {

            "x-apikey": f"{self.api_key}"

        }

        if url is None and ip is None and path is not None:

            resource = "file"

            endpoint = BASE_URL + "files"

        elif path is None and ip is None and url is not None:

            resource = "url"

            endpoint = BASE_URL + "urls"

        elif path is None and url is None and ip is not None:

            resource = "ip"

            endpoint = BASE_URL + "ip_addresses"

        else:

            raise ValueError("No file path, url, or IP was given")

        async with httpx.AsyncClient(headers=headers) as client:

            if method == "post":

                if resource == "file":

                    path_dict = {"file": (os.path.basename(path), open(os.path.abspath(path), "rb"))}

                    if os.path.getsize(path) >= 32000000:

                        endpoint = await large_file_url(self.api_key, client)

                    try:

                        response = await client.post(endpoint, files=path_dict)

                    except:

                        raise MemoryError("Given file seems to be an archive")

                elif resource == "url":

                    response = await client.post(endpoint, data={"url": url})

                return response

            elif method == "get":

                if resource == "file":

                    if hash is None:

                        hash = sha1(path)

                    endpoint = f"{endpoint}/{hash}"

                elif resource == "url":

                    url_id = urlsafe_b64encode(url.encode()).decode().strip("=")

                    endpoint = f"{endpoint}/{url_id}"

                elif resource == "ip":

                    endpoint = f"{endpoint}/{ip}"

                response = await client.get(endpoint)

                if response.status_code != 200:

                    raise vtError(response)

                else:

                    return response.json()["data"]["attributes"]

def sha1(filename):

    hash = hashlib.sha1()

    with open(filename, "rb") as file:

        chunk = 0

        while chunk != b"":

            chunk = file.read(1024)

            hash.update(chunk)

    return hash.hexdigest()

async def large_file_url(api_key, client):

    url = "https://www.virustotal.com/api/v3/files/upload_url"

    headers = {

        "Accept": "application/json",

        "x-apikey": api_key

    }

    response = await client.get(url, headers=headers)

    return response.text[15:-3]

