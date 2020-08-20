import requests

def Response_of_Hash(hashcode) :
    api_key = 'fedb7fd9a4420ae7f9b0cabdddcdb04b69e9c3561b84420dc55874d040ee0d76'
    REPORT_URL = 'https://www.virustotal.com/vtapi/v2/file/report' 
    parameters = {'apikey': api_key,'resource': hashcode }
    response = requests.get(REPORT_URL,params=parameters)

    data = response.json()
    scan = data.get("scans", {})
    return scan