import elasticsearch
es_client = elasticsearch.Elasticsearch("localhost:9200")

import json
all_indicies = []
temp_second = []
access_ip_indices = (es_client.indices.get_alias())
for a in access_ip_indices.keys():
   if a[0:10]=="winlogbeat":
        all_indicies.append(a)
import datetime
all_indicies = sorted(all_indicies,key=lambda x: datetime.datetime.strptime(x,'winlogbeat-%Y.%m.%d'))

number_of_index = len(all_indicies)
print("----------------연결된 pc목록-----------------")
for a in all_indicies:
    search_first = es_client.search(
                            index=a,    
                            body= {
                            "sort": [
                                {"@timestamp":"desc"}
                            ],
                            "size": 1,
                         }
    )
    temp_second.append(search_first['hits']['hits'][0]['_source']['host']['name'])

temp_zip=zip(all_indicies,temp_second)
for a,b in temp_zip:
    print(a+'--->'+b)

print("\n------------최근 접근 시도 ip 목록--------------")
temp_forth=[]
temp_time=[]
for a in range(number_of_index):
    temp_forth.append([])
    temp_time.append([])
for index,a in zip(range(0,number_of_index), all_indicies):
    ip_search = es_client.search(
                        index=a,
                        body= {
                           "sort": [
                               {"@timestamp":"desc"}
                           ],
                                "size": 5,
                                "query": {
                                    "match_phrase": {
                                      "winlog.event_id": 3
                                    }  
                                }
                        }
     )
    for b in range(0,5):
        temp_forth[index].append(ip_search['hits']['hits'][b]['_source']['winlog']['event_data']['DestinationIp'])
        temp_time[index].append(ip_search['hits']['hits'][b]['_source']['winlog']['event_data']['UtcTime'])
for index,a in zip(range(number_of_index),all_indicies):
    print(a+'---------->',end='')
    for b in range(0,5):
        print("["+temp_time[index][b]+"] ",end='')
        print(temp_forth[index][b])
        print('\t\t\t\t',end='')
    print()

print("\n------------최근 접근 DNS 목록-------------")
temp_forth=[]
temp_time=[]
for a in range(number_of_index):
    temp_forth.append([])
    temp_time.append([])
for index,a in zip(range(0,number_of_index), all_indicies):
    ip_search = es_client.search(
                        index=a,
                        body= {
                           "sort": [
                               {"@timestamp":"desc"}
                           ],
                                "size": 10,
                                "query": {
                                    "match_phrase": {
                                      "winlog.event_id": 22
                                    }  
                                }
                        }
     )
    for b in range(0,10):
        temp_forth[index].append(ip_search['hits']['hits'][b]['_source']['winlog']['event_data']['QueryName'])
        temp_time[index].append(ip_search['hits']['hits'][b]['_source']['winlog']['event_data']['UtcTime'])

for index,a in zip(range(number_of_index),all_indicies):
    print(a+'---------->',end='')
    for b in range(0,10):
        print("["+temp_time[index][b]+"] ",end='')
        print(temp_forth[index][b])
        print('\t\t\t\t',end='')
    print()

print("\n------------내 피씨에서 가장 많이 실행한 프로그램-------------")
temp_count=[]
temp_processid=[]
temp_time=[]
temp_orginalFilename=[]
for a in range(number_of_index):
    temp_count.append([])
    temp_processid.append([])
    temp_time.append([])
    temp_orginalFilename.append([])

for index,a in zip(range(0,number_of_index), all_indicies):
    id_search = es_client.search(
                        index=a,
                        body= {
                           "sort": [
                               {"@timestamp":"desc"}
                           ],
                           "aggs": {
                             "2": {
                                "terms": {
                                    "field": "winlog.event_data.ProcessId.keyword",
                                "order": {
                                    "_count": "desc"
                                },
                                "size": 5
                                 }
                                }
                            },
                            "size": 5,
                            "query": {
                                "match_phrase": {
                                "winlog.event_id": 1
                                }  
                            }
                        }
     )
    for b in range(0,5):
        temp_orginalFilename[index].append(id_search['hits']['hits'][b]['_source']['winlog']['event_data']['OriginalFileName'])
        temp_time[index].append(id_search['hits']['hits'][b]['_source']['winlog']['event_data']['UtcTime'])
        temp_count[index].append(id_search['aggregations']['2']['buckets'][b]['doc_count'])
        temp_processid[index].append(id_search['aggregations']['2']['buckets'][b]['key'])

for index,a in zip(range(number_of_index),all_indicies):
    print(a+'---------->',end='')
    for b in range(0,5):
        print("["+temp_time[index][b]+"] "+"[ Filename: "+temp_orginalFilename[index][b]+"] "+"[ Count: ",end='') 
        print(temp_count[index][b],end='')
        print("] ",end='')
        print("[ Process ID: "+temp_processid[index][b]+"] ")
        print('\t\t\t\t',end='')
    print()       



print("\n------------내 피씨에서 가장 많이 종료가 많은 프로그램-------------")
temp_count=[]
temp_processid=[]
temp_time=[]
temp_Image=[]
for a in range(number_of_index):
    temp_count.append([])
    temp_processid.append([])
    temp_time.append([])
    temp_Image.append([])

for index,a in zip(range(0,number_of_index), all_indicies):
    id_search = es_client.search(
                        index=a,
                        body= {
                           "sort": [
                               {"@timestamp":"desc"}
                           ],
                           "aggs": {
                             "2": {
                                "terms": {
                                    "field": "winlog.event_data.ProcessId.keyword",
                                "order": {
                                    "_count": "desc"
                                },
                                "size": 5
                                 }
                                }
                            },
                            "size": 5,
                            "query": {
                                "match_phrase": {
                                "winlog.event_id": 5
                                }  
                            }
                        }
     )
    total = len(id_search['aggregations']['2']['buckets'])
    for b in range(0,total):
        temp_Image[index].append(id_search['hits']['hits'][b]['_source']['winlog']['event_data']['Image'])
        temp_time[index].append(id_search['hits']['hits'][b]['_source']['winlog']['event_data']['UtcTime'])
        temp_count[index].append(id_search['aggregations']['2']['buckets'][b]['doc_count'])
        temp_processid[index].append(id_search['aggregations']['2']['buckets'][b]['key'])

for index,a in zip(range(number_of_index),all_indicies):
    print(a+'---------->',end='')
    for b in range(0,total):
        print("["+temp_time[index][b]+"] "+"[ Image: "+temp_Image[index][b]+"] "+"[ Count: ",end='') 
        print(temp_count[index][b],end='')
        print("] ",end='')
        print("[ Process ID: "+temp_processid[index][b]+"] ")
        print('\t\t\t\t',end='')
    print()       


print("\n------------의심스러운 해시 목록-------------")

import requests
import time

def Response_of_Hash(hashcode) :
    hash_code=hashcode[0][0]
    api_key = 'fedb7fd9a4420ae7f9b0cabdddcdb04b69e9c3561b84420dc55874d040ee0d76'
    REPORT_URL = 'https://www.virustotal.com/vtapi/v2/file/report' 
    parameters = {'apikey': api_key,'resource': hash_code }
    response = requests.get(REPORT_URL,params=parameters)
    return (response.json())

temp_count=[]
temp_processid=[]
temp_time=[]
temp_orginalFilename=[]
temp_hash=[]
hashcode=[]
for a in range(number_of_index):
    temp_count.append([])
    temp_processid.append([])
    temp_time.append([])
    temp_orginalFilename.append([])
    temp_hash.append([])
    hashcode.append([])

for index,a in zip(range(0,number_of_index), all_indicies):
    id_search = es_client.search(
                        index=a,
                        body= {
                           "sort": [
                               {"@timestamp":"desc"}
                           ],
                           "aggs": {
                             "2": {
                                "terms": {
                                    "field": "winlog.event_data.ProcessId.keyword",
                                "order": {
                                    "_count": "desc"
                                },
                                "size": 5
                                 }
                                }
                            },
                            "size": 5,
                            "query": {
                                "match_phrase": {
                                "winlog.event_id": 1
                                }  
                            }
                        }
     )
    for b in range(0,5):
        temp_orginalFilename[index].append(id_search['hits']['hits'][b]['_source']['winlog']['event_data']['OriginalFileName'])
        temp_time[index].append(id_search['hits']['hits'][b]['_source']['winlog']['event_data']['UtcTime'])
        temp_count[index].append(id_search['aggregations']['2']['buckets'][b]['doc_count'])
        temp_processid[index].append(id_search['aggregations']['2']['buckets'][b]['key'])
        temp_hash[index].append(id_search['hits']['hits'][b]['_source']['winlog']['event_data']['Hashes'])
        hashcode[index].append(temp_hash[index][b][4:temp_hash[index][b].find(',')])



data = json.loads(json.dumps(Response_of_Hash(hashcode)))
scan = data.get('scans', {})

print(scan)

print(json.dumps(Response_of_Hash(hashcode),indent=3))



# for index,a in zip(range(number_of_index),all_indicies):
#     print(a+'---------->',end='')
#     for b in range(0,5):
#         print("["+temp_time[index][b]+"] "+"[ Filename: "+temp_orginalFilename[index][b]+"] "+"[ Count: ",end='') 
#         print(temp_count[index][b],end='')
#         print("] ",end='')
#         print("[ Process ID: "+temp_processid[index][b]+"] ")
#         print("\t\t\t\t\t\t\t  [ Hash: "+temp_hash[index][b]+"] ")
#         print('\t\t\t\t',end='')
#     print()       
