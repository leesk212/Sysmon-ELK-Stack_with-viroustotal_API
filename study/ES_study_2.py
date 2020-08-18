import elasticsearch
es_client = elasticsearch.Elasticsearch("localhost:9200")
#doc = es_client.get(index = 'bank', doc_type = 'account', id = '100')
#winlog = es_client.get(index = 'winlogbeat-2020.08.03',id='GU_osnMBd9ZeySJiEInA')
#print(winlog)

import json
#print(json.dumps(winlog,indent=2))
#a = doc['_source']['email']
#print(a)

#print(es_client.ping())
#print(es_client.mget(index='bank',body={'ids':['100','101']}))
#doc_2 = es_client.mget(index='winlogbeat-2020.08.03',body={'ids':['GU_osnMBd9ZeySJiEInA','F0_osnMBd9ZeySJiA4mZ']})


#print(json.dumps(doc_2,indent=2))

# 1. 연결된 pc목록 (윈로그비트로 엘라스틱에 연결된 정보, 예를들면 hostname 은 pc마다 유니크 한 값(하드웨어아이디))
# 2. 프로세스 정보
# 3. 로그인 정보
# 4. 내 피씨에서 가장 많이 실행한 프로그램 (event id 1)
# 5. 내 피씨에서 오류가 가장 많이 나는 프로그램 (종료되었습니다)
# 6. 의심스러운 프로세스 목록(sysmon proc hash)
# 7. 부팅할때 생성되는 로그 (깨끗한 피씨) (화이트 리스트 관리용)
# 8. 7번 과 상이한 프로세스 목록 (ㅇㅇㅇㅇㅇ)(우리가 잘 모르는 프로세스, 확인해야 하는 프로그램)
# 9. 8번 프로세스 hash 로, virustotal 연동
# 10. hwid 2개를 입력받고, 두 pc에서 상이한 프로세스 목록 출력




#print(winlog['_source']['winlog']['computer_name']) #1번 구현 완료



# doc_3 = es_client.search(
#                         index="winlogbeat-2020.08.05",    
#                         body= {
#                             "from": 1,
#                             "size": 2,
#                             "query":{
#                                 "terms":{
#                                     "_id": ["y4hjvHMB4lRCKc53JtRN"],
#                                     "winlog.event_id": [22]
#                                 }
#                             }
#                          },

#                     )
# print(json.dumps(doc_3,indent=2))
# print(
#     json.dumps(
#        doc_3['hits']['hits'][0]['_source']['host']['name']
#     ,indent=2)
# )
# print(
#     json.dumps(
#        doc_3['hits']['hits'][1]['_source']['host']['name']
#     ,indent=2)
# )

#hostname 할당 가능

# doc_3 = es_client.search(
#                         index="winlogbeat-2020.08.05",    
#                         body= {
#                                 "aggs":{
#                                     "first":{
#                                         "terms":{
#                                             "field": "winlog.event_id"
#                                         }
#                                     }
#                                 }
#                             }
#                     )
# print(json.dumps(doc_3,indent=2))

# doc_3 = es_client.search(
# #                        index="winlogbeat-2020.08.05",    
#                         body= {
#                            "sort": [
#                                {"@timestamp":"desc"}
#                            ],
# ##가장 최근에 들어온 데이터 뽑기 기능
# #                                  "aggs": {
# #     "2": {
# #       "date_histogram": {
# #         "field": "@timestamp",
# #         "fixed_interval": "5m",
# #         "time_zone": "Asia/Seoul",
# #         "min_doc_count": 1
# #       }
# #     }
# #   },
# ##칸씩 나눠서 갯수를 표현하고 싶을 때 쓰는 aggs
#                                 # "docvalue_fields": [
#                                 #   {
#                                 #       "field": "agent.hostname"
#                                 #    },
#                                 #     {
#                                 #         "field": "event.created",
#                                 #         "format": "date_time"
#                                 #      },
#                                 # ],
# ##내가 찾던 기능 필요한 곳만 Field를 통해 출력해줌
#                                 # "_source": {
#                                 #     "excludes": ["_id","_index"]
#                                 # },
#                                 "size": 4,
# ##뽑는 갯수 출력
#                                 "query": {
#                                     "match_phrase": {
#                                       "winlog.event_id": 3
#                                     }  
#                                 }
#                         }
#                     )
#print(json.dumps(doc_3,indent=2))
#print(
#    json.dumps(
#       doc_3['hits']['hits'][0]['_source']['winlog']['event_data']['DestinationIp']
#    ,indent=2)
#)
# print(doc_3['hits']['hits'][0]['_id'])
# print(
#     json.dumps(
#        doc_3['hits']['hits'][1]['_source']['host']['name']
#     ,indent=2)
# )
# print(doc_3['hits']['hits'][1]['_id'])


#access_ip_indices = list(es_client.indices.get_alias().keys())
#access_ip_indices = es_client.cat.indices()
#from pprint import pprint as pp

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
    for b in range(0,5):
        temp_Image[index].append(id_search['hits']['hits'][b]['_source']['winlog']['event_data']['Image'])
        temp_time[index].append(id_search['hits']['hits'][b]['_source']['winlog']['event_data']['UtcTime'])
        temp_count[index].append(id_search['aggregations']['2']['buckets'][b]['doc_count'])
        temp_processid[index].append(id_search['aggregations']['2']['buckets'][b]['key'])

for index,a in zip(range(number_of_index),all_indicies):
    print(a+'---------->',end='')
    for b in range(0,5):
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



for index,a in zip(range(number_of_index),all_indicies):
    print(a+'---------->',end='')
    for b in range(0,5):
        print("["+temp_time[index][b]+"] "+"[ Filename: "+temp_orginalFilename[index][b]+"] "+"[ Count: ",end='') 
        print(temp_count[index][b],end='')
        print("] ",end='')
        print("[ Process ID: "+temp_processid[index][b]+"] ")
        print("\t\t\t\t\t\t\t  [ Hash: "+temp_hash[index][b]+"] ")
        print('\t\t\t\t',end='')
    print()       





# # -*- coding: utf-8 -*-  
# import urllib  
# import urllib2  
# import json  
# import time  
# #모듈선언 
# VT_KEY     = ''  
# #바이러스토탈 api키, 가입 후 제공받을 수 있음 1분에 4개 제한 
# HOST       = 'www.virustotal.com'  
# SCAN_URL   = 'https://www.virustotal.com/vtapi/v2/file/scan'  
# REPORT_URL = 'https://www.virustotal.com/vtapi/v2/file/report'  
# md5str= ''  
# #md5 값 담을 변수 선언 

# fields = [('apikey', VT_KEY)]  
# #전달할 apikey 값 담기 
# txtf = open('test.txt', 'r')  
# #test.txt에 md5값을 담아두고 'r'  read함  

# while True:  
# #while문으로 반복돌림 
#         line = txtf.readline()  
#         md5str = line.strip('\n')  
# #한 줄 씩 읽음. 개행으로 구분함 
#         if not md5str: break  
#         parameters = {'resource': md5str, 'apikey': VT_KEY}  
#         data = urllib.urlencode(parameters)  
#         req = urllib2.Request(REPORT_URL, data)  
#         response = urllib2.urlopen(req)  
#         data = response.read()  

#         data = json.loads(data)  
# #데이터를 json형태로 읽어서 data변수에 담음. 
#         md5 = data.get('md5', {})  
#         scan = data.get('scans', {})  
# #바이러스토탈에서 응답값 던져줄 때 내가 필요한  md5값과 scan결과 값 파싱 
#         keys = scan.keys()  
# #keys는 바이러스토탈에서 지원하는 백신엔진 목록 
#         print (" ")  
#         print ("==========================Virus Total Loading==========================")  
#         print ("=========================================================================")  
# #바이러스 토탈이 지원하는 백신 중 하나도 탐지되는게 없으면 '{}'값이 md5에 들어감. 그러므로 "no match"출력 
#         if md5 == {}: 
#            print (" !!!!!!!!! Sorry, No Match !!!!!!!!! ") 
#         else: 
#            print md5 
                     
#         print ("==========================================================================")  
#         time.sleep(20)  
# #1분에 4개로 제한되어 있어, 20초씩 sleep시켜줌. 
#         for key in keys :  

#                 if key == 'AhnLab-V3':  
#                     print '%-20s : %s' % (key, scan[key]['result'])  
#                 elif key == 'ALYac':  
#                     print '%-20s : %s' % (key, scan[key]['result'])  
#                 elif key == 'nProtect':  
#                     print '%-20s : %s' % (key, scan[key]['result'])  
#                 elif key == 'ViRobot':  
#                     print '%-20s : %s' % (key, scan[key]['result'])  
# txtf.close()  
# print("+++++++++++++++++++++++++++clear+++++++++++++++++++++++++++")
# [출처] 파이썬 - 바이러스토탈(Virustotal) API 사용하여 질의 하기|작성자 주호
