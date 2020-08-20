import viroustotal_API as Check_Hash
import OpenWhiteList as openWhitelist
import elasticsearch
es_client = elasticsearch.Elasticsearch("localhost:9200")

import json
all_indicies = []
access_ip_indices = (es_client.indices.get_alias())
for a in access_ip_indices.keys():
   if a[0:10]=="winlogbeat":
        all_indicies.append(a)
import datetime
all_indicies = sorted(all_indicies,key=lambda x: datetime.datetime.strptime(x,'winlogbeat-%Y.%m.%d'))

number_of_index = len(all_indicies)

def find_host_name(indice):
        search_first = es_client.search(
                            index=indice,    
                            body= {
                            "sort": [
                                {"@timestamp":"desc"}
                            ],
                            "size": 1,
                         }
        )      
        host_name = search_first['hits']['hits'][0]['_source']['host']['name']
        return host_name

def find_dns(indice):
        dns = []
        time = []
        DNS = []
        search_second = es_client.search(
                        index=indice,
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
        total = len(search_second['hits']['hits'])
        for b in range(0,total):
                dns.append(search_second['hits']['hits'][b]['_source']['winlog']['event_data']['QueryName'])
                time.append(search_second['hits']['hits'][b]['_source']['winlog']['event_data']['UtcTime'])
                DNS.append(" ["+time[b]+"] "+dns[b])
        return DNS


def find_IP(indice):
        ip = []
        time = []
        IP = []
        search_third = es_client.search(
                        index=indice,
                        body= {
                           "sort": [
                               {"@timestamp":"desc"}
                           ],
                                "size": 10,
                                "query": {
                                    "match_phrase": {
                                      "winlog.event_id": 3
                                    }  
                                }
                        }
        )
        total = len(search_third['hits']['hits'])
        for b in range(0,total):
                ip.append(search_third['hits']['hits'][b]['_source']['winlog']['event_data']['DestinationIp'])
                time.append(search_third['hits']['hits'][b]['_source']['winlog']['event_data']['UtcTime'])
                IP.append(" ["+time[b]+"] "+ip[b])
        return IP

def find_access_time(indice):
        search_forth = es_client.search(
                index = indice,
                body={
                        "sort": [
                                {
                                        "@timestamp":"asc"
                                }
                        ],
                        "size": 1
                }
        )
        search_fifth = es_client.search(
                index = indice,
                body={
                        "sort": [
                                {
                                        "@timestamp":"desc"
                                }
                        ],
                        "size": 1
                }
        )
        return_value = (
                " ["
                +search_forth['hits']['hits'][0]['_source']['winlog']['event_data']['UtcTime']
                +"]"
                +" ~ "
                +"["
                +search_fifth['hits']['hits'][0]['_source']['winlog']['event_data']['UtcTime']
                +"]"
                )
        
        return return_value

def find_most_running_process(indice):
        count=[]
        processid=[]
        time=[]
        orginalFilename=[]
        return_value=[]
        search_sixth = es_client.search(
                        index=indice,
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
                orginalFilename.append(search_sixth['hits']['hits'][b]['_source']['winlog']['event_data']['OriginalFileName'])
                time.append(search_sixth['hits']['hits'][b]['_source']['winlog']['event_data']['UtcTime'])
                count.append(search_sixth['aggregations']['2']['buckets'][b]['doc_count'])
                processid.append(search_sixth['aggregations']['2']['buckets'][b]['key'])
        
        for b in range(0,5):
                return_value.append(
                       " ["
                        +time[b]
                        +"] "
                        +"[ Count: "
                        +str(count[b])
                        +"] "
                        +"[ ProcessS_ID: "
                        +processid[b]
                        +"] "
                        +"[ FileName: "
                        +orginalFilename[b]
                        +"]"
                )
        
        return return_value


def find_most_closing_process(indice):
        count=[]
        processid=[]
        time=[]
        Image=[]
        return_value=[]
        search_sixth = es_client.search(
                        index=indice,
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
        total = len(search_sixth['aggregations']['2']['buckets'])
        for b in range(0,total):
                Image.append(search_sixth['hits']['hits'][b]['_source']['winlog']['event_data']['Image'])
                time.append(search_sixth['hits']['hits'][b]['_source']['winlog']['event_data']['UtcTime'])
                count.append(search_sixth['aggregations']['2']['buckets'][b]['doc_count'])
                processid.append(search_sixth['aggregations']['2']['buckets'][b]['key'])
        
        for b in range(0,total):
                return_value.append(
                       " ["
                        +time[b]
                        +"] "
                        +"[ Count: "
                        +str(count[b])
                        +"] "
                        +"[ ProcessS_ID: "
                        +processid[b]
                        +"] "
                        +"[ Image: "
                        +Image[b]
                        +"]"
                )
        
        return return_value


def find_last_100_logs(indice):
        event_id=[]
        event_action=[]
        event_data_processid=[]
        time=[]
        Image=[]
        return_value=[]
        search_seventh = es_client.search(
                        index=indice,
                        body= {
                           "sort": [
                               {"@timestamp":"desc"}
                           ],
                            "size": 300
                        }
        )
        total = len(search_seventh['hits']['hits'])
        for b in range(0,total):
                time.append(search_seventh['hits']['hits'][b]['_source']['winlog']['event_data']['UtcTime'])
                event_id.append(search_seventh['hits']['hits'][b]['_source']['winlog']['event_id'])
                event_action.append(search_seventh['hits']['hits'][b]['_source']['event']['action'])
                if event_id[b] == 8 | event_id[b] == 6:
                        event_data_processid.append("Default")
                        Image.append("Default")
                else:
                        event_data_processid.append(search_seventh['hits']['hits'][b]['_source']['winlog']['event_data']['ProcessId'])
                        Image.append(search_seventh['hits']['hits'][b]['_source']['winlog']['event_data']['Image'])
                
        
        for b in range(0,total):
                return_value.append(
                       " ["
                        +time[b]
                        +"] "
                        +"[ EventID: "
                        +str(event_id[b])
                        +"]"
                        +": "
                        +event_action[b]
                        +"\n"
                        +"\t                     [ ProcessID: "
                        +event_data_processid[b]
                        +"] \n"
                        +"\t                     [ Image: "
                        +Image[b]
                        +"]"
                )
        
        return return_value

def find_count_of_each_event_id(indice):
        event_count=[]
        event_id=[]
        return_value=[]
        search_eighth = es_client.search(
                        index=indice,
                        body= {
                                "sort": [
                               {"@timestamp":"desc"}
                           ],
                        "aggs": {
                                    "2": {
                                        "terms": {
                                                "field": "winlog.event_id",
                                                "order": {
                                                                "_count": "desc"
                                                         },
                                                "size": 23
                                                }
                                        }
                                },
                        "size": 0
                        }
        )
        total = len(search_eighth['aggregations']['2']['buckets'])
        for b in range(0,total):
                event_id.append(search_eighth['aggregations']['2']['buckets'][b]['key'])
                event_count.append(search_eighth['aggregations']['2']['buckets'][b]['doc_count'])     
        return_value.append(str(search_eighth['hits']['total']['value']))

        for b in range(0,total):
                return_value.append(
                        "[ EventID: "
                        +str(event_id[b])
                        +"] \t--->  "
                        +" [ Count: "
                        +str(event_count[b])
                        +"]"
                )
        
        return return_value

def find_PS_With_Hash_table_list(indice):
        Hash = []
        table=[]
        search_ninth= es_client.search(
                        index = indice,
                        body = {
                                "aggs": {
                                        "2": {
                                               "terms": {
                                                        "field": "winlog.event_data.Hashes.keyword" ,
                                                        "size": 400
                                                }
                                        }
                                },
                                "size": 0
                        }
                        
        )
        total = len(search_ninth['aggregations']['2']['buckets'])
        for index in range(0,total):
                table.append([])
                Hash.append( search_ninth['aggregations']['2']['buckets'][index]['key'])

        for index in range(0,total):
                search_tenth= es_client.search(
                        index= indice,
                        body={
                                "query": {
                                "match_phrase": {
                                        "winlog.event_data.Hashes": Hash[index]
                                        }
                                },
                                "size":1
                        }

                )
                table[index].append(Hash[index][4:Hash[index].find(',')]) 
                if search_tenth['hits']['hits'][0]['_source']['event']['code']!=6:
                        table[index].append(search_tenth['hits']['hits'][0]['_source']['winlog']['event_data']['OriginalFileName'])
                else:
                        table[index].append(search_tenth['hits']['hits'][0]['_source']['winlog']['event_data']['Signature'])
                        
        return table

def find_booting_start_time(indice):
    boot_start_time_table=[]
    search_eleventh = es_client.search(
        index=indice,
        body={
            "sort": [
                {"@timestamp": "desc"}
            ],
              "query": {
                "match_phrase": {
                  "winlog.event_id": 4
                }
              },
            "size": 300
        }

    )
    total = len(search_eleventh['hits']['hits'])
    for f in range(0,total):
        boot_start_time_table.append(search_eleventh['hits']['hits'][f]['_source']['winlog']['event_data']['UtcTime'])

    return boot_start_time_table

def find_booting_end_time(indice):
    boot_end_time_table=[]
    search_tweleventh = es_client.search(
        index=indice,
        body={
            "sort": [
                {"@timestamp": "desc"}
            ],
            "query": {
                "match_phrase": {
                  "winlog.event_data.OriginalFileName": "CALC.EXE"
                }
              },
            "size": 300
        }

    )
    total = len(search_tweleventh['hits']['hits'])
    for f in range(total):
        boot_end_time_table.append(search_tweleventh['hits']['hits'][f]['_source']['winlog']['event_data']['UtcTime'])
    return boot_end_time_table