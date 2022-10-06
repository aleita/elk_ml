#!/usr/bin/env python3.6

import matplotlib.pyplot as plt
import numpy as np
import pandas
from elasticsearch import Elasticsearch
from ssl import create_default_context
import json
import zat
from zat.log_to_dataframe import LogToDataFrame
from zat.dataframe_to_matrix import DataFrameToMatrix
import sklearn
from sklearn.ensemble import IsolationForest
from sklearn.decomposition import PCA
from sklearn.cluster import KMeans
import sys
from socket import socket
import time


# Process hits here
def process_hits(hits):
    for item in hits:
        print(json.dumps(item, indent=2))


#a = int(sys.argv[1])

def sendData(lines):

  sock = socket()
  try:
    sock.connect( (CARBON_SERVER,CARBON_PORT) )
  except:
    print("Couldn't connect to %(server)s on port %(port)d, is carbon-agent.py running?") % { 'server':CARBON_SERVER, 'port':CARBON_PORT }
    sys.exit(1)

  message = '\n'.join(lines) + '\n' #all lines must end in a newline
  #for g in lines: print g
  print(message)
  #sys.exit(0)
  sock.sendall(message.encode())

CARBON_SERVER = '90.147.169.209'
CARBON_PORT = 2003
now = int( time.time() )

context = create_default_context(cafile="/etc/filebeat/elasticsearch-ca.pem")
es = Elasticsearch(['elk-01.recas.ba.infn.it'],
                http_auth=('ai_ml', 'peFqi5-cisnyp-dencek'), 
                scheme="https", 
                port=9200, 
                ssl_context=context,)
                
#es = Elasticsearch(['172.20.0.148:9200'],http_auth=('elastic', '3last1cR3CaS'))
fields = {}


#body = {"_source": ["@timestamp", "source.address", "destination.port", 'destination.ip', 'zeek.connection.history', 'zeek.connection.state', "source.packets", "source.bytes"], "size": 10000, "sort": [{"@timestamp": {"order": "desc"}}], "query": {"bool": { "must": [{"match" : {"fileset.name": "connection"}},{"match" : {"source.ip": "90.147.170.139"}}],"filter": [{"range": {"@timestamp": {"gte": "now-20d"}}}]}}}
#body = {"size": 10000, "sort": [{"@timestamp": {"order": "desc"}}], "query": {"bool": { "must": [{"match" : {"fileset.name": "connection"},"match" : {"network.direction": "inbound"},"match" : {"network.transport": "tcp"}},],"filter": [{"range": {"@timestamp": {"gte": "now-5m"}}}]}}}
#body = {"size": 1000, "sort": [{"@timestamp": {"order": "desc"}}], "query": {"bool": { "must": [{"match" : {"fileset.name": "connection"},"match" : {"network.direction": "inbound"},"match" : {"network.transport": "tcp"}},],"filter": [{"range": {"@timestamp": {"gte": "now-1m"}}}]}}}

body = { "_source":["@timestamp", 
                    "source.address", 
                    "destination.port", 
                    'destination.ip', 
                    'zeek.connection.history', 
                    'zeek.connection.state', 
                    "source.packets", 
                    "source.bytes"],
                    
         "size": 10000, "sort": [{"@timestamp": {"order": "desc"}}],
         "query": 
           {"bool": 
              { "must": 
                [{"match" : {"fileset.name": "connection"}}, 
                 #{"match" : {"destination.ip": "90.147.170.3"}}, 
                 {"match" : {"network.direction": "inbound"}}, 
                 {"match" : {"network.transport": "tcp"}},
                 #{"range": {"destination.bytes": {"gte": 1}}}
                ],
              "filter": [{"range": {"@timestamp": {"gte": "now-5m"}}}]}}
       }

#body = {"_source": ["@timestamp", "source.address", "destination.port", 'destination.ip', 'zeek.connection.history', 'zeek.connection.state', "source.packets", "source.bytes"], "size": 1000, "sort": [{"@timestamp": {"order": "desc"}}], "query": {"bool": { "must": [{"match" : {"fileset.name": "connection"}}, {"match" : {"destination.ip": "90.147.170.3"}}, {"match" : {"network.direction": "inbound"}}, {"match" : {"network.transport": "tcp"}}],"filter": [{"range": {"@timestamp": {"gte": "now-60m"}}}]}}}



es_docs = []
for number in range(1):
  response = es.search(index='zeek', scroll='1m', body=body, request_timeout=600)
  #response = es.search(index='zeek',body={"_source": ["@timestamp", "source.address", "destination.port", 'destination.ip', 'zeek.connection.history', 'zeek.connection.state', "source.packets", "source.bytes"], "query": {"bool": {"must": [{"match" : {"fileset.name": "connection"}},{"match" : {"network.direction": "inbound"}},{"match" : {"network.transport": "tcp"}}]}},"sort" : [ { "@timestamp" : { "order" : "desc"}} ]},size=a,request_timeout=60)
  #response = es.search(index='zeek',body={"_source": ["source.bytes", "destination.bytes"], "query": {"bool": {"must": [{"match" : {"fileset.name": "connection"}},{"match" : {"network.direction": "inbound"}},{"match" : {"network.transport": "tcp"}}]}}},size=1000,request_timeout=60)
  #response = es.search(index='filebeat',body={"query": {"match" : {"gpfs": True}},"sort": [{"@timestamp": {"order": "desc"}}]},size=1000,request_timeout=600)
  #print(response['hits']['hits'])
  print("total docs:", len(response["hits"]["hits"]))
  #print(response["hits"]["hits"])
  scroll_size = len(response['hits']['hits'])
  scroll_id = response['_scroll_id']
  sid = response['_scroll_id']
 
  print(scroll_size)
  print(scroll_id)
  while scroll_size > 0:
    "Scrolling..."
    
    # Before scroll, process current batch of hits
    #process_hits(response['hits']['hits'])
    
    data = es.scroll(scroll_id=sid, scroll='2m', request_timeout=600)

    # Update the scroll ID
    sid = data['_scroll_id']

    # Get the number of results that returned in the last scroll
    scroll_size = len(data['hits']['hits'])
    print(scroll_size)

    es_docs = es_docs + data['hits']['hits']
  print(len(es_docs))
  print(type(es_docs))

a = []
for i in range(len(es_docs)):
  #print(es_docs[i]['_source'])
  a.append(es_docs[i]['_source'])
#sys.exit(0)
#print(a[0])
#features = ['_source.source.address', '_source.destination.port', '_source.destination.ip', '_source.zeek.connection.history', '_source.zeek.connection.state', '_source.source.packets', '_source.source.bytes']
#features = ['source.address', 'destination.port', 'destination.ip', 'zeek.connection.history', 'zeek.connection.state', 'source.packets', 'source.bytes']
features = ['source.address', 'destination.ip', 'destination.port', 'zeek.connection.history', 'zeek.connection.state']
print("DEBUG")
es_df = pandas.io.json.json_normalize(es_docs).dropna()
print(es_df.size)
print(es_df.shape)


#features = ['_source.destination.port', '_source.destination.ip', '_source.zeek.connection.history', '_source.zeek.connection.state',  '_source.source.port', '_source.source.ip']
pandas.set_option('display.max_rows', es_df.shape[0]+1)
#print(es_df[features])
#print(es_df[features])
#print(es_docs)
#print(es_df[features])
#print(dir(DataFrameToMatrix.fit_transform))
to_matrix = DataFrameToMatrix()
zeek_matrix = to_matrix.fit_transform(es_df[features], normalize=True)
print(zeek_matrix.shape)
#zeek_matrix[:1]
#print(str(zeek_matrix.size))
print(type(zeek_matrix))
#print(zeek_matrix[:1])

#sys.exit(0)

odd_clf = IsolationForest(contamination='auto', verbose=1, n_estimators=200) # Marking 25% odd
#odd_clf = IsolationForest(verbose=1) # Marking 25% odd
#odd_clf.fit(es_df[features])
odd_clf.fit(zeek_matrix)
#print("DEBUG")
#print(odd_clf.predict(zeek_matrix))
#print(dir(odd_clf.predict(zeek_matrix)))

#Outliers: Predict if a particular sample is an outlier or not.
odd_df = es_df[features][odd_clf.predict(zeek_matrix) == -1]
print(odd_df.size)
print(odd_df.shape)

lines = []
lines.append("ai.zeek.connection.ad.odd %s %d" % ((odd_df.shape[0]/es_df.shape[0]), now))
print(lines)
print(odd_df.shape[0]/es_df.shape[0])
sendData(lines)
#sys.exit(0)
odd_df.head()
#print(type(odd_df))

odd_matrix = to_matrix.fit_transform(odd_df)
print("DEBUG1")
#print(type(odd_matrix))

# Just some simple stuff for this example, KMeans and PCA
kmeans = KMeans(n_clusters=3).fit_predict(odd_matrix)  # Change this to 3/5 for fun
pca = PCA(n_components=5).fit_transform(odd_matrix)
# Now we can put our ML results back onto our dataframe!
odd_df['x'] = pca[:, 0] # PCA X Column
odd_df['y'] = pca[:, 1] # PCA Y Column
odd_df['cluster'] = kmeans
odd_df.head()

plt.title("IsolationForest")

plt.rcParams['font.size'] = 14.0
plt.rcParams['figure.figsize'] = 15.0, 6.0

# Helper method for scatter/beeswarm plot
def jitter(arr):
    stdev = .02*(max(arr)-min(arr))
    return arr + np.random.randn(len(arr)) * stdev
# Jitter so we can see instances that are projected coincident in 2D
odd_df['jx'] = jitter(odd_df['x'])
odd_df['jy'] = jitter(odd_df['y'])

# Now use dataframe group by cluster
cluster_groups = odd_df.groupby('cluster')
print("DEBUG2")
#print(type(cluster_groups))
#print(dir(cluster_groups))


#sys.exit(0)

# Plot the Machine Learning results
colors = {0:'green', 1:'blue', 2:'red', 3:'orange', 4:'purple', 5:'brown'}
fig, ax = plt.subplots()
for key, group in cluster_groups:
    #print("DEBUG3")
    #print(group['x'])
    #print(group['y'])
    group.plot(ax=ax, kind='scatter', x='jx', y='jy', alpha=0.5, s=250,
               label='Cluster: {:d}'.format(key), color=colors[key])

fig.savefig("foo_1.pdf", bbox_inches='tight')


pandas.set_option('display.width', 1000)
#for key, group in cluster_groups:
#    print('\nCluster {:d}: {:d} observations'.format(key, len(group)))
#    print(group[features].head())
#fig = a.get_figure()

# Now print out the details for each cluster
print('<<< Outliers Detected! >>>')
for key, group in cluster_groups:
    print('\nCluster {:d}: {:d} observations'.format(key, len(group)))
    print(group.head())
fig.savefig('/lustre/home/italiano/es_ml/figure.pdf')
