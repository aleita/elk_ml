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


# Process hits here
def process_hits(hits):
    for item in hits:
        print(json.dumps(item, indent=2))


a = int(sys.argv[1])

context = create_default_context(cafile="/etc/filebeat/elasticsearch-ca.pem")
es = Elasticsearch(['elk-01.recas.ba.infn.it'],http_auth=('elastic', '3last1cR3CaS'), scheme="https", port=9200, ssl_context=context,)
#es = Elasticsearch(['172.20.0.148:9200'],http_auth=('elastic', '3last1cR3CaS'))
fields = {}


body = {"_source": ["@timestamp", "source.address", "destination.port", 'destination.ip', 'zeek.connection.history', 'zeek.connection.state', "source.packets", "source.bytes"], "size": 10000, "sort": [{"@timestamp": {"order": "desc"}}], "query": {"bool": { "must": [{"match" : {"fileset.name": "connection"}},{"match" : {"network.direction": "inbound"}},{"match" : {"network.transport": "tcp"}}],"filter": [{"range": {"@timestamp": {"gte": "now-1h"}}}]}}}


es_docs = []
for number in range(1):
  response = es.search(index='zeek', scroll='3m', body=body, request_timeout=60)
  #response = es.search(index='zeek',body={"_source": ["@timestamp", "source.address", "destination.port", 'destination.ip', 'zeek.connection.history', 'zeek.connection.state', "source.packets", "source.bytes"], "query": {"bool": {"must": [{"match" : {"fileset.name": "connection"}},{"match" : {"network.direction": "inbound"}},{"match" : {"network.transport": "tcp"}}]}},"sort" : [ { "@timestamp" : { "order" : "desc"}} ]},size=a,request_timeout=60)
  #response = es.search(index='zeek',body={"_source": ["source.bytes", "destination.bytes"], "query": {"bool": {"must": [{"match" : {"fileset.name": "connection"}},{"match" : {"network.direction": "inbound"}},{"match" : {"network.transport": "tcp"}}]}}},size=1000,request_timeout=60)
  #response = es.search(index='filebeat',body={"query": {"match" : {"gpfs": True}},"sort": [{"@timestamp": {"order": "desc"}}]},size=1000,request_timeout=600)
  #print(response['hits']['hits'])
  print ("total docs:", len(response["hits"]["hits"]))
  scroll_size = len(response['hits']['hits'])
  scroll_id = response['_scroll_id']
  sid = response['_scroll_id']
 
  while scroll_size > 0:
    "Scrolling..."
    
    # Before scroll, process current batch of hits
    #process_hits(response['hits']['hits'])
    
    data = es.scroll(scroll_id=sid, scroll='2m')

    # Update the scroll ID
    sid = data['_scroll_id']

    # Get the number of results that returned in the last scroll
    scroll_size = len(data['hits']['hits'])
    print(scroll_size)

    es_docs = es_docs + data['hits']['hits']
  #print(len(es_docs))


es_df = pandas.io.json.json_normalize(es_docs)


#features = ['_source.destination.port', '_source.destination.ip', '_source.zeek.connection.history', '_source.zeek.connection.state',  '_source.source.port', '_source.source.ip']
features = ['_source.source.address', '_source.destination.port', '_source.destination.ip', '_source.zeek.connection.history', '_source.zeek.connection.state', '_source.source.packets', '_source.source.bytes']
#print(es_df[features])
#print(es_docs)
#print(es_df[features])
to_matrix = DataFrameToMatrix()
zeek_matrix = to_matrix.fit_transform(es_df[features], normalize=True)
#print(zeek_matrix)
#print(type(zeek_matrix))

zeek_matrix[:1]

odd_clf = IsolationForest(behaviour='new', contamination=0.15, verbose=1) # Marking 25% odd
#odd_clf.fit(es_df[features])
odd_clf.fit(zeek_matrix)
print(odd_clf.predict(zeek_matrix))

#Outliers
odd_df = es_df[features][odd_clf.predict(zeek_matrix) == -1]
odd_df.head()
print("DEBUG")
print(type(odd_df))

odd_matrix = to_matrix.fit_transform(odd_df)
print("DEBUG1")
print(type(odd_matrix))

# Just some simple stuff for this example, KMeans and PCA
kmeans = KMeans(n_clusters=6).fit_predict(odd_matrix)  # Change this to 3/5 for fun
pca = PCA(n_components=2).fit_transform(odd_matrix)

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
print(type(cluster_groups))
print(dir(cluster_groups))

# Plot the Machine Learning results
colors = {0:'green', 1:'blue', 2:'red', 3:'orange', 4:'purple', 5:'brown'}
fig, ax = plt.subplots()
for key, group in cluster_groups:
    print("DEBUG3")
    print(group['x'])
    print(group['y'])
    group.plot(ax=ax, kind='scatter', x='jx', y='jy', alpha=0.5, s=250,
               label='Cluster: {:d}'.format(key), color=colors[key])

fig.savefig("foo_1.pdf", bbox_inches='tight')


pandas.set_option('display.width', 1000)
for key, group in cluster_groups:
    print('\nCluster {:d}: {:d} observations'.format(key, len(group)))
    print(group[features].head())
#fig = a.get_figure()
#fig.savefig('./figure.pdf')
