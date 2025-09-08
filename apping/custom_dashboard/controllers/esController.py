import configparser
import datetime

from elasticsearch import Elasticsearch, RequestsHttpConnection

config = configparser.ConfigParser()
config.read('config.ini', encoding='utf-8')

# api_url = config['network_monitoring']['ndr_api']
es_con = Elasticsearch(hosts=str(config['network_monitoring']['ndr_api']), verify_certs=False,
                   connection_class=RequestsHttpConnection, use_ssl=True, timeout=150, max_retries=10,
                   retry_on_timeout=True)
