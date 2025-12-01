import datetime
import os
import hashlib

class Tools:
    def __init__(self):
        pass        
    def get_hash_value(self, input_string):
        hash_object = hashlib.sha256()
        hash_object.update(input_string.encode('utf-8'))
        return hash_object.hexdigest()

    def get_timestamp(self):
        current_datetime = datetime.datetime.now()
        return str(current_datetime.timestamp())