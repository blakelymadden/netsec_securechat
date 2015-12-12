# -*- coding: utf-8 -*-
import json, datetime, os, sys
from local_crypt import H, N, load_public_key
from l_globals import FILE_PATH

USER_PATH = FILE_PATH + "/users/"

"""
users file path
|
-/users
    |
    - /al
    |
    - - al_data.txt
    - - al_pub_key.pem
    ...
    ...
    - /zoe
    |
    - - zoe_data.txt
    - - zoe_pub_key.pem
"""

class User():
    def __init__(self, name=None, pw=None, addresss=None, port_in=None, json_data=None):
        if(json_data != None):
            data = json_data
            self.name = data['name']
            self.pw = data['password']
            self.addresss = data['addresss']
            self.port_in = data["port_in"]
            self.pub_key = User.load_pub_key(self.name)
            if addresss is not None:
                self.addresss = addresss
            
        else:
            self.name = name
            self.pw = H(pw, name, N)
            self.addresss = addresss
            self.pub_key = None
            self.port_in = port_in
        self.attempts = 0
        self.verifier = None
            
    # generates a json formated version of this object
    def json_dump(self):
        l_json = {
            "name": self.name,
            "password": self.pw,
            "addresss": self.addresss,
            "port_in": self.port_in,
        }
        return l_json
    
    def attempt(self):
        self.attempts += 1
    
    # creates a user from a json file
    @staticmethod
    def load_user_from_json(uname):
        try:
            path = User.get_user_data_path(uname)
            print(path)
            data = None
            with open(path, "r") as data_file:
                read_data = data_file.read()
                data = json.loads(read_data)
            if data is None:
                return None
            return User(json_data=data)
        except IOError as e:
            #print(str(e))
            return None
    
    # loads a users public key
    @staticmethod
    def load_pub_key(uname):
        path = User.get_user_pub_key_path(uname)
        return load_public_key(path)

            
    # generates the users data path
    @staticmethod
    def get_user_path(uname, file_type):
        return USER_PATH + "{0}/{0}_{1}".format(uname, file_type)
    
    # generates the users data path
    @staticmethod
    def get_user_data_path(uname):
        return User.get_user_path(uname, "data.txt")
    
    # generates the users data path
    @staticmethod
    def get_user_pub_key_path(uname):
        return User.get_user_path(uname, "pub_key.pem")
    
    # list all users in the user folder
    @staticmethod
    def list_users():
        dirs = []
        for (dirpath, dirnames, filenames) in walk(mypath):
            dirs.extend(dirnames)
            break
        return dirs
    
    # returns a dict of usernames to users
    @staticmethod
    def load_all_users():
        res = {}
        users = User.load_all_users()
        for uname in users:
            res[uname] = User.load_user_from_json(uname)
        return res
