#!/usr/bin/python3
import os
import json

class EtcEnv:
    def __init__(self, dirlist):
        self.confmap = {}
        for mydir in dirlist:
            if os.path.isdir(mydir):
                for filename in os.listdir(mydir):
                    if os.path.splitext(filename)[1].lower() == ".json":
                        fullpath = os.path.join(mydir, filename)
                        if os.path.isfile(fullpath):
                            with open(fullpath) as jsonfile:
                                try:
                                    content = json.load(jsonfile)
                                except ValueError:
                                    content = {}
                            if "appname" in content and isinstance(content["appname"], str):
                                appname = content["appname"]
                                if appname not in self.confmap:
                                    self.confmap[appname] = content

    def __getitem__(self, key):
        if key in self.confmap:
            return self.confmap[key]
        else:
            raise KeyError("No coinZdense blockchain RC named " + key)


