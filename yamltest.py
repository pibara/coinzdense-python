#!/usr/bin/python3
from yaml import load
try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader

def _params_to_chunk_count(hashlen, otsbits):
    return (hashlen * 8 + otsbits -1) // otsbits

def _params_to_per_signature_index_space(hashlen, otsbits):
    # *2 : secret_up + secret_down
    # +2 : + transaction salt + misc seed/salt 
    return _params_to_chunk_count(hashlen, otsbits) *2 + 2


def _params_to_index_space(hashlen, otsbits, heights):
    lowest_level_signing_space = (1 << sum(heights)) * _params_to_per_signature_index_space(hashlen, otsbits)
    if len(heights) > 1:
        lowest_level_level_key_salts = 1 << sum(heights[:-1])
        return lowest_level_signing_space + lowest_level_level_key_salts + _params_to_index_space(hashlen, otsbits, heights[:-1])
    else:
        return lowest_level_signing_space + 1

class RcSubKey:
    def __init__(self, obj, parent=None, default=None):
        if parent is None:
            if "appname" in obj:
                self.node = [obj["appname"]]
            else:
                raise RuntimeError("Missing mandatory 'appname' from application RC")
            if "hashlen" in obj:
                self.hashlen = obj["hashlen"]
            else:
                self.hashlen = 16
            if "otsbits" in obj:
                self.otsbits = obj["otsbits"]
            else:
                self.otsbits = 4
            if "heights" in obj:
                self.heights = obj["heights"]
            else:
                raise RuntimeError("Missing mandatory 'heights' from applicatio  RC")
            self.allocated = 1
            self.shared = 1
            self.default = {}
            self.subkeys = []
            if "subkeys" in obj:
                for subkey in obj["subkeys"]:
                    if "typ" in subkey and subkey["typ"] == "default":
                        self.default = subkey
                    else:
                        self.subkeys.append(subkey)
        else:
            if default is None:
                raise RuntimeError("default should not be None if parent is defined")
            if "name" in obj:
                self.node = parent.node[:]
                self.node.append(obj["name"])
            else:
                raise RuntimeError("Subkey should have a name:" + str(obj))
            self.hashlen = parent.hashlen
            self.otsbits = parent.otsbits
            if "heights" in obj:
                self.heights = obj["heights"]
            elif "heights" in default:
                self.heights = default["heights"]
            else:
                self.heights = parent.heights
            if "allocated" in obj:
                self.allocated = obj["allocated"]
            elif "allocated" in default:
                self.allocated = default["allocated"]
            else:
                self.allocated = 0
            if "shared" in obj:
                self.shared = obj["shared"]
            elif "shared" in default:
                self.shared = default["shared"]
            else:
                if self.allocated > 0:
                    self.shared = 0
                else:
                    raise RuntimeError("Either allocated or shared must be defined for subkey " + str(self.node))
            self.default = {}
            self.subkeys = []
            if "subkeys" in obj:
                for subkey in obj["subkeys"]:
                    if "typ" in subkey and subkey["typ"] == "default":
                        self.default = subkey
                    else:
                        self.subkeys.append(subkey)
    def index_space(self):
        ownkey_space = _params_to_index_space(self.hashlen, self.otsbits, self.heights)
        biggest_shared = 0
        total_reserved = 0
        for subkey in self.subkeys:
            child = RcSubKey(subkey, self, self.default)
            one_child_size = sum(child.index_space())
            shared_candidate = one_child_size * self.shared
            if shared_candidate > biggest_shared:
                biggest_shared = shared_candidate
            total_reserved += one_child_size * self.allocated
        return [ownkey_space, total_reserved, biggest_shared]

    def reserved_count(self):
        rval = 0
        for subkey in self.subkeys:
            child = RcSubKey(subkey, self, self.default)
            rval += child.allocated
        return rval

    def total_count(self):
        return 1 << sum(self.heights)

    def check(self, minimum=0.0):
        total_index_space = sum(self.index_space())
        for subkey in self.subkeys:
            to_test = RcSubKey(subkey, self, self.default)
            to_test.check()
        percentage = total_index_space * 100.0 / float(1 << 64)
        if len(self.node) == 1 and percentage < minimum:
            raise RuntimeError("Maximum allocatable index space is lower than the check treshold of " + str(minimum) + "% (" + str(percentage) + "%)")
        if percentage > 100.0:
            raise RuntimeError("Maximum allocatable index space exceeds the maximum available index space " + str(percentage) + "% used",str(self.node))
        return percentage

    def __getitem__(self, key):
        for subkey in self.subkeys:
            if subkey["name"] == key:
                return RcSubKey(subkey, self, self.default)
        raise KeyError(key)

class KsSubKey:
    def __init__(self, rckey, offset=0, kssize=1<<64,  old_state=None, sync=None, parent_sign_index=None):
        print(offset, kssize)
        self.rckey = rckey
        self.keyspace_offset = offset
        self.keyspace_end_offset = offset + kssize - 1
        sizes = rckey.index_space()
        self.heap_offset = offset + sizes[0]
        self.reserved_count = rckey.reserved_count()
        self.total_count = rckey.total_count()
        if old_state is None:
            self.state = {}
            self.state["reserved_index"] = 0
            self.state["regular_index"] = self.reserved_count
            self.state["heap_pointer"] = self.heap_offset
        else:
            self.state = old_state
        self.sync = sync
        self.parent_sign_index = parent_sign_index

    def __getitem__(self, key):
        rckey = self.rckey[key]
        if self.state["regular_index"] < self.total_count:
            myindex = self.state["regular_index"] 
            self.state["regular_index"] += 1
        elif self.state["reserved_index"] < self.reserved_count:
            myindex = self.state["reserved_index"]
            self.state["reserved_index"] += 1
        else:
            raise RuntimeError("Exausted reserved key index")
        myoffset = self.state["heap_pointer"]
        mysize = sum(rckey.index_space())
        if self.state["heap_pointer"] + mysize - 1 > self.keyspace_end_offset:
            raise RuntimeError("Ran out of keyspace heap")
        self.state["heap_pointer"] += mysize
        if self.sync is not None:
            self.sync(self.state)
        return KsSubKey(rckey, myoffset, mysize, parent_sign_index=myindex)

    def set_sync(self,sync):
        self.sync = sync
        self.sync(self.state)

    def signing_index(self):
        if self.state["regular_index"] < self.total_count:
            myindex = self.state["regular_index"]
            self.state["regular_index"] += 1
            if self.sync is not None:
                self.sync(self.state)
            return myindex
        else:
            raise RuntimeError("Exausted main key index")

with open("etc/coinzdense.d/hiveish.yml") as apprc:
    data = load(apprc, Loader=Loader)

owner_key = RcSubKey(data)
owner_key_2 = KsSubKey(owner_key)
print(owner_key_2.signing_index())
print(owner_key_2.signing_index())
active_key_2 = owner_key_2["ACTIVE"]
print(active_key_2.parent_sign_index)
print(active_key_2.signing_index())
#percentage = owner_key.check(minimum=50.0)
#print("OK:", percentage)
#print(owner_key.index_space())
#active_key = owner_key["ACTIVE"]
#print(active_key.index_space())
#posting_key = active_key["POSTING"]
#print(posting_key.index_space())
#vote_key = posting_key["vote"]
#print(vote_key.index_space())
#custom_json_key = posting_key["custom_json"]
#print(custom_json_key.index_space())
#splinterland_key = custom_json_key["sm"]
#print(splinterland_key.index_space())
#find_match_key = splinterland_key["sm_find_match"]
#print(find_match_key.index_space())


