#!/usr/bin/python3
import sys
import json

def keys_per_signature(hashlen, otsbits):
    return 2*(((hashlen*8-1) // otsbits)+1)

def sub_sub_keyspace_usage(hashlen, otsbits, height):
    return 1 + keys_per_signature(hashlen, otsbits) * (1 << height)

def sub_keyspace_usage(hashlen, otsbits, heights):
    usage = sub_sub_keyspace_usage(hashlen, otsbits,heights[0])
    if len(heights) > 1:
        usage += (1 << heights[0]) * sub_keyspace_usage(hashlen, otsbits, heights[1:])
    if usage.bit_length() > 64:
        print("ERROR: Key-derivation entropy would be exausted", usage.bit_length(),"out of 64 bit needed to support keyspace for deepest",len(heights), "single-priv key-levels")
    elif usage.bit_length() > 32:
        print("NOTICE:", usage.bit_length(),"out of 64 bit needed to support keyspace for deepest",len(heights), "single-priv key-levels")
    return usage

def keyspace_usage(hashlen, otsbits, keyspace):
    usage = (1 << sum(keyspace[0]["heights"])) + sub_keyspace_usage(hashlen, otsbits, keyspace[0]["heights"])
    if len(keyspace) > 1:
        usage += (1 << keyspace[0]["reserve"]) * keyspace_usage(hashlen, otsbits, keyspace[1:])
    if usage.bit_length() > 64:
        print("ERROR: Key-derivation entropy would be exausted", usage.bit_length(),"out of 64 bit needed to support keyspace for deepest",len(keyspace), "priviledge levels")
    return usage

def test_keyspace(hashlen, otsbits, keyspace):
    total = keyspace_usage(hashlen, otsbits, keyspace)
    if total.bit_length() > 64:
        print("ERROR: Key-derivation entropy would be exausted", total.bit_length(),"out of 64 bit needed to support keyspace")
        return 1
    else:
        print("INFO: Key-derivation entropy usage:", total.bit_length(),"out of 64 bit needed to support keyspace")
    return 0

def process_hierarchy(hyr, errcount_old):
    max_depth = 1
    errcount = errcount_old
    for key, val in hyr.items():
        if isinstance(val, dict):
            depth, errcount = process_hierarchy(val, errcount)
            depth += 1
            if depth > max_depth:
                max_depth = depth
        else:
            print("ERROR: sub-hierarchy item", key, "should be a dict")
            errcount += 1
    return max_depth, errcount


if len(sys.argv) < 2:
    print("Please specify application coinZdense RC file path")
    sys.exit(1)
try:
    with open(sys.argv[1]) as config:
        try:
            conf = json.load(config)
        except json.decoder.JSONDecodeError:
            print("ERROR:", sys.argv[1], "isn't properly JSON formatted") 
            sys.exit(3)
except FileNotFoundError:
    print("Error: no such file:", sys.argv[1])
    sys.exit(2)
except IsADirectoryError:
    print("Error: call on file, not directory:", sys.argv[1])
    sys.exit(3)

errcount = 0
if "appname" not in conf:
    print("ERROR: missing appname definition in coinZdense RC file")
    errcount += 1
elif not isinstance(conf["appname"], str):
    print("ERROR: appname definition in coinZdense RC file should be a string")
    errcount += 1
if "hashlen" not in conf:
    print("ERROR: missing hashlen definition in coinZdense RC file")
    errcount += 1
elif not isinstance(conf["hashlen"], int):
    print("ERROR: hashlen definition in coinZdense RC file should be a number")
    errcount += 1
elif conf["hashlen"] < 16:
    print("ERROR: hashlen definition in coinZdense RC file should be a number larger than 15")
    errcount += 1
elif conf["hashlen"] > 64:
    print("ERROR: hashlen definition in coinZdense RC file should be a number smaller than 65")
    errcount += 1
if "otsbits" not in conf:
    print("ERROR: missing otsbits definition in coinZdense RC file")
    errcount += 1
elif not isinstance(conf["otsbits"], int):
    print("ERROR: otsbits definition in coinZdense RC file should be a number")
    errcount += 1
elif conf["otsbits"] < 4:
    print("ERROR: otsbits definition in coinZdense RC file should be a number larger than 3")
    errcount += 1
elif conf["otsbits"] > 16:
    print("ERROR: otsbits definition in coinZdense RC file should be a number smaller than 17")
    errcount += 1
if "hierarchy" not in conf:
    depth = 1
elif not isinstance(conf["hierarchy"], dict):
    depth = 1
    print("ERROR: hierarchy definition in coinZdense RC file if defined should be an object")
    errcount += 1
else:
    depth, errcount = process_hierarchy(conf["hierarchy"], errcount)
if "keyspace" not in conf:
    print("ERROR: missing keyspace definition in coinZdense RC file")
    errcount += 1
elif not isinstance(conf["keyspace"], list):
    print("ERROR: keyspace definition in coinZdense RC file should be a list of objects")
    errcount += 1
elif len(conf["keyspace"]) != depth:
    print("ERROR:, keyspace should define exactly", depth, "objects, but defined", len(conf["keyspace"]),"instead")
    errcount += 1
else:
    for idx, val in enumerate(conf["keyspace"]):
        if not isinstance(val, dict):
            print("ERROR: keyspace at index number", idx,"should be an object")
            errcount += 1
        else:
            total_height = 0
            if "heights" not in val:
                print("ERROR: keyspace at index number", idx,"should have an heights field")
                errcount += 1
            elif not isinstance(val["heights"], list):
                print("ERROR: keyspace at index number", idx,"should have an heights field containing a list of ints")
                errcount += 1
            elif len(val["heights"]) < 2:
                print("ERROR: keyspace at index number", idx,"has a heights field with less than the minimum of 2 values")
                errcount += 1
            elif len(val["heights"]) > 32:
                print("ERROR: keyspace at index number", idx,"has a heights field with more than the maximum of 32 values")
                errcount += 1
            else:
                for idx2,height in enumerate(val["heights"]):
                    if not isinstance(height, int):
                        print("ERROR: The", idx2, "height value of the ",idx,"keyspace object should be a number")
                        errcount += 1
                    elif height < 3:
                        print("ERROR: The", idx2, "height value of the ",idx,"keyspace object should be 3 or higher")
                        errcount += 1
                    elif height > 16:
                        print("ERROR: The", idx2, "height value of the ",idx,"keyspace object should be 16 or lower")
                        errcount += 1
                    else:
                        total_height += height
            if idx < len(conf["keyspace"]) -1:
                if "reserve" not in val:
                    print("ERROR: keyspace at index number", idx,"should have an reserve field")
                    errcount += 1
                elif not isinstance(val["reserve"], int):
                    print("ERROR: keyspace at index number", idx,"reserve field should be a number")
                    errcount += 1
                elif val["reserve"] < 2:
                    print("ERROR: keyspace at index number", idx,"reserve field should be a number larger than 1")
                    errcount += 1
                elif val["reserve"] > total_height - 2:
                    print("ERROR: keyspace at index number", idx,"with a total height of", total_height,
                          "should have a reserved space of at most", total_height - 2, "specified", val["reserve"])
                    errcount += 1
            else:
                if "reserve" in val:
                    print("ERROR: The last object in the keyspace definition must NOT have a reserve field")
                    errcount += 1
if errcount == 0:
    errcount = test_keyspace(conf["hashlen"], conf["otsbits"], conf["keyspace"])
else:
    print("NOTICE: There are errors in the file format, not testing keyspace dimentions!")
print("NOTICICE: error count :", errcount)




