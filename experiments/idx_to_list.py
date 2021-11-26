#!/usr/bin/python3

def deep_count(harr):
    if len(harr) == 1:
        return 1 + 2 * (1 << harr[0])
    ccount = deep_count(harr[1:])
    return 1 + (1 << harr[0]) * ( 2 + ccount)

def idx_to_list(idx, harr, start=0):
    if len(harr) == 1:
        return [[start, idx]]
    bits = 0
    for num in harr[1:]:
        bits += num
    deepersigs = 1 << bits
    lindex = idx // deepersigs
    dindex = idx % deepersigs
    dstart = start + 1 + 2 * (1 << harr[0]) + lindex * deep_count(harr[1:])
    return [[start, lindex]] + idx_to_list(dindex, harr[1:], dstart)


heights = [3,5,4]
sigcount =1
for h in heights:
    sigcount *= 1 << h  
for idx in range(0,sigcount):
    print(idx,idx_to_list(idx,heights))
