#!/usr/bin/env python3
# -*- coding:utf-8 -*-
# credit: https://github.com/realoriginal/titanldr-ng/blob/master/python3/hashstring.py

import sys

def hash_string( string ):
    try:
        hash = 5381

        for x in string.upper():
            hash = (( hash << 5 ) + hash ) + ord(x)


        # hash ^= 0xA5A5A5A5

        return hash & 0xFFFFFFFF
    except:
        pass

def hash_coffapi( string ):
    try:
        hash = 5381

        for x in string:
            hash = (( hash << 5 ) + hash ) + ord(x)

        
        # hash ^= 0xA5A5A5A5

        return hash & 0xFFFFFFFF
    except:
        pass

if __name__ in '__main__':
    try:
        print('#define H_FUNC_%s 0x%x' % ( sys.argv[ 1 ].upper(), hash_string( sys.argv[ 1 ] ) ));
        print('#define H_COFFAPI_%s 0x%x' % ( sys.argv[ 1 ].upper(), hash_coffapi( sys.argv[ 1 ] ) ));
    except IndexError:
        print('usage: %s [string]' % sys.argv[0]);
