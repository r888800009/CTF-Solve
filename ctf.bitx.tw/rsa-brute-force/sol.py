#!/usr/bin/env python
import gmpy

e = 10001
n = 46162621237273343596561734914538883909361696167860765627236987089210110553737515170606141271033824645667251043403322830902823065131663376811129460311285003231750160268414559101581048380014925270570435126891301971653061676620269182051364269183452487788185991252281649691555335527909864982934230090294737918788660287725380648189507867627970153812936490608567972618678969715208640470795927868394351672548723142240675860840885482506143981963401534029958533319943330445611011534303987098000529350740022996941904702393627394661

table = {}

for i in range(0, 128):
    table[str(pow(i , e , n))] = chr(i)

with open('output', 'r') as f:
    flag = ""
    for line in f:
        flag += table[line.strip()]
    print(flag)
