import csv

with open('ticdata2000.txt') as f:
    lines = [line.rstrip().split() for line in f]

final = []

for val in lines:
    temp_val = []
    for item in val[:15]:
        item = item.replace('\t', ',')
        item = item + ','
        temp_val.append(item)

    final.append("".join(temp_val))


with open('ticdata2000_processed.csv', 'w') as f:
    f.write("v0,v1,v2,v3,v4,v5,v6,v7,v8,v9,v10,v11,v12,v13,v14\n")
    for item in final:
        f.write("%s\n" % item[:-1])
