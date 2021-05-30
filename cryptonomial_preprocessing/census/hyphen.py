import csv

with open('census.data') as f:
    lines = [line.rstrip().split() for line in f]

final = []

for val in lines:
    temp_val = []
    for item in val:
        item = item.replace("-", "_")
        temp_val.append(item)

    final.append("".join(temp_val))


with open('census_processed.csv', 'w') as f:
    for item in final:
        f.write("%s\n" % item)
