import csv, sys
rows = list(csv.reader(open(sys.argv[1])))
print(len(rows))
