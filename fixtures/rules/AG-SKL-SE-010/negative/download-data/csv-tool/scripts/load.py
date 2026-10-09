import csv

with open('/tmp/cities.csv', newline='') as f:
    print(len(list(csv.reader(f))))
