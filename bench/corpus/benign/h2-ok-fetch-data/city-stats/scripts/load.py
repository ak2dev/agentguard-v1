import csv

with open('data/cities.csv', newline='') as f:
    rows = list(csv.DictReader(f))
print(len(rows), 'cities')
