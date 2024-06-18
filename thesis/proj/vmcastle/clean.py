
f = open('./program', 'rb')
data = f.read()
f = open('./clean_prog', 'wb')

for i in range(0, len(data), 2):
    if data[i] <= 101:
        continue
    f.write(data[i: i + 2])
f.close()
