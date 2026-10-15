from utils.ioc_reader import read_iocs

iocs = read_iocs("input/iocs.txt")

for ioc in iocs:
    print(ioc)
