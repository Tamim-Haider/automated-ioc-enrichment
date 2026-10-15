def read_iocs(filename):
    iocs = []

    with open(filename, "r") as file:
        for line in file:
            ioc = line.strip()

            if ioc:
                iocs.append(ioc)

    return iocs

