def from_utctime(utctime):
    #from: '2020-08-18 07:23:34.837'
    #to:   '2020-08-18T07:23:34.839Z'

    first, second = map(str, utctime.split())
    first = first+"T"
    second = second+"Z"
    timeline = first+second
    return timeline