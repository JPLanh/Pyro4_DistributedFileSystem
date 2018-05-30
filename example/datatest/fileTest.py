

if __name__ == "__main__":
  f = open("test.zip", 'rb')
  data = f.read()
  array = []
  byteRead = 0
  while byteRead < len(data):
    if (len(data)-byteRead) > 1024:      
      array.append(data[byteRead:(byteRead+1023)])
      byteRead += 1023
    else:
      array.append(data[byteRead:len(data)])
      byteRead = len(data)

  newF = open("copy.zip", 'wb')
  for we in array:
    newF.write(we)
#  newF.write(data)
#  newF.close()
  f.close()
  newF.close()
