from __future__ import division # allows 3/2 == 1.5
import base64
import binascii
import string
import operator

def hexToBytes (hexString):
    return bytearray.fromhex(hexString)
    #return hexString.decode('hex')

def base64EncodeBytes (bytes):
    return base64.b64encode(bytes)

def base64Decode(encodedString):
    return base64.b64decode(encodedString)

def base64EncodeHex (hexString):
    return base64.b64encode(hexToBytes(hexString))

def xorHex(buffer1, buffer2):
    buffer1 = hexToBytes(buffer1)
    buffer2 = hexToBytes(buffer2)
    return xorBytes(buffer1, buffer2)

def xorBytes(buffer1, buffer2):
    output = bytearray()
    #if (len(buffer1) != len(buffer2)):
    #    raise ValueError("Buffers should be equal lengths")
    for i in range(len(buffer1)):
        output.append(buffer1[i]^buffer2[i])
    return output

def xorBytesWithKey(bytes, key):
    output = bytearray()
    keyLength = len(key)
    for i in range(len(bytes)):
        output.append(xorBytes([bytes[i]], [key[i%keyLength]])[0])
    return output

def xorHexWithByteKey(hexString, key):
    bytes = hexToBytes(hexString)
    return xorBytesWithKey(bytes, key)

def xorTextWithKey(plaintext, key):
    bytes = bytearray(plaintext)
    key = bytearray(key)
    return xorBytesWithKey(bytes, key)

def guessSingleXorKey(cipherText, numberOfCandidates = 5, silent = False):
    ########################################################
    # given byte array, encoded (xor) with a single byte,
    # tries to guess the key
    # returns (bestKey, ranking, decryption)
    ########################################################
    rankings={}
    decodings={}
    for keyGuess in range(255):
        potentialSolution = xorBytesWithKey(cipherText, [keyGuess])
        ranking = rankPlaintext(potentialSolution)
        rankings[keyGuess] = ranking
        decodings[keyGuess] = potentialSolution
        #print keyGuess, potentialSolution

    sorted_rankings = sorted(rankings.items(), key=operator.itemgetter(1), reverse=True)
    top = sorted_rankings[0:numberOfCandidates]
    if (not silent):
        print "Ranking, Key, Plaintext"
    for item in top:
        key = item[0]
        if (not silent):
            print rankings[key], ", ", key, ", ", decodings[key]
    return (top[0][0], top[0][1], decodings[top[0][0]]) # (bestKey, ranking, decryption)

def rankPlaintext(plaintext):
    ranking = 0
    try:
        plaintext = plaintext.decode('utf8')
    except UnicodeDecodeError:
        return 0
    for char in plaintext:
        #if char in string.printable:
        #    ranking+=1
        if char in (string.digits + string.ascii_letters + string.punctuation + ' '):
            ranking+=1
        else:
            ranking-=5
        if char in (string.ascii_letters + ' '):
            ranking+=1 # extra points if it's a letter or space!
    return ranking    

def bits(byte):
    for i in xrange(8):
        yield (byte >> i) & 1

def hammingDistance(bytes1, bytes2):
    xor = xorBytes(bytes1, bytes2)
    distance = 0
    for byte in xor:
        for bit in bits(byte):
            distance+=bit
    return distance

def chunks(myList, n):
    output = []
    for i in xrange(0, len(myList), n):
        output.append(myList[i:i+n])
    return output

def guessKeySize(cipherTextBytes, lowerBound = 1, upperBound = 40, silent = False):
    ########################################################################
    # Currently uses just the first 4 blocks of size keySize to calculate
    # normalised hamming distance. Should maybe use more
    ########################################################################

    smallestDistance = 8 # theoretical maximum?
    probableKeySize = 0
    for keySize in range(lowerBound,upperBound+1):
        buffer1 = cipherTextBytes[0:keySize]
        buffer2 = cipherTextBytes[keySize:keySize*2]
        buffer3 = cipherTextBytes[keySize*2: keySize*3]
        buffer4 = cipherTextBytes[keySize*3: keySize*4]
        averageHammingDistance = (  hammingDistance(buffer1, buffer2)
                                  + hammingDistance(buffer1, buffer3)
                                  + hammingDistance(buffer1, buffer4)
                                  + hammingDistance(buffer2, buffer3)
                                  + hammingDistance(buffer2, buffer4)
                                  + hammingDistance(buffer3, buffer4))/6
        normalisedHammingDistance = averageHammingDistance/keySize
        if (normalisedHammingDistance < smallestDistance):
            probableKeySize = keySize
            smallestDistance = normalisedHammingDistance
        if not silent:
            print keySize, normalisedHammingDistance
    return probableKeySize

def guessXorKey(cipherTextBytes, minKeySize = 1, maxKeySize = 40, silent = False):
    probableKeySize = guessKeySize(cipherTextBytes, minKeySize, maxKeySize, silent)
    if not silent:
        print "key size: ", probableKeySize
    blocks = chunks(cipherTextBytes, probableKeySize)
    transposedBlocks = []
    for i in range(probableKeySize):
        transposedBlocks.append([])
        for block in blocks:
            try:
                transposedBlocks[i].append(block[i])
            except IndexError:
                continue

    fullKey = bytearray()
    for block in transposedBlocks:
        key = guessSingleXorKey(block, 1, True)[0]
        fullKey.append(key)

    if not silent:
        print "key: ", fullKey
    return fullKey

def guessXorKeyShort(cipherTextBytes, probableKeySize):
    blocks = chunks(cipherTextBytes, probableKeySize)
    transposedBlocks = []
    for i in range(probableKeySize):
        transposedBlocks.append([])
        for block in blocks:
            try:
                transposedBlocks[i].append(block[i])
            except IndexError:
                continue

    fullKey = bytearray()
    for block in transposedBlocks:
        key = guessSingleXorKey(block, 1, True)[0]
        fullKey.append(key)

    print "key: ", fullKey
    return fullKey

def RotateMe(text,mode=0,steps=1):
  # Takes a text string and rotates
  # the characters by the number of steps.
  # mode=0 rotate right
  # mode=1 rotate left
  length=len(text)
 
  for step in range(steps):
  # repeat for required steps
 
    if mode==0:
      # rotate right
      text=text[length-1] + text[0:length-1]
    else:
      # rotate left
      text=text[1:length] + text[0]
 
  return text


