'''
Created on 2 Jun 2019

@author: david

Initial import from:
https://wiki.mikrotik.com/wiki/Manual:API_Python3
'''
#!/usr/bin/python3
# -*- coding: latin-1 -*-
import binascii
import hashlib
import logging
import select
import socket
import ssl
import sys

logger = logging.getLogger(__name__)

class MikrotikAPIError(Exception):

    def __init__(self, message, category = -1):
        self.message = message
        self.category = category

    def __str__(self):
        return repr(self.message)


class MikrotikAPI(object):
  """
  Routeros API client.
  
  Based on:
  https://wiki.mikrotik.com/wiki/Manual:API
  
  Notes:
  - Built for version 6.43 or later.
  
  
  Attributes: 
    s (socket): raw socket connected to mikrotik router.
    
    imag (int): The imaginary part of complex number. 
  
  """
  __port_secure = 8729
  __port_normal = 8728
  
  def __init__(self, hostname, port = 0, secure = False):
    '''
    
    '''
    
    # Set default port appropriately.
    if (port == 0):
      port = self.__port_secure if secure else self.__port_normal
    
    self.open_socket(hostname, port, secure)
    self.currenttag = 0

  def login(self, username, pwd):
    '''
    
    '''
    for repl, attrs in self.talk(["/login", 
                                  "=name=" + username,
                                  "=password=" + pwd]):
      if repl == '!trap':
        return False
      elif '=ret' in attrs.keys():
        chal = binascii.unhexlify((attrs['=ret']).encode(sys.stdout.encoding))
        md = hashlib.md5()
        md.update(b'\x00')
        md.update(pwd.encode(sys.stdout.encoding))
        md.update(chal)
        for repl2, attrs2 in self.talk(["/login", "=name=" + username,
               "=response=00" + binascii.hexlify(md.digest()).decode(sys.stdout.encoding) ]):
          if repl2 == '!trap':
            return False
          
    return True

  def _talk(self, words):
    return self.talk(words)

  def talk(self, words):
    '''
    '''
    if self.writeSentence(words) == 0: 
      return
    r = []
    while True:
      i = self.readSentence();
      if len(i) == 0:
        continue
      reply = i[0]
      attrs = {}
      for w in i[1:]:
        j = w.find('=', 1)
        if (j == -1):
          attrs[w] = ''
        else:
          attrs[w[:j]] = w[j+1:]
      r.append((reply, attrs))
      if reply == '!done': 
        return r

  def writeSentence(self, words):
    '''
    '''
    ret = 0
    for w in words:
      self.writeWord(w)
      ret += 1
    self.writeWord('')
    return ret

  def readSentence(self):
    r = []
    while 1:
      w = self.readWord()
      if w == '':
        return r
      r.append(w)

  def writeWord(self, w):
    logger.debug(("<<< " + w))
    self.writeLen(len(w))
    self.writeStr(w)

  def readWord(self):
    ret = self.readStr(self.readLen())
    logger.debug((">>> " + ret))
    return ret

  def writeLen(self, l):
    if l < 0x80:
      self.writeByte((l).to_bytes(1, sys.byteorder))
    elif l < 0x4000:
      l |= 0x8000
      tmp = (l >> 8) & 0xFF
      self.writeByte(((l >> 8) & 0xFF).to_bytes(1, sys.byteorder))
      self.writeByte((l & 0xFF).to_bytes(1, sys.byteorder))
    elif l < 0x200000:
      l |= 0xC00000
      self.writeByte(((l >> 16) & 0xFF).to_bytes(1, sys.byteorder))
      self.writeByte(((l >> 8) & 0xFF).to_bytes(1, sys.byteorder))
      self.writeByte((l & 0xFF).to_bytes(1, sys.byteorder))
    elif l < 0x10000000:
      l |= 0xE0000000
      self.writeByte(((l >> 24) & 0xFF).to_bytes(1, sys.byteorder))
      self.writeByte(((l >> 16) & 0xFF).to_bytes(1, sys.byteorder))
      self.writeByte(((l >> 8) & 0xFF).to_bytes(1, sys.byteorder))
      self.writeByte((l & 0xFF).to_bytes(1, sys.byteorder))
    else:
      self.writeByte((0xF0).to_bytes(1, sys.byteorder))
      self.writeByte(((l >> 24) & 0xFF).to_bytes(1, sys.byteorder))
      self.writeByte(((l >> 16) & 0xFF).to_bytes(1, sys.byteorder))
      self.writeByte(((l >> 8) & 0xFF).to_bytes(1, sys.byteorder))
      self.writeByte((l & 0xFF).to_bytes(1, sys.byteorder))

  def readLen(self):
    c = ord(self.readStr(1))
    # print (">rl> %i" % c)
    if (c & 0x80) == 0x00:
      pass
    elif (c & 0xC0) == 0x80:
      c &= ~0xC0
      c <<= 8
      c += ord(self.readStr(1))
    elif (c & 0xE0) == 0xC0:
      c &= ~0xE0
      c <<= 8
      c += ord(self.readStr(1))
      c <<= 8
      c += ord(self.readStr(1))
    elif (c & 0xF0) == 0xE0:
      c &= ~0xF0
      c <<= 8
      c += ord(self.readStr(1))
      c <<= 8
      c += ord(self.readStr(1))
      c <<= 8
      c += ord(self.readStr(1))
    elif (c & 0xF8) == 0xF0:
      c = ord(self.readStr(1))
      c <<= 8
      c += ord(self.readStr(1))
      c <<= 8
      c += ord(self.readStr(1))
      c <<= 8
      c += ord(self.readStr(1))
    return c

  def writeStr(self, to_write):
    n = 0;
    while n < len(to_write):
      r = self.sk.send(bytes(to_write[n:], 'UTF-8'))
      if r == 0: 
        raise RuntimeError("connection closed by remote end")
      n += r

  def writeByte(self, to_write):
    n = 0;
    while n < len(to_write):
      r = self.sk.send(to_write[n:])
      if r == 0:
        raise RuntimeError("connection closed by remote end")
      n += r

  def readStr(self, length):
    ret = ''
    # logger.debug("length: %i" % length)
    while len(ret) < length:
      s = self.sk.recv(length - len(ret))
      if s == b'':
        raise RuntimeError("connection closed by remote end")
      # logger.debug(b">>>" + s)
      # atgriezt kaa byte ja nav ascii chars
      if s >= (128).to_bytes(1, "big") :
        return s
      # logger.debug((">>> " + s.decode(sys.stdout.encoding, 'ignore')))
      ret += s.decode(sys.stdout.encoding, "replace")
    return ret

  def open_socket(self, dst, port, secure = False):
    """ 
    Open raw socket to 

    Parameters: 
      dst (int): The real part of complex number. 
      port (int): The imaginary part of complex number.
      secure (bool): The imaginary part of complex number.
      
    Returns: 
      socket: created socket.   
      
    Raises:
      AttributeError: The ``Raises`` section is a list of all exceptions
        that are relevant to the interface.
      ValueError: If `param2` is equal to `param1`.
           
    """

    res = socket.getaddrinfo(dst, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    af, socktype, proto, _, sockaddr = res[0]
    
    logger.debug("Opening socket to '{0}'-'{1}'-'{2}'-'{3}'".format(af, socktype, proto, sockaddr))
    skt = socket.socket(af, socktype, proto)
    if secure:
      self._socket = ssl.wrap_socket(skt, ssl_version=ssl.PROTOCOL_TLSv1_2, ciphers="ADH-AES128-SHA256") # ADH-AES128-SHA256
    else:
      self._socket = skt
    self._socket.connect(sockaddr)
    
    if self._socket is None:
      raise RuntimeError('could not open socket')
    
    # TODO: Rewrite all references to self.sk and self.s to self._socket
    self.s = self._socket
    self.sk = self._socket
    
    return self._socket
  
  def runCommand(self, command, **parameters):
    '''
    Run command via API.
        
    Run a command attempting to keep as close to the command line version,
    while maintaining an easy to use library.
    
    If you have a parameter that has a dash '-' in it replace the dash with
    a double underscore '__' in the parameter list. The special field '.id'
    also cannot be used directly and can be referenced via __id__. Neither
    of these are necessary if you are unpacking a dictionary of parameters.
    
    Examples:
    apiros = ApiRos('<ip address / hostname>')
    apiros.login('<username>', '<password>')

    rez = apiros.runCommand("/ip/address/print", cpu__load = 5)
                        
    rez = apiros.runCommand("/ip/address/add",
                        address = "192.168.1.1/24", interface = "ether1"
                        )
    
    rez = apiros.runCommand("/ip/address/set",
                        __id__ = '*3', address = '172.20.0.5/24'
                        )
                        
    rez = apiros.runCommand("/ip/address/add",
                            address = "192.168.1.1/24", interface = "ether1"
                            )
                            
    rez = apiros.runCommand('/ip/route/print',
                            where = ['dst-address=10.10.10.0/24', 'dynamic=true']
                            )
                            
    Parameters: 
      command (string): The base command. 
      parameters (list): Parameters to the base command.
      
    Returns: 
      list: result of command. For print commands    
      
    Raises:
      MikrotikAPIError: The ``Raises`` section is a list of all exceptions
        that are relevant to the interface.
      ValueError: If `param2` is equal to `param1`.
    '''
    
    try:
      apiMessage = [command]

      if parameters != None:
        if 'where' in parameters:
          criteria = parameters['where']
          del parameters['where']
          apiMessage += map(lambda sm: "?{0}".format(sm), criteria)

        if '__id__' in parameters:
          parameters['.id'] = parameters['__id__']
          del parameters['__id__']
        apiMessage += ["={0}={1}".format(k.replace('__', '-'), v) for k, v in parameters.items()]

      logger.debug("Raw data sent: {0}".format(apiMessage))

      rez = self._talk(apiMessage)

      logger.debug("Raw return: {0}".format(rez))

      # Remove the !done at the end of the list.
      if rez[len(rez) - 1][0] == '!done':
        doneVal = rez.pop()

      # Check for error conditions (Need to make this more efficient).
      trapVal = list(filter(lambda sm: sm[0] == '!trap', rez))
      if trapVal != []:
        trapVal = trapVal.pop()
        if 'category' in trapVal:
          category = trapVal[1]['=category']
        else:
          category = -1

        # print "TrapVal = {0}".format(trapVal[1])
        raise MikrotikAPIError("{0} - {1} - {2}".format(trapVal[1]['=message'], command, parameters), category)

      # Extract the data itself
      data = map(lambda sm: sm[1], rez)
      if data == []:
        if doneVal[1] != {}:
          data = doneVal[1]['=ret']

      # Reset the retry counter if we are successful.
      self._retry_count = 0
      return list(data)
    except MikrotikAPIError as e:
      if e.message == "connection closed by remote end":
        self._retry_count += 1
        if self._retry_count > 3:
          raise
        self.connect(self._ip, self._port, self._timeout)
        self.runCommand(command, **parameters)
      else:
        raise

if __name__ == '__main__':
  import pprint
  import traceback
  
  logging.BASIC_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
  logging.basicConfig(level = logging.DEBUG)
  
  try:
    apiros = MikrotikAPI('192.168.1.1', secure = False);
    if not apiros.login('api', 'Gh6Z9nG6cDZrdEqH'):
      raise RuntimeError("Wrong username or password")
  
    res = apiros.runCommand('/ip/address/print', where=['interface=Inside'])
    
    logging.debug("Result: {0}".format(pprint.pformat(res)))      
  except Exception as e:
    logging.error("An exception occurred 'mikrotik_api': {0}, {1}".format(e.__class__, e))
    exc_type, exc_value, exc_traceback = sys.exc_info()
    logging.error(repr(traceback.format_exception(exc_type, exc_value, exc_traceback)))
    
