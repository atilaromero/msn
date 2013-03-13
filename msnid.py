#!/usr/bin/python

def calcid(email):
  "Computes the MSNid of the given account."
  r=0
  for s in email:
    r=(r*101)%(2**32)
    r=(r+ord(s.lower()))%(2**32)
  return str(r)

def findaccount(name_id,providers):
  "Given an name_id (like 'test3803284015'), tries to find the account (like 'test@hotmail.com')"
  for i in range(1,len(name_id)):
    b=name_id[:-i]
    c=name_id[-i:]
    for e in providers:
      e='@'+e
      print b+e,c,calcid(b+e)
      if calcid(b+e)==c:
        return b+e
  return

providers=['hotmail.com',
        'hotmail.co.uk',
        'hotmail.com.br',
        'yahoo.com',
        'yahoo.com.br',
        'gmail.com',
        'msn.com',
        'live.com',
        'live.com.br',
        'live.co.uk']
