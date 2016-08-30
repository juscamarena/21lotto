#!/usr/bin/env python3
from two1.wallet import Wallet
from two1.bitrequests import BitTransferRequests
import hashlib
from two1.bitcoin.crypto import PrivateKey




# set up bitrequest client for BitTransfer requests
wallet = Wallet()
requests = BitTransferRequests(wallet)

# server address
#server_url = 'http://10.244.18.81:5000/'
server_url = 'http://10.244.132.78:5000/'

def play():
	#######################################################################
	response = requests.get(url=server_url+'genHash')  # Contact server for H
	secret_h = response.text							# Secret H received
	print("Received H: " + secret_h) 
	########################################################################

	private_key = PrivateKey.from_random()				#Random C to give to server for truly random lottery, this is priv key, but pub key is sent
	payout = wallet.get_payout_address()				#Payout Address, I wanted to use this as static random C, but it seems as if it's reused if nothing is won

	random_input = private_key.public_key.address()
	#Sends Server Payout, and random C
	sel_url = server_url + 'play?payout_address={0}&random_input={1}&genHash={2}' #sends unused payout addresss and random C(which is just a public key)
	answer = requests.get(url=sel_url.format(payout, random_input, secret_h))

	print("Sent C: "+ private_key.public_key.address())
	#Secret R is received and I can compute whether I won or not.
	print("\nReceived Secret R: " + answer.text)
	hashed_r = hashlib.sha256(answer.text.encode('ascii')).hexdigest()
	print("Hashed R: " + hashed_r)

	if hashed_r == secret_h:
		print("So far so good. Hashed R == H received earlier")
		hash_cr = answer.text + random_input
		hash_cr =  hashlib.sha256(hash_cr.encode('ascii')).hexdigest()
		print("hash(R + C) = " + hash_cr)
		print("\n")
		if hash_cr[63] == "1":
			print("You have won, expect funds to be sent to the payout address")
		else:
			print("Sorry, you have lost as hash(R + C)[63] == %s and not 1" % hash_cr[63] )
	else:
		print("You have been cheated, server is lying, low on funds, or just buggy as heck")


if __name__ == '__main__':
	play()
