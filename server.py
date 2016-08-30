#!/usr/bin/env python3
import random
import hashlib
from flask import Flask
from flask import request

from two1.wallet import Wallet
from two1.bitserv.flask import Payment
from two1.bitcoin.crypto import PrivateKey

import hashlib

app = Flask(__name__)
wallet = Wallet()
payment = Payment(app, wallet)

private_key = PrivateKey.from_random()


private_public_list = []


@app.route('/genHash')
def generateH():
    while True:
        global private_key
        private_key = PrivateKey.from_random() #gen new priv each run through to prevent cheating
        
        print("Secret R: %s" % private_key.public_key.address())
        print("\n")
        hash_public = hashlib.sha256(private_key.public_key.address().encode('ascii')).hexdigest() #send hash of pub key

        if(len(private_public_list) > 0):
            for x in private_public_list:
                if x[1] == hash_public:
                    print("ALREADY IN THE LISTTTT")
                    continue

        private_public_list.append((private_key.public_key.address(), hash_public))
        print(private_public_list)
        print("\n")

        return hash_public


@app.route('/play')
@payment.required(50)
def play():
    client_payout_addr = request.args.get('payout_address')
    print(client_payout_addr)
    gen_hash = request.args.get('genHash')
    for x in range(len(private_public_list)):
        if private_public_list[x][1] == gen_hash:
            hashed_R = gen_hash
            secret_R = private_public_list[x][0]
            private_public_list.pop(x) # deletes to prevent reuse

    print("Received H: " + gen_hash)

    random_input = request.args.get('random_input') # random input C
    combinedStrings = secret_R + random_input
    print("Random C: " + random_input)
    combinedHash = hashlib.sha256(combinedStrings.encode('ascii')).hexdigest()
    print("\nCombined Hash: " + combinedHash + "\n" )

    print(combinedHash[63])

    global private_key

    private_key = PrivateKey.from_random() #gen new priv each run through to prevent cheating

    if(combinedHash[63] == "1"):
        print("You won!!!")
        #send_to(client_payout_addr, 7000)
    else:
        print("Sorry you lost")




    print("\n\n\nLIST: ")
    print(private_public_list)

    print("Sent Secret R " + secret_R)
    return str(secret_R)



if __name__ == '__main__':
    app.run(host='0.0.0.0')

