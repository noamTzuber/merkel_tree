# Itay Shwartz, 318528171, Noam Tzuberi, 313374837

import hashlib
import math
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization



def add_node(list,leaf):
    list.append(hashlib.sha256(str(leaf).encode('utf-8')).hexdigest())


def find_root(list, first, end):
    # if the list is empty we return
    if len(list) == 0:
        return
    # if we reach to point that first = end that's mean we look to a single object in array - se we return it.
    if first == end:
        return list[first]

    # we find the biggest power of two that contain in our list size
    x = math.floor(math.log((end-first+1), 2))
    # if 2 power x is the size of the array we do x--
    if math.pow(2, x) == end-first+1:
        x = x - 1
    # find the root of the left and right and do hash on both to return the root
    left = find_root(list, first,int(first + math.pow(2, x)-1))
    right = find_root(list,int( first + math.pow(2, x)) , end)
    return hashlib.sha256(str(left + right).encode('utf-8')).hexdigest()

def find_proof(list, i, j, index, result_list,side):
    # if we reach to single leaf in the array - i == j then we add the side of it and the leaf.
    if i == j:
        result_list.append(str(side)+list[index])
        return
    # we find the biggest power of two that contain in our list size
    x = math.floor(math.log((j - i + 1), 2))
    # if 2 power x is the size of the array we do x--
    if math.pow(2, x) == j - i + 1:
        x = x - 1
    # if the leaf that we search is in left side we find it first and than we find it first and than append
    # the root of the right side.
    if i <= index <= math.pow(2, x)+i-1:
        find_proof(list, i, int(math.pow(2, x)+i-1), index, result_list,0)
        result_list.append('1'+find_root(list, int(math.pow(2, x)+i), j))
    else:
        find_proof(list,int(math.pow(2, x) + i), j, index, result_list,1)
        result_list.append('0'+find_root(list, i, int(math.pow(2, x)+i-1)))

def print_the_proof(res_list_proof):
    print_list=" ".join(str(x) for x in res_list_proof)
    print(print_list)

def proof_of_inclusion(leaf,root,proof):
    tmp = hashlib.sha256(str(leaf).encode('utf-8')).hexdigest()
    # we do hash on pairs by the 0 or 1 that appears in the first bit of the hash to decide who come left or right.
    for x in proof[1:]:
        if x[0]=='1':
            tmp = hashlib.sha256(str(tmp+x[1:]).encode('utf-8')).hexdigest()
        else:
            tmp = hashlib.sha256(str(x[1:]+tmp).encode('utf-8')).hexdigest()
    print(root == tmp)

def genarate_keys():
    # generate key's by the algorithm of RSA
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_key = private_key.public_key()

    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    print(pem_private.decode('utf-8'))
    print(pem_public.decode('utf=8'))

def signature_root(key,root):
    # we signature the root with the key that we given.
    while True:
        tmp =input()
        key = key + "\n" + tmp
        if tmp == '-----END RSA PRIVATE KEY-----':
            break

    message = root.encode()
    private_key = serialization.load_pem_private_key(key.encode(),password=None,backend=default_backend())
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print(base64.b64encode(signature).decode())

def verify_sign(public_key):
    # we get the rest of the public key by the loop
    while True:
        tmp = input()
        public_key = public_key + "\n" + tmp
        if tmp == '-----END PUBLIC KEY-----':
            break
    signature = input()
    txt = input().encode()
    public_key = serialization.load_pem_public_key(public_key.encode(),backend=default_backend())

    # we try to verify. if it true then we print true. if we reach to except then it failed so we return false.
    try:
        public_key.verify(
            base64.b64decode(signature),
            txt,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print(True)
    except:
        print(False)

if __name__ == '__main__':
    list = []

    while True:

        res_list_proof = []
        parameter = input()
        # we split the input by spaces
        action_value = parameter.split()

        if len(action_value) == 0:
             print('')
             continue
        choose = action_value[0]
        try:
            if choose == '1':
                # we return the return the string from the list
                var =" ".join(str(x) for x in action_value[1:])
                add_node(list, var)
            elif choose == '2':
                res=(find_root(list, 0, len(list)-1))
                if res is None:
                    print('')
                    continue
                print(res)
            elif choose == '3':
                # we create the list of proof and the root, and return both.
                res_list_proof.append(find_root(list, 0, len(list)-1))
                find_proof(list, 0, len(list)-1, int(action_value[1]), res_list_proof,0)
                print_the_proof(res_list_proof)
            elif choose == '4':
                proof_of_inclusion(action_value[1],action_value[2],action_value[3:])
            elif choose == '5':
                genarate_keys()
            elif choose == '6':
                begin = " ".join(str(x) for x in action_value[1:])
                signature_root(begin, find_root(list, 0, len(list)-1))
            elif choose == '7':
                public_key = " ".join(str(x) for x in action_value[1:])
                verify_sign(public_key)
            else:
                print('')
        except:
            print('')

