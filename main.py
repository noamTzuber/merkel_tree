# Itay Shwartz 318528171
# Noam Tzuberi 313374837

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
    if len(list) == 0:
        return
    if first == end:
        return list[first]
    x = math.floor(math.log((end-first+1), 2))
    if math.pow(2, x) == end-first+1:
        x = x - 1
    left = find_root(list, first,int(first + math.pow(2, x)-1))
    right = find_root(list,int( first + math.pow(2, x)) , end)
    return hashlib.sha256(str(left + right).encode('utf-8')).hexdigest()

def find_proof(list, i, j, index, result_list):
    if i == j:
        result_list.append(list[index])
        return
    x = math.floor(math.log((j - i + 1), 2))
    if math.pow(2, x) == j - i + 1:
        x = x - 1
    if i <= index <= math.pow(2, x)+i-1:
        find_proof(list, i, int(math.pow(2, x)+i-1), index, result_list)
        result_list.append(find_root(list, int(math.pow(2, x)+i), j))
    else:
        find_proof(list,int(math.pow(2, x) + i), j, index, result_list)
        result_list.append(find_root(list, i, int(math.pow(2, x)+i-1)))

def print_the_proof(res_list_proof):
    print_list=" ".join(str(x) for x in res_list_proof)
    print(print_list)

def proof_of_inclusion(leaf,root,proof):

    tmp = hashlib.sha256(str(leaf).encode('utf-8')).hexdigest()
    for x in proof:
        tmp = hashlib.sha256(str(tmp+x).encode('utf-8')).hexdigest()
    print(root == tmp)

def genarate_keys():

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
    while True:
        tmp = input()
        public_key = public_key + "\n" + tmp
        if tmp == '-----END PUBLIC KEY-----':
            break
    signature = input()
    txt = input().encode()
    public_key = serialization.load_pem_public_key(public_key.encode(),backend=default_backend())

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
        action_value = parameter.split()

        if len(action_value) == 0:
             print('')
             continue
        choose = action_value[0]
        try:
            if choose == '1':
                var =" ".join(str(x) for x in action_value[1:])
                add_node(list, var)
            elif choose == '2':
                print(find_root(list, 0, len(list)-1))
            elif choose == '3':
                res_list_proof.append(find_root(list, 0, len(list)-1))
                find_proof(list, 0, len(list)-1, int(action_value[1]), res_list_proof)
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

