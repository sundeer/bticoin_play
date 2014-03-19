__author__ = 'rs'

import random
import ecdsa
import base58
import hashlib


def privatekey_to_wif(key):
#    return utils.base58CheckEncode(0x80, key_hex.decode('hex'))
    x = '80' + key
    return base58.b58encode_check(x.decode('hex'))


def privatekey_to_publickey(s):
    sk = ecdsa.SigningKey.from_string(s.decode('hex'), curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    return ('\04' + sk.verifying_key.to_string()).encode('hex')


def publickey_to_address(public_key):
    sha256_of_pubkey = hashlib.sha256(public_key.decode('hex')).digest()
    #print 'sha256 of public key -> ', sha256_of_pubkey.encode('hex')

    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(sha256_of_pubkey)
    ripemd160_of_sha256 = ripemd160.digest()
    #print 'ripemd160 of sha256 -> ', ripemd160_of_sha256.encode('hex')

    ripemd160_of_sha256_with_network = '00' + ripemd160_of_sha256.encode('hex')
    #print 'ripemd160 of sha256 with network -> ', ripemd160_of_sha256_with_network

    double_sha256 = hashlib.sha256(hashlib.sha256(ripemd160_of_sha256_with_network.decode('hex')).digest())
    #print 'double sha256 of previous -> ', double_sha256.digest().encode('hex')

    checksum = double_sha256.digest().encode('hex')[:8]
    #print 'checksum -> ', checksum

    with_checksum = ripemd160_of_sha256_with_network + checksum
    #print 'with checksum -> ', with_checksum

    address = base58.b58encode(with_checksum.decode('hex'))
    #print 'address -> ', address
    return address

def keyToAddr(s):
    return publickey_to_address(privatekey_to_publickey(s))

# Warning: this random function is not cryptographically strong and is just for example
private_key = ''.join(['{:x}'.format(random.randrange(16)) for x in range(64)])
private_key = 'f19c523315891e6e15ae0608a35eec2e00ebd6d1984cf167f46336dabd9b2de4'
print 'private key -> ', private_key
#print 'private key -> ', private_key_ken

wif_private_key = privatekey_to_wif(private_key)
print 'WIF private key -> ', wif_private_key

print ''

public_key = privatekey_to_publickey(private_key)
print 'public key -> ', public_key

address = publickey_to_address(public_key)
print 'Bitcoin Address -> ', address

