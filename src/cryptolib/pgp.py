import pgpy
from pgpy.constants import *
from datetime import datetime
from cryptolib.crypto import Random

from pgpy import *

from pgpy.packet import *
from pgpy.packet.packets import *
from pgpy.packet.fields import *
from pgpy.packet.types import *
from pgpy.decorators import *

from pgpy.types import Fingerprint
from cryptolib.openssl.pyed25519 import *
from cryptolib.crypto import *
import cryptolib
import six
from phe import paillier
from pgpy.types import SignatureVerification
from cryptolib.openssl import ecdsa
from cryptography.hazmat.primitives import hashes
import random
from cryptography.hazmat.primitives.asymmetric import ec
import calendar
import math
from cryptolib.crypto import scrypt_fct
import hashlib
from random import SystemRandom
import json

class COINPLUSPGPKey(PGPKey):
    
    def add_uid(self, uid, selfsign=True, **prefs):
        """
        Add a User ID to this key.
        :param uid: The user id to add
        :type uid: :py:obj:`~pgpy.PGPUID`
        :param selfsign: Whether or not to self-sign the user id before adding it
        :type selfsign: ``bool``
        Valid optional keyword arguments are identical to those of self-signatures for :py:meth:`PGPKey.certify`.
        Any such keyword arguments are ignored if selfsign is ``False``
        """
        uid._parent = self
        if selfsign:
            uid |= self.certify(uid, SignatureType.Positive_Cert, **prefs)

        self |= uid


        
    @KeyAction(is_unlocked=True)
    def bind(self, key, **prefs):
        """
        Bind a subkey to this key.
        Valid optional keyword arguments are identical to those of self-signatures for :py:meth:`PGPkey.certify`
        """
        hash_algo = prefs.pop('hash', None)

        if self.is_primary and not key.is_primary:
            sig_type = SignatureType.Subkey_Binding

        elif key.is_primary and not self.is_primary:
            sig_type = SignatureType.PrimaryKey_Binding

        else:  # pragma: no cover
            raise PGPError

        sig = PGPSignature.new(sig_type, self.key_algorithm, hash_algo, self.fingerprint.keyid, created=prefs["created"])

        if sig_type == SignatureType.Subkey_Binding:
            # signature options that only make sense in subkey binding signatures
            usage = prefs.pop('usage', None)

            if usage is not None:
                sig._signature.subpackets.addnew('KeyFlags', hashed=True, flags=usage)

            # if possible, have the subkey create a primary key binding signature
            if key.key_algorithm.can_sign:
                subkeyid = key.fingerprint.keyid
                esig = None

                if not key.is_public:
                    esig = key.bind(self)

                elif subkeyid in self.subkeys:  # pragma: no cover
                    esig = self.subkeys[subkeyid].bind(self)

                if esig is not None:
                    sig._signature.subpackets.addnew('EmbeddedSignature', hashed=False, _sig=esig._signature)

        return self._sign(key, sig, **prefs)
        
        
    def add_subkey(self, key, **prefs):
        """
        Add a key as a subkey to this key.
        :param key: A private :py:obj:`~pgpy.PGPKey` that does not have any subkeys of its own
        :keyword usage: A ``set`` of key usage flags, as :py:obj:`~constants.KeyFlags` for the subkey to be added.
        :type usage: ``set``
        Other valid optional keyword arguments are identical to those of self-signatures for :py:meth:`PGPKey.certify`
        """
        if key.is_primary:
            if len(key._children) > 0:
                raise PGPError("Cannot add a key that already has subkeys as a subkey!")

            # convert key into a subkey
            npk = PrivSubKeyV4()
            npk.pkalg = key._key.pkalg
            npk.created = key._key.created
            npk.keymaterial = key._key.keymaterial
            key._key = npk
            key._key.update_hlen()

        self._children[key.fingerprint.keyid] = key
        key._parent = self

        ##TODO: skip this step if the key already has a subkey binding signature
        bsig = self.bind(key, **prefs)
        key |= bsig

    def finish_add_subkey(self, key, bsig):
        key |= bsig

    def generate_data_for_add_subkey(self, key, **prefs):
        """
        Add a key as a subkey to this key.
        :param key: A private :py:obj:`~pgpy.PGPKey` that does not have any subkeys of its own
        :keyword usage: A ``set`` of key usage flags, as :py:obj:`~constants.KeyFlags` for the subkey to be added.
        :type usage: ``set``
        Other valid optional keyword arguments are identical to those of self-signatures for :py:meth:`PGPKey.certify`
        """

        if key.is_primary:
            if len(key._children) > 0:
                raise PGPError("Cannot add a key that already has subkeys as a subkey!")

            # convert key into a subkey
            npk = PrivSubKeyV4()
            npk.pkalg = key._key.pkalg
            npk.created = key._key.created
            npk.keymaterial = key._key.keymaterial
            key._key = npk
            key._key.update_hlen()

        self._children[key.fingerprint.keyid] = key
        key._parent = self

        ##TODO: skip this step if the key already has a subkey binding signature
        return self.bind(key, **prefs)
        

    def certify(self, subject, level=SignatureType.Generic_Cert, **prefs):
        """
        Sign a key or a user id within a key.
        :param subject: The user id or key to be certified.
        :type subject: :py:obj:`PGPKey`, :py:obj:`PGPUID`
        :param level: :py:obj:`~constants.SignatureType.Generic_Cert`, :py:obj:`~constants.SignatureType.Persona_Cert`,
                      :py:obj:`~constants.SignatureType.Casual_Cert`, or :py:obj:`~constants.SignatureType.Positive_Cert`.
                      Only used if subject is a :py:obj:`PGPUID`; otherwise, it is ignored.
        :raises: :py:exc:`~pgpy.errors.PGPError` if the key is passphrase-protected and has not been unlocked
        :raises: :py:exc:`~pgpy.errors.PGPError` if the key is public
        :returns: :py:obj:`PGPSignature`
        In addition to the optional keyword arguments accepted by :py:meth:`PGPKey.sign`, the following optional
        keyword arguments can be used with :py:meth:`PGPKey.certify`.
        These optional keywords only make sense, and thus only have an effect, when self-signing a key or User ID:
        :keyword usage: A ``set`` of key usage flags, as :py:obj:`~constants.KeyFlags`.
                        This keyword is ignored for non-self-certifications.
        :type usage: ``set``
        :keyword ciphers: A list of preferred symmetric ciphers, as :py:obj:`~constants.SymmetricKeyAlgorithm`.
                          This keyword is ignored for non-self-certifications.
        :type ciphers: ``list``
        :keyword hashes: A list of preferred hash algorithms, as :py:obj:`~constants.HashAlgorithm`.
                         This keyword is ignored for non-self-certifications.
        :type hashes: ``list``
        :keyword compression: A list of preferred compression algorithms, as :py:obj:`~constants.CompressionAlgorithm`.
                              This keyword is ignored for non-self-certifications.
        :type compression: ``list``
        :keyword key_expiration: Specify a key expiration date for when this key should expire, or a
                              :py:obj:`~datetime.timedelta` of how long after the key was created it should expire.
                              This keyword is ignored for non-self-certifications.
        :type key_expiration: :py:obj:`datetime.datetime`, :py:obj:`datetime.timedelta`
        :keyword keyserver: Specify the URI of the preferred key server of the user.
                            This keyword is ignored for non-self-certifications.
        :type keyserver: ``str``, ``unicode``, ``bytes``
        :keyword primary: Whether or not to consider the certified User ID as the primary one.
                          This keyword is ignored for non-self-certifications, and any certifications directly on keys.
        :type primary: ``bool``
        These optional keywords only make sense, and thus only have an effect, when signing another key or User ID:
        :keyword trust: Specify the level and amount of trust to assert when certifying a public key. Should be a tuple
                        of two ``int`` s, specifying the trust level and trust amount. See
                        `RFC 4880 Section 5.2.3.13. Trust Signature <https://tools.ietf.org/html/rfc4880#section-5.2.3.13>`_
                        for more on what these values mean.
        :type trust: ``tuple`` of two ``int`` s
        :keyword regex: Specify a regular expression to constrain the specified trust signature in the resulting signature.
                        Symbolically signifies that the specified trust signature only applies to User IDs which match
                        this regular expression.
                        This is meaningless without also specifying trust level and amount.
        :type regex: ``str``
        """
        hash_algo = prefs.pop('hash', None)
        sig_type = level
        if isinstance(subject, PGPKey):
            sig_type = SignatureType.DirectlyOnKey


        sig = PGPSignature.new(sig_type, self.key_algorithm, hash_algo, self.fingerprint.keyid, created= prefs["created"])
        # signature options that only make sense in certifications
        usage = prefs.pop('usage', None)
        exportable = prefs.pop('exportable', None)

        if usage is not None:
            sig._signature.subpackets.addnew('KeyFlags', hashed=True, flags=usage)

        if exportable is not None:
            sig._signature.subpackets.addnew('ExportableCertification', hashed=True, bflag=exportable)

        keyfp = self.fingerprint
        if isinstance(subject, PGPKey):
            keyfp = subject.fingerprint
        if isinstance(subject, PGPUID) and subject._parent is not None:
            keyfp = subject._parent.fingerprint

        if keyfp == self.fingerprint:
            # signature options that only make sense in self-certifications
            cipher_prefs = prefs.pop('ciphers', None)
            hash_prefs = prefs.pop('hashes', None)
            compression_prefs = prefs.pop('compression', None)
            key_expires = prefs.pop('key_expiration', None)
            keyserver_flags = prefs.pop('keyserver_flags', None)
            keyserver = prefs.pop('keyserver', None)
            primary_uid = prefs.pop('primary', None)

            if key_expires is not None:
                # key expires should be a timedelta, so if it's a datetime, turn it into a timedelta
                if isinstance(key_expires, datetime):
                    key_expires = key_expires - self.created

                sig._signature.subpackets.addnew('KeyExpirationTime', hashed=True, expires=key_expires)

            if cipher_prefs is not None:
                sig._signature.subpackets.addnew('PreferredSymmetricAlgorithms', hashed=True, flags=cipher_prefs)

            if hash_prefs:
                sig._signature.subpackets.addnew('PreferredHashAlgorithms', hashed=True, flags=hash_prefs)
                if sig.hash_algorithm is None:
                    sig._signature.halg = hash_prefs[0]
            if sig.hash_algorithm is None:
                sig._signature.halg = HashAlgorithm.SHA256

            if compression_prefs is not None:
                sig._signature.subpackets.addnew('PreferredCompressionAlgorithms', hashed=True, flags=compression_prefs)

            if keyserver_flags is not None:
                sig._signature.subpackets.addnew('KeyServerPreferences', hashed=True, flags=keyserver_flags)

            if keyserver is not None:
                sig._signature.subpackets.addnew('PreferredKeyServer', hashed=True, uri=keyserver)

            if primary_uid is not None:
                sig._signature.subpackets.addnew('PrimaryUserID', hashed=True, primary=primary_uid)
            # Features is always set on self-signatures
            sig._signature.subpackets.addnew('Features', hashed=True, flags=Features.pgpy_features)

        else:
            # signature options that only make sense in non-self-certifications
            trust = prefs.pop('trust', None)
            regex = prefs.pop('regex', None)

            if trust is not None:
                sig._signature.subpackets.addnew('TrustSignature', hashed=True, level=trust[0], amount=trust[1])

                if regex is not None:
                    sig._signature.subpackets.addnew('RegularExpression', hashed=True, regex=regex)

        return self._sign(subject, sig, **prefs)
    
    def _sign(self, subject, sig, **prefs):
        """
        The actual signing magic happens here.
        :param subject: The subject to sign
        :param sig: The :py:obj:`PGPSignature` object the new signature is to be encapsulated within
        :returns: ``sig``, after the signature is added to it.
        """
        user = prefs.pop('user', None)
        uid = None
        if user is not None:
            uid = self.get_uid(user)

        else:
            uid = next(iter(self.userids), None)
            if uid is None and self.parent is not None:
                uid = next(iter(self.parent.userids), None)

        if sig.hash_algorithm is None:
            sig._signature.halg = next((h for h in uid.selfsig.hashprefs if h.is_supported), HashAlgorithm.SHA256)

        if uid is not None and sig.hash_algorithm not in uid.selfsig.hashprefs:
            warnings.warn("Selected hash algorithm not in key preferences", stacklevel=4)

        # signature options that can be applied at any level
        expires = prefs.pop('expires', None)
        notation = prefs.pop('notation', None)
        revocable = prefs.pop('revocable', True)
        policy_uri = prefs.pop('policy_uri', None)
        intended_recipients = prefs.pop('intended_recipients', [])

        for intended_recipient in intended_recipients:
            if isinstance(intended_recipient, PGPKey) and isinstance(intended_recipient._key, PubKeyV4):
                sig._signature.subpackets.addnew('IntendedRecipient', hashed=True, version=4,
                                                 intended_recipient=intended_recipient.fingerprint)
            elif isinstance(intended_recipient, Fingerprint):
                # FIXME: what if it's not a v4 fingerprint?
                sig._signature.subpackets.addnew('IntendedRecipient', hashed=True, version=4,
                                                 intended_recipient=intended_recipient)
            else:
                warnings.warn("Intended Recipient is not a PGPKey, ignoring")

        if expires is not None:
            # expires should be a timedelta, so if it's a datetime, turn it into a timedelta
            if isinstance(expires, datetime):
                expires = expires - self.created

            sig._signature.subpackets.addnew('SignatureExpirationTime', hashed=True, expires=expires)

        if revocable is False:
            sig._signature.subpackets.addnew('Revocable', hashed=True, bflag=revocable)

        if notation is not None:
            for name, value in notation.items():
                # mark all notations as human readable unless value is a bytearray
                flags = NotationDataFlags.HumanReadable
                if isinstance(value, bytearray):
                    flags = 0x00

                sig._signature.subpackets.addnew('NotationData', hashed=True, flags=flags, name=name, value=value)

        if policy_uri is not None:
            sig._signature.subpackets.addnew('Policy', hashed=True, uri=policy_uri)

        if user is not None and uid is not None:
            signers_uid = "{:s}".format(uid)
            sig._signature.subpackets.addnew('SignersUserID', hashed=True, userid=signers_uid)

        # handle an edge case for timestamp signatures vs standalone signatures
        if sig.type == SignatureType.Timestamp and len(sig._signature.subpackets._hashed_sp) > 1:
            sig._signature.sigtype = SignatureType.Standalone

        if prefs.pop('include_issuer_fingerprint', True):
            if isinstance(self._key, PrivKeyV4):
                sig._signature.subpackets.addnew('IssuerFingerprint', hashed=True, _version=4, _issuer_fpr=self.fingerprint)

        sigdata = sig.hashdata(subject)
        h2 = sig.hash_algorithm.hasher
        h2.update(sigdata)
        sig._signature.hash2 = bytearray(h2.digest()[:2])

        _sig = self._key.sign(sigdata, getattr(hashes, sig.hash_algorithm.name)())
        if _sig is NotImplemented:
            raise NotImplementedError(self.key_algorithm)

        sig._signature.signature.from_signer(_sig)
        sig._signature.update_hlen()

        return sig

    def end_signature(self, sig, _sig):
        
        if _sig is NotImplemented:
            raise NotImplementedError(self.key_algorithm)

        sig._signature.signature.from_signer(_sig)
        sig._signature.update_hlen()

        return sig

hexdata = "0123456789abcdefABCDEF"

class Phase1PublicParams(object):
    def __init__(self, c1, c2, pailler_public_key, Ka):
        self.c1 = c1
        self.c2 = c2
        self.pailler_public_key = pailler_public_key
        self.Ka = Ka
    def serialize(self, hexa=True):
        ser_bytes = self.pailler_public_key.n.to_bytes(256, "big") # 256
        ser_bytes += self.c1.ciphertext().to_bytes(512, "big") # 512
        ser_bytes += self.c2.ciphertext().to_bytes(512, "big") # 512
        ser_bytes += ecdsa.secp256k1_compress(self.Ka) # 33
        if hexa is False:
            return ser_bytes
        return ser_bytes.hex()

    @classmethod
    def deserialize(cls, stream ):
        if len(stream) % 2 == 0 and type(stream) == str:
            stream = bytes.fromhex(stream)
        pailler_public_key = paillier.PaillierPublicKey(int.from_bytes(stream[:256],"big"))
        c1 =  paillier.EncryptedNumber (pailler_public_key,  int.from_bytes(stream[256:256+512],"big"))
        c2 =  paillier.EncryptedNumber (pailler_public_key,  int.from_bytes(stream[768:768+512],"big"))
        Ka =  ecdsa.secp256k1_uncompress(stream[1280:1280+33])
        return cls(c1=c1, c2=c2, pailler_public_key=pailler_public_key, Ka=Ka)
 
class Phase2PublicParams(object):
    def __init__(self, c):
        self.c = c
    def serialize(self, hexa=True):
        ser_bytes = self.c.ciphertext().to_bytes(512, "big") # 512
        if hexa is False:
            return ser_bytes
        return ser_bytes.hex()

    @classmethod
    def deserialize(cls, stream, pailler_public_key):
        if len(stream) % 2 == 0 and type(stream) == str:
            stream = bytes.fromhex(stream)
        c =  paillier.EncryptedNumber (pailler_public_key,  int.from_bytes(stream[0:512],"big"))
        return cls(c=c)
 


class Phase1PrivateParams(object):
    def __init__(self, pailler_public_key, pailler_private_key, k):
        self.pailler_public_key = pailler_public_key
        self.pailler_private_key = pailler_private_key
        self.k = k
    def serialize(self, hexa=True):
        ser_bytes = self.pailler_public_key.n.to_bytes(256, "big") # 256
        ser_bytes += self.pailler_private_key.p.to_bytes(128, "big")
        ser_bytes += self.pailler_private_key.q.to_bytes(128, "big")
        ser_bytes += self.k.to_bytes(32, "big")
        if hexa is False:
            return ser_bytes
        return ser_bytes.hex()
    @classmethod
    def deserialize(cls, stream):
        if len(stream) % 2 == 0 and type(stream) == str:
            stream = bytes.fromhex(stream)
        pailler_public_key = paillier.PaillierPublicKey(int.from_bytes(stream[:256],"big"))
        p = int.from_bytes(stream[256:256+128],"big")
        q = int.from_bytes(stream[384:384+128],"big")
        pailler_private_key = paillier.PaillierPrivateKey(pailler_public_key, p, q )
        k =  int.from_bytes(stream[512:512+32],"big")
        return cls(pailler_public_key=pailler_public_key, pailler_private_key=pailler_private_key, k=k)
        
class COINPLUSPubKeyV4(PubKeyV4):

    def sign(self, sigdata, hash_alg):
        return self.keymaterial.sign(sigdata, hash_alg)


class COINPLUSECDSAPub(ECDSAPub):

    s2k = False
    @staticmethod
    def generate_phase1_params(secret, random):
        modu = ecdsa.N
        public_key, private_key = paillier.generate_paillier_keypair()
        kbin = random.get_random_b256(32)
        k = int.from_bytes(kbin,"big") % modu
        Ka = ecdsa.secp256k1_mul(k, ecdsa.G )
        c1 = public_key.encrypt(secret*ecdsa.modInv(k, modu))
        c2 = public_key.encrypt(ecdsa.modInv(k, modu))
        phase1publicparams = Phase1PublicParams(c1=c1, c2=c2, pailler_public_key=public_key, Ka=Ka)
        phase1privateparams = Phase1PrivateParams(public_key, private_key, k)

        return phase1publicparams, phase1privateparams


    def prepare_presign(self, myprivateparams, otherpublicparams, secret):
        self.myprivateparams = myprivateparams
        self.otherpublicparams = otherpublicparams
#         k = int(khex, 16)
#         Ko = ecdsa.secp256k1_uncompress(bytes.fromhex(Ko_hex))
#         public_key= paillier.PaillierPublicKey(int(public_key_hex, 16))
#         c1 = paillier.EncryptedNumber (public_key,  int(c1hex, 16))
#         c2 = paillier.EncryptedNumber (public_key,  int(c2hex, 16))
#         self.k = k 
#         self.Ko =Ko
#         self.c1 = c1
#         self.c2 = c2
        self.secret_intsig = int.from_bytes(scrypt_fct( secret+'-sign'), "big")
        self.phase = "presign"

        
    def presign(self, sigdata, hash_alg):
        if hash_alg.name != "sha256":
            raise Exception("hash algo not supported")
        h = hashlib.sha256()
        h.update(sigdata)
        hdata = h.digest()
        msgi = int.from_bytes(hdata, "big")
        
        modu = ecdsa.N
        K = ecdsa.secp256k1_mul(self.myprivateparams.k, self.otherpublicparams.Ka)
        t = K[0]
        r = SystemRandom().randint(1, modu**5)
        c = self.otherpublicparams.c1 * t * (self.secret_intsig * ecdsa.modInv(self.myprivateparams.k, modu))  + \
            self.otherpublicparams.c2 *msgi* ecdsa.modInv(self.myprivateparams.k, modu) +  self.otherpublicparams.pailler_public_key.encrypt(r * modu)
#         c.obfuscate()
        phase2publicparams = Phase2PublicParams(c=c)
        self.phase2publicparams = phase2publicparams
        

        # return dummy, the real return value is in self.phase2publicparams
        sig = DSASignature()
        sig.s = MPI(0)
        sig.r = MPI(0)
        return sig.__sig__()

    def prepare_sign(self, myprivateparams, otherpublicparams, phase2publicparams):  
        modu = ecdsa.N
        self.myprivateparams = myprivateparams
        self.otherpublicparams = otherpublicparams
        self.K = ecdsa.secp256k1_mul(self.myprivateparams.k, self.otherpublicparams.Ka)
        self.phase2publicparams = phase2publicparams
        
        self.phase = "sign"
        
    def full_sign(self, sigdata, hash_alg):
        modu = ecdsa.N
        t = self.K[0]
        
        s = self.myprivateparams.pailler_private_key.decrypt(self.phase2publicparams.c) % modu

        sig = DSASignature()
        sig.s = MPI(s)
        sig.r = MPI(t)
        return sig.__sig__()
    
    def sign(self, sigdata, hash_alg):
        if self.phase == "presign":
            return self.presign(sigdata, hash_alg)
        if self.phase == "sign":
            return self.full_sign(sigdata, hash_alg)


class COINPLUSECDHPriv(ECDHPriv):
    @classmethod
    def from_number(cls, priv, publickey):
        key = cls()
        key.oid = EllipticCurveOID.SECP256K1

        key.kdf.halg = key.oid.kdf_halg
        key.kdf.encalg = key.oid.kek_alg
        

        
        key.p = ECPoint.from_values(key.oid.key_size, ECPointFormat.Standard,
                                    x=MPI( publickey[0]),
                                    y=MPI(publickey[1]))
        key.s = MPI( priv)
        key._compute_chksum()
        return key

class COINPLUSECDSAPriv(ECDSAPriv):
    @classmethod
    def from_number(cls, priv, publickey):
        key = cls()
        key.oid = EllipticCurveOID.SECP256K1


        #a = ECPoint.from_values(bitlen=pubkeyecdsa.oid.key_size, pform=ECPointFormat.Standard, x=publicsig[0], y=publicsig[1])

        key.p = ECPoint.from_values(key.oid.key_size, ECPointFormat.Standard,
                                    x=MPI( publickey[0]),
                                    y=MPI(publickey[1]))
        
        key.s = MPI( priv)
        key._compute_chksum()
        return key

def create_key_struct(secret_1, passpoint_2_sighex, passpoint_2_enchex):
    secret_intsig = int.from_bytes(scrypt_fct( secret_1+'-sign'), "big")  
    secret_intenc = int.from_bytes(scrypt_fct( secret_1), "big")  
    publicsig = ecdsa.secp256k1_mul(secret_intsig, ecdsa.secp256k1_uncompress(bytes.fromhex(passpoint_2_sighex)))
    publicenc = ecdsa.secp256k1_mul(secret_intenc, ecdsa.secp256k1_uncompress(bytes.fromhex(passpoint_2_enchex)))
    
    ## Signature key
    pubkeyecdsa = COINPLUSECDSAPub()
    pubkeyecdsa.oid = pgpy.constants.EllipticCurveOID.SECP256K1
    
    pubkeyecdsa.publicsig = publicsig
    k = KEY()
    a = ECPoint.from_values(bitlen=pubkeyecdsa.oid.key_size, pform=ECPointFormat.Standard, x=publicsig[0], y=publicsig[1])
    pubkeyecdsa.p = a
    
    pubkey = COINPLUSPubKeyV4()
    pubkey.pkalg = PubKeyAlgorithm.ECDSA
    pubkey.keymaterial = pubkeyecdsa
    key = COINPLUSPGPKey()
    key._key = pubkey
    key._key.created = datetime(2020, 1, 1, 0, 0, 0, 0)
    key._key.update_hlen()



    uid = pgpy.PGPUID.new('SOLO PGP', email='info@coinplus.com')
    
    # ~ ## Encryption key
    
    pubkeyecdh = ECDHPub()
    pubkeyecdh.oid = pgpy.constants.EllipticCurveOID.SECP256K1
    a = ECPoint.from_values(bitlen=pubkeyecdh.oid.key_size, pform=ECPointFormat.Standard, 
                            x=publicenc[0],
                            y=publicenc[1])
    pubkeyecdh.p = a
    pubkeyecdh.kdf.halg = pubkeyecdh.oid.kdf_halg
    pubkeyecdh.kdf.encalg = pubkeyecdh.oid.kek_alg


    skey = PGPKey()
    subpubkey = PubSubKeyV4()
    subpubkey.pkalg = PubKeyAlgorithm.ECDH
    subpubkey.key_algorithm =  PubKeyAlgorithm.ECDH
    subpubkey.keymaterial = pubkeyecdh
    skey._key = subpubkey
    skey._key.created = datetime(2020, 1, 1, 0, 0, 0, 0)
    skey._key.update_hlen()

    return key, uid, skey

class PGP_PrivPoint(object):
    def __init__(self, params_phase1_priv_list, secret ):
        self.params_phase1_priv_list = params_phase1_priv_list
        self.secret = secret
    def serialize(self):
        return json.dumps({
            "params_phase1_priv_list": [i.serialize() for i in self.params_phase1_priv_list],
            "secret": self.secret
            })
    @classmethod
    def deserialize(cls, stream):
        js = json.loads(stream)

        params_phase1_priv_list = [Phase1PrivateParams.deserialize(i) for i in js["params_phase1_priv_list"]]
        secret = js["secret"]
        return cls(params_phase1_priv_list, secret)

class PGP_Passpoint(object):
    def __init__(self, params_phase1_pub_list, passpoint_sig, passpoint_enc ):
        self.params_phase1_pub_list = params_phase1_pub_list
        self.passpoint_sig = passpoint_sig
        self.passpoint_enc = passpoint_enc
    def serialize(self):
        return json.dumps({
            "params_phase1_pub_list": [i.serialize() for i in self.params_phase1_pub_list],
            "passpoint_sig": self.passpoint_sig,
            "passpoint_enc": self.passpoint_enc,
            })

    @classmethod
    def deserialize(cls, stream):
        js = json.loads(stream)
        params_phase1_pub_list = [Phase1PublicParams.deserialize(i) for i in js["params_phase1_pub_list"]]
        passpoint_sig, passpoint_enc = js["passpoint_sig"], js["passpoint_enc"]
        return cls(params_phase1_pub_list, passpoint_sig, passpoint_enc )

def presign_coinplus_key(params_phase1_priv_ser, params_phase1_pub_other_ser):
    params_phase1_priv_unser = PGP_PrivPoint.deserialize(params_phase1_priv_ser)
    secret = params_phase1_priv_unser.secret
    params_phase1_priv_list =  params_phase1_priv_unser.params_phase1_priv_list
    params_phase1_pub_other_unser = PGP_Passpoint.deserialize(params_phase1_pub_other_ser)
    params_phase1_pub_list_other = params_phase1_pub_other_unser.params_phase1_pub_list
    passpoint_other_sig = params_phase1_pub_other_unser.passpoint_sig
    passpoint_other_enc = params_phase1_pub_other_unser.passpoint_enc
    
   
    pros_key = {"usage":{KeyFlags.Sign, KeyFlags.Certify},
            "hashes":[HashAlgorithm.SHA256],
            "ciphers":[SymmetricKeyAlgorithm.AES256, SymmetricKeyAlgorithm.AES192, SymmetricKeyAlgorithm.AES128],
            "compression":[CompressionAlgorithm.ZLIB, CompressionAlgorithm.BZ2, CompressionAlgorithm.ZIP, CompressionAlgorithm.Uncompressed],
            "primary": True,
            "created": datetime(2020, 1, 1, 0, 0, 0, 0)}

    key, uid, skey = create_key_struct(secret, passpoint_other_sig, passpoint_other_enc)
    
    params_phase2_pub_list = []
    
    pubkeyecdsa = key._key.keymaterial
    pubkeyecdsa.prepare_presign(params_phase1_priv_list[0], params_phase1_pub_list_other[0], secret)
    key.add_uid(uid, selfsign=True, **pros_key )
    params_phase2_pub_list.append(pubkeyecdsa.phase2publicparams.serialize())
    
    pubkeyecdsa = key._key.keymaterial
    pubkeyecdsa.prepare_presign(params_phase1_priv_list[1], params_phase1_pub_list_other[1], secret)
    key.add_subkey(skey, usage={KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage}, hash=HashAlgorithm.SHA256, ciphers=[SymmetricKeyAlgorithm.AES256], 
                   created=datetime(2020, 1, 1, 0, 0, 0, 0))
    params_phase2_pub_list.append(pubkeyecdsa.phase2publicparams.serialize())

    
    return json.dumps(params_phase2_pub_list)

def sign_coinplus_key(params_phase1_priv_ser, params_phase1_pub_other_ser, params_phase2_pub_list_other_ser):
    params_phase2_pub_list_other = json.loads(params_phase2_pub_list_other_ser)
    params_phase1_priv_unser = PGP_PrivPoint.deserialize(params_phase1_priv_ser)
    secret = params_phase1_priv_unser.secret
    params_phase1_priv_list =  params_phase1_priv_unser.params_phase1_priv_list
    params_phase1_pub_other_unser = PGP_Passpoint.deserialize(params_phase1_pub_other_ser)
    params_phase1_pub_list = params_phase1_pub_other_unser.params_phase1_pub_list
    passpoint_other_sig = params_phase1_pub_other_unser.passpoint_sig
    passpoint_other_enc = params_phase1_pub_other_unser.passpoint_enc
        
        
    pros_key = {"usage":{KeyFlags.Sign, KeyFlags.Certify},
            "hashes":[HashAlgorithm.SHA256],
            "ciphers":[SymmetricKeyAlgorithm.AES256, SymmetricKeyAlgorithm.AES192, SymmetricKeyAlgorithm.AES128],
            "compression":[CompressionAlgorithm.ZLIB, CompressionAlgorithm.BZ2, CompressionAlgorithm.ZIP, CompressionAlgorithm.Uncompressed],
            "primary": True,
            "created": datetime(2020, 1, 1, 0, 0, 0, 0)}

    key, uid, skey = create_key_struct(secret, passpoint_other_sig, passpoint_other_enc)

    pubkeyecdsa = key._key.keymaterial
    pubkeyecdsa.prepare_sign(params_phase1_priv_list[0], params_phase1_pub_list[0], 
                             Phase2PublicParams.deserialize(params_phase2_pub_list_other[0], params_phase1_priv_list[0].pailler_public_key) )
    key.add_uid(uid, selfsign=True, **pros_key )

    pubkeyecdsa = key._key.keymaterial
    pubkeyecdsa.prepare_sign(params_phase1_priv_list[1],params_phase1_pub_list[1], 
                             Phase2PublicParams.deserialize(params_phase2_pub_list_other[1], params_phase1_priv_list[1].pailler_public_key) )
    key.add_subkey(skey, usage={KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage}, hash=HashAlgorithm.SHA256, ciphers=[SymmetricKeyAlgorithm.AES256], 
                   created=datetime(2020, 1, 1, 0, 0, 0, 0))

    return key


def create_private_key_from_secrets(secret58_1, secret58_2):
    secretsig1 = int(scrypt_fct(secret58_1+"-sign").hex(),16) 
    secretsig2 = int(scrypt_fct(secret58_2+"-sign").hex(),16) 
    
    ## Signature key
    privkeyecdsa = COINPLUSECDSAPriv()
    privkeyecdsa.oid = pgpy.constants.EllipticCurveOID.SECP256K1
    
    privkey = (secretsig1*secretsig2)%ecdsa.N
    publickey = ecdsa.secp256k1_mul(privkey , ecdsa.G)
    privkeyecdsa = COINPLUSECDSAPriv.from_number(privkey, publickey)

    
    primary_privkey = PrivKeyV4()
    primary_privkey.pkalg = PubKeyAlgorithm.ECDSA
    primary_privkey.keymaterial = privkeyecdsa
    key = COINPLUSPGPKey()
    key._key = primary_privkey
    key._key.update_hlen()
    key._key.created = datetime(2020, 1, 1, 0, 0, 0, 0)
    
    
    
    uid = pgpy.PGPUID.new('SOLO PGP', email='info@coinplus.com')
    
    pros_key = {"usage":{KeyFlags.Sign, KeyFlags.Certify},
                "hashes":[HashAlgorithm.SHA256],
                "ciphers":[SymmetricKeyAlgorithm.AES256, SymmetricKeyAlgorithm.AES192, SymmetricKeyAlgorithm.AES128],
                "compression":[CompressionAlgorithm.ZLIB, CompressionAlgorithm.BZ2, CompressionAlgorithm.ZIP, CompressionAlgorithm.Uncompressed],
                "primary": True,
                "created": datetime(2020, 1, 1, 0, 0, 0, 0)}
    key.add_uid(uid, selfsign=True, **pros_key )
    
    
    
    # ~ ## Encryption key

    secretenc1 = int(scrypt_fct(secret58_1).hex(),16) 
    secretenc2 = int(scrypt_fct(secret58_2).hex(),16) 
    
    privkey = (secretenc1*secretenc2)%ecdsa.N
    publickey = ecdsa.secp256k1_mul(privkey , ecdsa.G)
    privkeyecdh = COINPLUSECDHPriv.from_number(privkey, publickey)
    
    
    
    skey = PGPKey()
    subpubkey = PrivSubKeyV4()
    subpubkey.created = datetime(2020, 1, 1, 0, 0, 0, 0)
    subpubkey.pkalg = PubKeyAlgorithm.ECDH
    subpubkey.key_algorithm =  PubKeyAlgorithm.ECDH
    subpubkey.keymaterial = privkeyecdh
    skey._key = subpubkey
    skey._key.update_hlen() 
    
    
    
    key.add_subkey(skey, usage={KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage}, hash=HashAlgorithm.SHA256, ciphers=[SymmetricKeyAlgorithm.AES256],
                   created= datetime(2020, 1, 1, 0, 0, 0, 0))
    
    return key


def generate_pgp_init_info(random_instance, secret = None):
    if secret is None:
        secret = random_instance.get_random_b58(29)
       
    secret_intsig = int.from_bytes(scrypt_fct(secret+'-sign'), "big")

    P1 =  ecdsa.secp256k1_mul(secret_intsig, ecdsa.G)
    assert P1 ==  list(ecdsa.secp256k1_uncompress(ecdsa.secp256k1_compress(P1)))
    
    
    passpoint_sig = ecdsa.secp256k1_compress(ecdsa.secp256k1_mul(secret_intsig, ecdsa.G)).hex()
    params_phase1_pub_list = []
    params_phase1_priv_list = []
    params_phase1_pub, params_phase1_priv = COINPLUSECDSAPub.generate_phase1_params(secret_intsig, random_instance)
    params_phase1_pub_list.append(params_phase1_pub)
    params_phase1_priv_list.append(params_phase1_priv)
    params_phase1_pub, params_phase1_priv = COINPLUSECDSAPub.generate_phase1_params(secret_intsig, random_instance)
    params_phase1_pub_list.append(params_phase1_pub)
    params_phase1_priv_list.append(params_phase1_priv)

    secret_intenc = int.from_bytes(scrypt_fct(secret), "big")  
    passpoint_enc = ecdsa.secp256k1_compress(ecdsa.secp256k1_mul(secret_intenc, ecdsa.G)).hex()
    return PGP_Passpoint(params_phase1_pub_list, passpoint_sig, passpoint_enc).serialize(), PGP_PrivPoint(params_phase1_priv_list, secret).serialize()

if __name__ == "__main__":
    random = Random()
    params_phase1_pub_user1_ser, params_phase1_priv_user1_ser = generate_pgp_init_info(random)
    params_phase1_pub_user2_ser, params_phase1_priv_user2_ser = generate_pgp_init_info(random)


    params_phase2_pub_list = presign_coinplus_key(params_phase1_priv_user1_ser   ,  params_phase1_pub_user2_ser)

    key2 = sign_coinplus_key(params_phase1_priv_user2_ser, params_phase1_pub_user1_ser, params_phase2_pub_list)
#     
# 
#         secret_2, 
#                              params_phase1_priv_list_user2,
#                              params_phase1_pub_list_user1,
#                              passpoint_1_sig, 
#                              passpoint_1_enc, 
#                              params_phase2_pub_list)
    print(key2)
    print(key2.verify(key2._uids[0], key2._uids[0].selfsig))
    
    secret_1 = PGP_PrivPoint.deserialize(params_phase1_priv_user1_ser).secret
    secret_2 = PGP_PrivPoint.deserialize(params_phase1_priv_user2_ser).secret
    
    key_regen = create_private_key_from_secrets(secret_1, secret_2)
    print(key_regen)

    

