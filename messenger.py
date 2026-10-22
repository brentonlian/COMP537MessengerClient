import os
import pickle
import string
import json

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

def _certificate_bytes(certificate):
    """Deterministically encode the two certificate fields for signing."""
    if (not isinstance(certificate, dict)
            or set(certificate) != {"name", "public_key"}
            or not isinstance(certificate["name"], str)
            or not certificate["name"]
            or not isinstance(certificate["public_key"], str)):
        raise ValueError("Malformed certificate")

    return json.dumps(certificate, sort_keys=True,
                      separators=(",", ":"), ensure_ascii=False).encode("utf-8")

class MessengerServer:
    def __init__(self, server_signing_key, server_decryption_key):
        self.server_signing_key = server_signing_key
        self.server_decryption_key = server_decryption_key

    def decryptReport(self, ct):
        raise Exception("not implemented!")
        return

    def signCert(self, cert):
        # ECDSA signature of the entire certificate, using SHA-256.
        return self.server_signing_key.sign(
            _certificate_bytes(cert), ec.ECDSA(hashes.SHA256())
        )

class MessengerClient:

    def __init__(self, name, server_signing_pk, server_encryption_pk):
        self.name = name
        self.server_signing_pk = server_signing_pk
        self.server_encryption_pk = server_encryption_pk
        self.conns = {}
        self.certs = {}
        self.initial_dh_sk = None
        self.certificate = None

    def generateCertificate(self):
        # Generate the client's initial P-256 DH key pair once.
        if self.initial_dh_sk is None:
            self.initial_dh_sk = ec.generate_private_key(ec.SECP256R1())
            public_key_bytes = self.initial_dh_sk.public_key().public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.UncompressedPoint,
            )
            self.certificate = {
                "name": self.name,
                "public_key": public_key_bytes.hex(),
            }
        return dict(self.certificate)

    def receiveCertificate(self, certificate, signature):
        # Do not trust or store the certificate until its server signature verifies.
        self.server_signing_pk.verify(
            signature, _certificate_bytes(certificate), ec.ECDSA(hashes.SHA256())
        )
        # Require that the signed key encodes a valid P-256 curve point.
        peer_pk = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), bytes.fromhex(certificate["public_key"])
        )
        self.certs[certificate["name"]] = peer_pk

    def sendMessage(self, name, message):
        raise Exception("not implemented!")
        return

    def receiveMessage(self, name, header, ciphertext):
        raise Exception("not implemented!")
        return

    def report(self, name, message):
        raise Exception("not implemented!")
        return
