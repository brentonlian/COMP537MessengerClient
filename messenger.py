import os
import pickle
import string
import json

from cryptography.hazmat.primitives import hashes, serialization, hmac
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def _certificate_bytes(certificate):
    """Deterministically encode the two certificate fields for signing."""
    if (not isinstance(certificate, dict)
            or set(certificate) != {"name", "public_key"}
            or not isinstance(certificate["name"], str)
            or not certificate["name"]
            or not isinstance(certificate["public_key"], str)):
        raise ValueError("Malformed certificate")

    return json.dumps(
        certificate, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


class MessengerServer:
    def __init__(self, server_signing_key, server_decryption_key):
        self.server_signing_key = server_signing_key
        self.server_decryption_key = server_decryption_key

    def decryptReport(self, ct):
        # 65-byte P-256 public key + 12-byte nonce + GCM ciphertext/tag.
        if not isinstance(ct, bytes) or len(ct) < 93:
            raise ValueError("Malformed report")

        ephemeral_pk_bytes = ct[:65]
        nonce = ct[65:77]
        ciphertext = ct[77:]

        ephemeral_pk = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), ephemeral_pk_bytes
        )

        shared_secret = self.server_decryption_key.exchange(
            ec.ECDH(), ephemeral_pk
        )

        key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"COMP537-report-v1",
        ).derive(shared_secret)

        plaintext = AESGCM(key).decrypt(
            nonce, ciphertext, ephemeral_pk_bytes
        )

        return plaintext.decode("utf-8")

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

    def _initialize_session(self, name, initiator):
        if name in self.conns:
            return self.conns[name]

        if self.initial_dh_sk is None:
            raise ValueError("Generate your certificate first")

        if name not in self.certs:
            raise ValueError("Missing verified certificate")

        peer_pk = self.certs[name]

        initial_secret = self.initial_dh_sk.exchange(
            ec.ECDH(), peer_pk
        )

        state = {
            "RK": initial_secret,
            "DHs": self.initial_dh_sk,
            "DHr": None,
            "CKs": None,
            "CKr": None,
            "Ns": 0,
            "Nr": 0,
            "PN": 0,
        }

        if initiator:
            state["DHr"] = peer_pk

            state["RK"], state["CKs"] = _kdf_root(
                initial_secret, initial_secret
            )

        self.conns[name] = state
        return state

    def sendMessage(self, name, message):
        # Initialize a session if this is the first message.
        state = self._initialize_session(name, True)

        if state["CKs"] is None:
            raise ValueError("Sending chain not initialized")

        # Derive a fresh message key and next chain key.
        next_ck, message_key = _kdf_chain(state["CKs"])

        # Construct the message header.
        public_key = state["DHs"].public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )

        nonce = os.urandom(12)

        header = {
            "dh": public_key.hex(),
            "pn": state["PN"],
            "n": state["Ns"],
            "nonce": nonce.hex(),
        }

        # Encrypt the message and authenticate its header.
        ciphertext = AESGCM(message_key).encrypt(
            nonce,
            message.encode("utf-8"),
            _header_aad(self.name, name, header),
        )

        # Advance the sending ratchet only after encryption succeeds.
        state["CKs"] = next_ck
        state["Ns"] += 1

        return header, ciphertext

    def receiveMessage(self, name, header, ciphertext):
        # Validate the header and ciphertext.
        if (not isinstance(header, dict)
                or set(header) != {"dh", "pn", "n", "nonce"}
                or not isinstance(header["dh"], str)
                or not isinstance(header["nonce"], str)
                or type(header["n"]) is not int or header["n"] < 0
                or type(header["pn"]) is not int or header["pn"] < 0
                or not isinstance(ciphertext, bytes) or len(ciphertext) < 16):
            return None

        try:
            incoming_dh = bytes.fromhex(header["dh"])
            nonce = bytes.fromhex(header["nonce"])

            if len(incoming_dh) != 65 or len(nonce) != 12:
                return None

            state = self._initialize_session(name, False)

            first_receive = state["DHr"] is None
            peer_changed = False
            peer_pk = None

            if first_receive:
                # First message uses the sender's certified DH key.
                peer_pk = self.certs[name]
                expected_dh = peer_pk.public_bytes(
                    encoding=serialization.Encoding.X962,
                    format=serialization.PublicFormat.UncompressedPoint,
                )

                if (incoming_dh != expected_dh
                        or header["pn"] != 0
                        or header["n"] != 0):
                    return None

                new_root, input_ck = _kdf_root(
                    state["RK"], state["RK"]
                )

            else:
                old_dh = state["DHr"].public_bytes(
                    encoding=serialization.Encoding.X962,
                    format=serialization.PublicFormat.UncompressedPoint,
                )

                if incoming_dh == old_dh:
                    # Continue the existing receiving chain.
                    if (header["n"] != state["Nr"]
                            or state["CKr"] is None):
                        return None

                    new_root = None
                    input_ck = state["CKr"]

                else:
                    # New peer DH key: start a new receiving chain.
                    # No skipped messages are allowed.
                    if (header["pn"] != state["Nr"]
                            or header["n"] != 0):
                        return None

                    peer_pk = ec.EllipticCurvePublicKey.from_encoded_point(
                        ec.SECP256R1(), incoming_dh
                    )

                    new_root, input_ck = _kdf_root(
                        state["RK"],
                        state["DHs"].exchange(ec.ECDH(), peer_pk)
                    )

                    peer_changed = True

            # Derive the next receiving chain key and message key.
            next_ck, msg_key = _kdf_chain(input_ck)

            # Authenticate and decrypt the message.
            plaintext = AESGCM(msg_key).decrypt(
                nonce,
                ciphertext,
                _header_aad(name, self.name, header),
            ).decode("utf-8")

            # Commit changes only after successful authentication.
            if first_receive or peer_changed:
                new_private = ec.generate_private_key(ec.SECP256R1())

                next_root, next_send_ck = _kdf_root(
                    new_root,
                    new_private.exchange(ec.ECDH(), peer_pk)
                )

                state["PN"] = state["Ns"]
                state["Ns"] = 0
                state["Nr"] = 0

                state["DHr"] = peer_pk
                state["DHs"] = new_private

                state["RK"] = next_root
                state["CKs"] = next_send_ck

            state["CKr"] = next_ck
            state["Nr"] += 1

            return plaintext

        except (InvalidTag, ValueError, TypeError, KeyError):
            return None

    def report(self, name, message):
        # Encode the sender name and reported message.
        plaintext = json.dumps({
            "sender": name,
            "message": message
        }, ensure_ascii=False).encode("utf-8")

        # Generate a fresh ephemeral P-256 key pair.
        ephemeral_sk = ec.generate_private_key(ec.SECP256R1())
        ephemeral_pk = ephemeral_sk.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )

        # Derive a shared secret using the server's encryption public key.
        shared_secret = ephemeral_sk.exchange(
            ec.ECDH(), self.server_encryption_pk
        )

        key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"COMP537-report-v1",
        ).derive(shared_secret)

        nonce = os.urandom(12)

        # Authenticate the ephemeral public key as associated data.
        ciphertext = AESGCM(key).encrypt(
            nonce, plaintext, ephemeral_pk
        )

        # Include everything necessary for server decryption.
        return plaintext.decode("utf-8"), ephemeral_pk + nonce + ciphertext


def _kdf_root(root_key, dh_output):
    output = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=root_key,
        info=b"COMP537-double-ratchet-root-v1",
    ).derive(dh_output)

    return output[:32], output[32:]


def _kdf_chain(chain_key):
    if chain_key is None:
        raise ValueError("Sending chain not initialized")

    # Derive the one-time message key.
    h = hmac.HMAC(chain_key, hashes.SHA256())
    h.update(b"\x01")
    message_key = h.finalize()

    # Derive the next chain key.
    h = hmac.HMAC(chain_key, hashes.SHA256())
    h.update(b"\x02")
    next_chain_key = h.finalize()

    return next_chain_key, message_key


def _header_aad(sender, recipient, header):
    return json.dumps(
        {
            "sender": sender,
            "recipient": recipient,
            "header": header,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
