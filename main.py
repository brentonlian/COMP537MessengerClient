from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec

# Increase as we implement more methods: 1=certificates, 2=reporting, 3=messaging.
TEST_STAGE = 7

from messenger import MessengerServer
from messenger import MessengerClient

def error(s):
  print("=== ERROR: " + s)

print("Initializing Server")
server_sign_sk = ec.generate_private_key(ec.SECP256R1())
server_enc_sk = ec.generate_private_key(ec.SECP256R1())
server = MessengerServer(server_sign_sk, server_enc_sk)

server_sign_pk = server_sign_sk.public_key()
server_enc_pk = server_enc_sk.public_key()

print("Initializing Users")
alice = MessengerClient("alice", server_sign_pk, server_enc_pk)
bob = MessengerClient("bob", server_sign_pk, server_enc_pk)
carol = MessengerClient("carol", server_sign_pk, server_enc_pk)

print("Generating Certs")
certA = alice.generateCertificate()
certB = bob.generateCertificate()
certC = carol.generateCertificate()

print("Signing Certs")
sigA = server.signCert(certA)
sigB = server.signCert(certB)
sigC = server.signCert(certC)

print("Distributing Certs")
try:
    alice.receiveCertificate(certB, sigB)
    alice.receiveCertificate(certC, sigC)
    bob.receiveCertificate(certA, sigA)
    bob.receiveCertificate(certC, sigC)
    carol.receiveCertificate(certA, sigA)
    carol.receiveCertificate(certB, sigB)
except:
    error("certificate verification issue")

print("Testing incorrect cert issuance")
mallory = MessengerClient("mallory", server_sign_pk, server_enc_pk)
certM = mallory.generateCertificate()
try:
    alice.receiveCertificate(certM, sigC)
except:
    print("successfully detected bad signature!")
else:
    error("accepted certificate with incorrect signature")

# Additional certificate security tests (Step 1).
print("Testing certificate authenticity and stored public keys")
assert alice.certs["bob"].public_numbers() == bob.initial_dh_sk.public_key().public_numbers()
assert "mallory" not in alice.certs

# Tampering with the signed username must invalidate the signature.
tampered_name = certB.copy()
tampered_name["name"] = "eve"
try:
    alice.receiveCertificate(tampered_name, sigB)
except InvalidSignature:
    print("successfully rejected tampered username!")
else:
    error("accepted a certificate with a tampered username")
assert "eve" not in alice.certs

# Replacing Bob's signed public key with Carol's valid key must also be rejected.
tampered_key = certB.copy()
tampered_key["public_key"] = certC["public_key"]
try:
    alice.receiveCertificate(tampered_key, sigB)
except InvalidSignature:
    print("successfully rejected tampered public key!")
else:
    error("accepted a certificate with a tampered public key")

if TEST_STAGE == 1:
    print("Step 1 complete: certificate tests passed!")
    raise SystemExit(0)

print("Testing Reporting")
content = "inappropriate message contents"
reportPT, reportCT = alice.report("Bob", content)
decryptedReport = server.decryptReport(reportCT)
if decryptedReport != reportPT:
    error("report did not decrypt properly")
    print(reportPT)
    print(decryptedReport)
else:
    print("Reporting test successful!")

print("Testing tampered report ciphertext")

tampered = bytearray(reportCT)
tampered[-1] ^= 1

try:
    server.decryptReport(bytes(tampered))
except Exception:
    print("successfully rejected tampered report!")
else:
    error("accepted tampered report")


print("Testing randomized report encryption")

_, reportCT2 = alice.report("Bob", content)

assert reportCT != reportCT2
assert server.decryptReport(reportCT2) == reportPT

print("randomized encryption test passed!")

if TEST_STAGE == 2:
    print("Step 2 complete: reporting tests passed!")
    raise SystemExit(0)

print("Testing session initialization")

a = alice._initialize_session("bob", True)
b = bob._initialize_session("alice", False)

shared_a = alice.initial_dh_sk.exchange(
    ec.ECDH(), alice.certs["bob"]
)
shared_b = bob.initial_dh_sk.exchange(
    ec.ECDH(), bob.certs["alice"]
)

assert shared_a == shared_b
assert b["RK"] == shared_a

from messenger import _kdf_root

expected_rk, expected_ck = _kdf_root(shared_a, shared_a)

assert a["RK"] == expected_rk
assert a["CKs"] == expected_ck
assert a["CKr"] is None
assert b["CKs"] is None
assert b["CKr"] is None

assert a["Ns"] == 0
assert a["Nr"] == 0
assert a["PN"] == 0

print("Step 3 session initialization tests passed!")

if TEST_STAGE == 3:
    raise SystemExit(0)

print("Testing sending ratchet")

from messenger import _kdf_chain, _header_aad
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Use separate test users so the original conversation
# is unaffected when we implement receiving later.
sender = MessengerClient("sender", server_sign_pk, server_enc_pk)
receiver = MessengerClient("receiver", server_sign_pk, server_enc_pk)

sender.generateCertificate()
receiver_cert = receiver.generateCertificate()
receiver_sig = server.signCert(receiver_cert)

sender.receiveCertificate(receiver_cert, receiver_sig)

state = sender._initialize_session("receiver", True)
old_ck = state["CKs"]

header, ciphertext = sender.sendMessage("receiver", "Hello!")

# Verify message numbering and sending-chain advancement.
assert header["n"] == 0
assert header["pn"] == 0
assert state["Ns"] == 1

expected_ck, message_key = _kdf_chain(old_ck)
assert state["CKs"] == expected_ck
assert state["CKs"] != old_ck

# Independently verify that the derived key decrypts the message.
plaintext = AESGCM(message_key).decrypt(
    bytes.fromhex(header["nonce"]),
    ciphertext,
    _header_aad("sender", "receiver", header),
)

assert plaintext.decode("utf-8") == "Hello!"

print("Step 4 sending ratchet tests passed!")

if TEST_STAGE == 4:
    raise SystemExit(0)

print("Testing Step 5: receiving chain")

first_sender = MessengerClient(
    "first_sender", server_sign_pk, server_enc_pk
)
first_receiver = MessengerClient(
    "first_receiver", server_sign_pk, server_enc_pk
)

sa_cert = first_sender.generateCertificate()
rb_cert = first_receiver.generateCertificate()

first_sender.receiveCertificate(
    rb_cert, server.signCert(rb_cert)
)
first_receiver.receiveCertificate(
    sa_cert, server.signCert(sa_cert)
)

# Test 1: Initial message decryption.
h1, c1 = first_sender.sendMessage(
    "first_receiver", "One-way hello!"
)

assert first_receiver.receiveMessage(
    "first_sender", h1, c1
) == "One-way hello!"

recv_state = first_receiver.conns["first_sender"]

assert recv_state["Nr"] == 1
assert recv_state["CKr"] is not None
assert recv_state["CKs"] is not None
assert recv_state["DHs"] is not first_receiver.initial_dh_sk

print("Initial message decrypted successfully!")

# Test 2: Second message.
h2, c2 = first_sender.sendMessage(
    "first_receiver", "Second message"
)

assert first_receiver.receiveMessage(
    "first_sender", h2, c2
) == "Second message"

assert recv_state["Nr"] == 2

print("Second message decrypted successfully!")

# Test 3: Reject replayed messages.
before_ck = recv_state["CKr"]

assert first_receiver.receiveMessage(
    "first_sender", h2, c2
) is None

assert recv_state["CKr"] == before_ck
assert recv_state["Nr"] == 2

print("Replay rejected successfully!")

# Test 4: Reject tampered ciphertext.
h3, c3 = first_sender.sendMessage(
    "first_receiver", "Untampered text"
)

bad_ct = bytearray(c3)
bad_ct[-1] ^= 1

assert first_receiver.receiveMessage(
    "first_sender", h3, bytes(bad_ct)
) is None

assert recv_state["CKr"] == before_ck
assert recv_state["Nr"] == 2

# The valid message must still decrypt afterward.
assert first_receiver.receiveMessage(
    "first_sender", h3, c3
) == "Untampered text"

assert recv_state["Nr"] == 3

print("Tampered ciphertext rejected successfully!")
print("Step 5 receiving chain tests passed!")

if TEST_STAGE == 5:
    raise SystemExit(0)

print("Testing Step 6: two-way DH ratcheting")

chat_a = MessengerClient("chat_a", server_sign_pk, server_enc_pk)
chat_b = MessengerClient("chat_b", server_sign_pk, server_enc_pk)

cert_a = chat_a.generateCertificate()
cert_b = chat_b.generateCertificate()

chat_a.receiveCertificate(cert_b, server.signCert(cert_b))
chat_b.receiveCertificate(cert_a, server.signCert(cert_a))

# Alice sends two messages.
h1, c1 = chat_a.sendMessage("chat_b", "First")
assert chat_b.receiveMessage("chat_a", h1, c1) == "First"

h2, c2 = chat_a.sendMessage("chat_b", "Second")
assert chat_b.receiveMessage("chat_a", h2, c2) == "Second"

# Bob replies with a new DH public key.
h3, c3 = chat_b.sendMessage("chat_a", "Reply 1")
assert h3["n"] == 0
assert chat_a.receiveMessage("chat_b", h3, c3) == "Reply 1"

# Bob continues the same sending chain.
h4, c4 = chat_b.sendMessage("chat_a", "Reply 2")
assert chat_a.receiveMessage("chat_b", h4, c4) == "Reply 2"

# Alice replies, triggering another DH ratchet.
h5, c5 = chat_a.sendMessage("chat_b", "Reply back")
assert h5["pn"] == 2
assert h5["n"] == 0
assert chat_b.receiveMessage("chat_a", h5, c5) == "Reply back"

# Tamper with a new ratchet header.
h6, c6 = chat_b.sendMessage("chat_a", "Another reply")

before = chat_a.conns["chat_b"].copy()

bad_header = dict(h6)
bad_header["dh"] = h5["dh"]

assert chat_a.receiveMessage("chat_b", bad_header, c6) is None
assert chat_a.conns["chat_b"] == before

# A failed message must not prevent legitimate decryption.
assert chat_a.receiveMessage("chat_b", h6, c6) == "Another reply"

print("Step 6 DH ratchet tests passed!")

if TEST_STAGE == 6:
    raise SystemExit(0)

print("Testing a conversation")
header, ct = alice.sendMessage("bob", "Hi Bob!")
msg = bob.receiveMessage("alice", header, ct)
if msg != "Hi Bob!":
    error("message 1 was not decrypted correctly")

header, ct = alice.sendMessage("bob", "Hi again Bob!")
msg = bob.receiveMessage("alice", header, ct)
if msg != "Hi again Bob!":
    error("message 2  was not decrypted correctly")

header, ct = bob.sendMessage("alice", "Hey Alice!")
msg = alice.receiveMessage("bob", header, ct)
if msg != "Hey Alice!":
    error("message 3 was not decrypted correctly")

header, ct = bob.sendMessage("alice", "Can't talk now")
msg = alice.receiveMessage("bob", header, ct)
if msg != "Can't talk now":
    error("message 4 was not decrypted correctly")

header, ct = bob.sendMessage("alice", "Started the homework too late :(")
msg = alice.receiveMessage("bob", header, ct)
if msg != "Started the homework too late :(":
    error("message 5 was not decrypted correctly")

header, ct = alice.sendMessage("bob", "Ok, bye Bob!")
msg = bob.receiveMessage("alice", header, ct)
if msg != "Ok, bye Bob!":
    error("message 6  was not decrypted correctly")

header, ct = bob.sendMessage("alice", "I'll remember to start early next time!")
msg = alice.receiveMessage("bob", header, ct)
if msg != "I'll remember to start early next time!":
    error("message 7 was not decrypted correctly")

print("conversation completed!")


print("Testing handling an incorrect message")

h, c = alice.sendMessage("bob", "malformed message test")
m = bob.receiveMessage("alice", h, ct)
if m != None:
    error("didn't reject incorrect message")
else:
    print("success!")


print("Testing complete")
