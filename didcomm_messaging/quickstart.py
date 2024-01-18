from typing import Optional, Dict, List, Any, Union, Callable, Awaitable, Sequence
import aiohttp
import attr, attrs
import json
import logging
import uuid

from did_peer_2 import KeySpec, generate
from pydid.did import DID
from pydid import DIDDocument

from aries_askar import Key, KeyAlg
from didcomm_messaging import DIDCommMessaging
from didcomm_messaging.crypto.backend.askar import AskarCryptoService, AskarSecretKey
from didcomm_messaging.crypto.backend.basic import InMemorySecretsManager
from didcomm_messaging.multiformats import multibase, multicodec
from didcomm_messaging.packaging import PackagingService
from didcomm_messaging.resolver import PrefixResolver
from didcomm_messaging.resolver.peer import Peer2, Peer4
from didcomm_messaging.routing import RoutingService

JSON_OBJ = Dict[str, Any]
Attachment = JSON_OBJ
JSON_VALUE = Union[None, str, int, bool, float, JSON_OBJ, List[Any]]

LOG = logging.getLogger(__name__)

@attr.s(auto_attribs=True)
class Message:
    """Provide a nicer interface for messages than just Dictionaries"""

    type: str
    body: JSON_OBJ
    id: Optional[str] = None
    typ: Optional[str] = "application/didcomm-plain+json"
    frm: Optional[DID] = None
    to: Optional[List[DID]] = None
    lang: Optional[str] = None
    created_time: Optional[int] = None
    expires_time: Optional[int] = None
    thid: Optional[str] = None
    pthid: Optional[str] = None
    please_ack: Optional[List[str]] = None
    ack: Optional[List[str]] = None

    # TODO: better implement/support these fields
    attachments: Optional[List[Attachment]] = None
    #from_prior: Optional[JWT] = None

    # TODO: Add message validation for spec-defined fields

    def __attrs_post_init__(self):
        #super().__init__(*args, **kwargs)
        if self.id is None:
            self.id = str(uuid.uuid4())

    def as_dict(self):
        return attrs.asdict(self, filter=(lambda _, x: not x is None))

    @classmethod
    def from_json(cls, data):
        data = json.loads(data)
        if "from" in data:
            data["frm"] = data["from"]
            del data["from"]
        return cls(**data)


class CompatibilityPrefixResolver(PrefixResolver):
    """Provide backwards compatibility with older DID methods.

    This will be removed in the future, as the intent is for agents to follow
    the did:peer:2 spec. The CompatibilityPrefixResolver allows for interaction
    with agents that are using the old #key-byte-prefix. Once this changes,
    this class will be removed.

    If you don't need this, it is recommended that you just use the
    PrefixResolver directly.
    """

    async def resolve_and_parse(self, did: str) -> DIDDocument:
        """Resolve a DID and parse the DID document."""
        doc = await self.resolve(did)
        #return DIDDocument.deserialize(doc)
        id_map = {}
        def set_id(method):
            new_id = method["publicKeyMultibase"][1:9]
            id_map[method["id"]] = new_id
            method["id"] = did + "#" + new_id
            return method
        doc["verificationMethod"] = [
            set_id(method) for method in doc["verificationMethod"]
        ]
        doc["authentication"] = [
            did + "#" + id_map.get(id) for id in doc["authentication"]
        ]
        doc["keyAgreement"] = [did + "#" + id_map.get(id) for id in doc["keyAgreement"]]
        return DIDDocument.deserialize(doc)


def generate_did():
    """Use Askar to generate encryption/verification keys, then a DID from both."""

    verkey = Key.generate(KeyAlg.ED25519)
    xkey = Key.generate(KeyAlg.X25519)
    did = generate(
        [
            KeySpec.verification(
                multibase.encode(
                    multicodec.wrap("ed25519-pub", verkey.get_public_bytes()),
                    "base58btc",
                )
            ),
            KeySpec.key_agreement(
                multibase.encode(
                    multicodec.wrap("x25519-pub", xkey.get_public_bytes()), "base58btc"
                )
            ),
        ],
        [
            {
                "type": "DIDCommMessaging",
                "serviceEndpoint": {
                    "uri": "didcomm:transport/queue",
                    "accept": [
                        "didcomm/v2"
                    ],
                    "routingKeys": []
                }
            }
        ],
    )
    return did, (verkey, xkey)


async def setup_default(did, did_secrets, enable_compatibility_prefix=False):

    # The Crypto Service is used to encrypt, decrypt, sign and verify messages.
    # Askar is a pretty solid choice for these tasks.
    crypto = AskarCryptoService()

    # The secrets manager is used to hold the private encryption/signing keys
    # to a DID and provide a mapping from the public keys to the private keys.
    # The keys are primarily used by the crypto service when the packaging
    # service is packing/unpacking a signed/encrypted message
    secrets = InMemorySecretsManager()

    # The Resolver is used to turn a DID into a valid DID Document.
    # DIDDocuments contain the public keys of the DID, as well as provide an
    # endpoint in which a message can be sent to. DIDDocuments can refer to a
    # DID as their endpoint, in which case, that DID will also be unwrapped
    # into it's own DIDDocument.
    #
    # At present, the PrefixResolver is used to determine which library should
    # be used to convert a DID into a DIDDocument.
    if enable_compatibility_prefix:
        resolver = CompatibilityPrefixResolver({"did:peer:2": Peer2(), "did:peer:4": Peer4()})
    else:
        resolver = PrefixResolver({"did:peer:2": Peer2(), "did:peer:4": Peer4()})

    # The Packaging Service is where a lot of the magic happens. Similar to a
    # shipping box, the PackagingService will "pack" and "unpack" an encrypted
    # message. When packing a message, the PackagingService will encrypt the
    # message to a single target, however. If the message needs to be forwarded
    # (because the recipient is behind a relay), then those messages will need
    # to be handled by the RoutingService.
    packer = PackagingService(
        resolver, crypto, secrets
    )

    # The RoutingService handles the routing of messages through relays. When a
    # message needs to be forwarded, the RoutingService will handle wrapping
    # each encrypted message within a forward message. The built-in
    # RoutingService allows for multiple levels of relays, so you don't need to
    # worry about how a message is routed to the recipient.
    router = RoutingService(packaging=packer, resolver=resolver)

    # Once everything is setup, we need to store the DID Secrets within the
    # SecretsService. We do this by taking the secrets that were passed in,
    # converting them to AskarSecretKey objects (since we are using the
    # AskarCryptoService), then we associate them with the public key lookup
    # value that will be sent to us.
    verkey, xkey = did_secrets
    await secrets.add_secret(AskarSecretKey(verkey, f"{did}#key-1"))
    await secrets.add_secret(AskarSecretKey(xkey, f"{did}#key-2"))

    # These can be removed once all keys being sent/received are in #key-N
    # format. They basically do the same as above, except with the same public
    # keys that are returned from the CompatibilityPrefixResolver.
    doc = await resolver.resolve_and_parse(did)
    await secrets.add_secret(AskarSecretKey(verkey, doc.authentication[0]))
    await secrets.add_secret(AskarSecretKey(xkey, doc.key_agreement[0]))

    # Finally, we put it all together in the DIDCommMessaging class. The
    # DIDCommMessaging handles the orchestration of each individual service,
    # ensuring that messages get packed and delivered via a simple and straight
    # forward interface.
    DMP = DIDCommMessaging(crypto=crypto, secrets=secrets, resolver=resolver, packaging=packer, routing=router)

    return DMP


async def send_http_message(
    dmp: DIDCommMessaging, my_did: DID, message: Message, target: DID
):

    # Get the message as a dictionary
    message_wrapper = message
    message = message_wrapper.as_dict()

    # Encrypt/pack the message to our target
    packy = await dmp.pack(
        message=message,
        to=target,
        frm=my_did,
    )
    packed = packy.message

    # Get the first http endpoint from the last DID in the DID chain
    endpoint = packy.get_endpoint("http")

    async with aiohttp.ClientSession() as session:
        LOG.info("posting message type %s to %s" % (message_wrapper.type, endpoint))

        async with session.post(endpoint, data=packed) as resp:
            LOG.debug("posted message: %s" % (message))
            LOG.debug("message ID: %s" % (message_wrapper.id))
            packed = await resp.text()

            # If the HTTP enpoint responded with a message, decode it
            if len(packed) > 0:
                unpacked = await dmp.packaging.unpack(packed)
                msg = unpacked[0].decode()
                LOG.debug("Raw message from remote %s" % msg)
                return Message.from_json(msg)
    return


async def setup_relay(
    dmp: DIDCommMessaging, my_did: DID, relay_did: DID, keys: Sequence[Key]
) -> Union[DID, None]:

    # Request mediation from the outbound relay
    message = Message(
        type="https://didcomm.org/coordinate-mediation/3.0/mediate-request",
        id=str(uuid.uuid4()),
        body={},
        frm=my_did,
        to=[relay_did],
    )
    message = await send_http_message(dmp, my_did, message, target=relay_did)

    # Verify that mediation-access has been granted
    if message.type == "https://didcomm.org/coordinate-mediation/3.0/mediate-deny":
        return
    if message.type != "https://didcomm.org/coordinate-mediation/3.0/mediate-grant":
        # We shouldn't run into this case, but it's possible
        raise Exception("Unknown response type received: %s" % message.type)

    # Create a new DID with an updated service endpoint, pointing to our relay
    relay_did = message.body["routing_did"][0]
    new_did = generate(
        keys,
        [
            {
                "type": "DIDCommMessaging",
                "serviceEndpoint": {
                    "uri": relay_did,
                    "accept": ["didcomm/v2"],
                },
            }
        ],
    )
    LOG.info("relayed did: ", new_did)

    # A couple of helpers variables to simplify the next few lines
    resolver = dmp.resolver
    secrets = dmp.secrets

    # Add the DID to our secrets manager so that we can unpack messages
    # destined to us via our new DID
    doc = await resolver.resolve_and_parse(new_did)
    # New format, key-# is in order of keys in did
    await secrets.add_secret(AskarSecretKey(keys[0], f"{new_did}#key-1"))
    await secrets.add_secret(AskarSecretKey(keys[1], f"{new_did}#key-2"))

    # Legacy formats
    await secrets.add_secret(AskarSecretKey(verkey, doc.authentication[0]))
    await secrets.add_secret(AskarSecretKey(xkey, doc.key_agreement[0]))

    # Send a message to the relay informing it of our new endpoint that people
    # should contact us by
    message = Message(
       type="https://didcomm.org/coordinate-mediation/3.0/recipient-update",
       id=str(uuid.uuid4()),
       body={
           "updates": [
               {
                   "recipient_did": new_did,
                   "action": "add",
               },
           ],
       },
       frm=my_did,
       to=[relay_did],
    )
    message = await send_http_message(dmp, my_did, message, target=relay_did)

    return new_did


async def fetch_relayed_messages(
    dmp: DIDCommMessaging,
    my_did: DID,
    relay_did: DID,
    callback: Callable[[Message], Awaitable[None]] = None,
) -> List[Message]:

    # Fetch a count of all stored messages
    message = Message(
        type="https://didcomm.org/messagepickup/3.0/status-request",
        id=str(uuid.uuid4()),
        body={},
        frm=my_did,
        to=[relay_did],
    )
    message = await send_http_message(dmp, my_did, message, target=relay_did)

    # If there's no messages, we can return early
    if message.body["message_count"] == 0:
        return []

    # Request messages that are stored at the relay, according to the
    # message_count returned in the previous call
    message = Message(
        type="https://didcomm.org/messagepickup/3.0/delivery-request",
        id=str(uuid.uuid4()),
        body={
            "limit": message.body["message_count"],
        },
        frm=my_did,
        to=[relay_did],
    )
    message = await send_http_message(dmp, my_did, message, target=relay_did)

    # Handle each stored message is order we receive it
    for attach in message.attachments:
        logger.info("Received message %s", attach["id"][:-58])

        # Decrypt/Unpack the encrypted message attachment
        unpacked = await dmp.packaging.unpack(json.dumps(attach["data"]["json"]))
        msg = unpacked.message
        msg = Message.from_json(msg)

        # Call callback if it exists, passing the message in
        if callback:
            await callback(msg)

        if msg.type == "https://didcomm.org/basicmessage/2.0/message":
            logmsg = msg.body['content'].replace('\n', ' ').replace('\r', '')
            logger.info(f"Got message: {logmsg}")

        message = Message(
            type="https://didcomm.org/messagepickup/3.0/messages-received",
            id=str(uuid.uuid4()),
            body={
                "message_id_list": [msg.id for msg in message.attachments],
            },
            frm=my_did,
            to=[relay_did],
        )
        await send_http_message(dmp, my_did, message, target=relay_did)
