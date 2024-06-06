"""Quickstart helpers for beginner users of DIDComm."""

from typing import (
    Optional,
    Dict,
    List,
    Any,
    Union,
    Callable,
    Awaitable,
    Tuple,
)
import aiohttp
import json
import logging
import uuid

from did_peer_2 import KeySpec, generate
from pydid.did import DID

from aries_askar import Key, KeyAlg
from didcomm_messaging import DIDCommMessaging
from didcomm_messaging.crypto.backend.askar import AskarCryptoService, AskarSecretKey
from didcomm_messaging.crypto.backend.basic import InMemorySecretsManager
from didcomm_messaging.multiformats import multibase, multicodec
from didcomm_messaging.packaging import PackagingService
from didcomm_messaging.resolver import PrefixResolver
from didcomm_messaging.resolver.web import DIDWeb
from didcomm_messaging.resolver.peer import Peer2, Peer4
from didcomm_messaging.routing import RoutingService

JSON_OBJ = Dict[str, Any]
Attachment = JSON_OBJ
JSON_VALUE = Union[None, str, int, bool, float, JSON_OBJ, List[Any]]

LOG = logging.getLogger(__name__)


def generate_did() -> Tuple[DID, Tuple[Key, Key]]:
    """Use Askar to generate encryption/verification keys, then return a DID from both."""

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
                    "accept": ["didcomm/v2"],
                    "routingKeys": [],
                },
            }
        ],
    )
    return did, (verkey, xkey)


async def setup_default(did: DID, did_secrets: Tuple[Key, Key]) -> DIDCommMessaging:
    """Setup a pre-configured DIDCommMessaging instance."""

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
    resolver = PrefixResolver(
        {
            "did:peer:2": Peer2(),
            "did:peer:4": Peer4(),
            "did:web:": DIDWeb(),
        }
    )

    # The Packaging Service is where a lot of the magic happens. Similar to a
    # shipping box, the PackagingService will "pack" and "unpack" an encrypted
    # message. When packing a message, the PackagingService will encrypt the
    # message to a single target, however. If the message needs to be forwarded
    # (because the recipient is behind a relay), then those messages will need
    # to be handled by the RoutingService.
    packer = PackagingService()

    # The RoutingService handles the routing of messages through relays. When a
    # message needs to be forwarded, the RoutingService will handle wrapping
    # each encrypted message within a forward message. The built-in
    # RoutingService allows for multiple levels of relays, so you don't need to
    # worry about how a message is routed to the recipient.
    router = RoutingService()

    # Once everything is setup, we need to store the DID Secrets within the
    # SecretsService. We do this by taking the secrets that were passed in,
    # converting them to AskarSecretKey objects (since we are using the
    # AskarCryptoService), then we associate them with the public key lookup
    # value that will be sent to us.
    verkey, xkey = did_secrets
    await secrets.add_secret(AskarSecretKey(verkey, f"{did}#key-1"))
    await secrets.add_secret(AskarSecretKey(xkey, f"{did}#key-2"))

    # Finally, we put it all together in the DIDCommMessaging class. The
    # DIDCommMessaging handles the orchestration of each individual service,
    # ensuring that messages get packed and delivered via a simple and straight
    # forward interface.
    DMP = DIDCommMessaging(
        crypto=crypto,
        secrets=secrets,
        resolver=resolver,
        packaging=packer,
        routing=router,
    )

    return DMP


async def send_http_message(
    dmp: DIDCommMessaging, my_did: DID, message: Dict[str, Any], target: DID
) -> Optional[Dict[str, Any]]:
    """Send a message via HTTP."""

    # Ensure an ID is on the message
    if "id" not in message or not message["id"]:
        message["id"] = str(uuid.uuid4())

    # Ensure that a typ is on the message
    if "typ" not in message or not message["typ"]:
        message["typ"] = "application/didcomm-plain+json"

    # Ensure that a return-route is on the message
    if "return_route" not in message or not message["return_route"]:
        message["return_route"] = "all"

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
        LOG.info("posting message type %s to %s", message["type"], endpoint)

        async with session.post(endpoint, data=packed) as resp:
            # Get the message from the response and prepare for decryption
            packed = await resp.text()

            # Dump useful information about the message
            LOG.debug("posted message: %s", message)
            LOG.debug("message ID: %s", message["id"])
            LOG.debug("response code: %s", resp.status)
            LOG.debug("response message: %s", packed)

            # Raise an exception if the destination did not return success
            if resp.status != 200:
                raise Exception(
                    "Destination responded with error: code=%s message=%s"
                    % (resp.status, packed)
                )

            # If the HTTP enpoint responded with a message, decode it
            if len(packed) > 0:
                unpacked = await dmp.unpack(packed)
                msg = unpacked.message
                LOG.debug("Raw message from remote %s", msg)
                return msg
    return


async def setup_relay(
    dmp: DIDCommMessaging, my_did: DID, relay_did: DID, verkey: Key, xkey: Key
) -> Union[DID, None]:
    """Negotiate services with an inbound relay.

    Returns a DID upon successful negotiation.
    """

    # Request mediation from the inbound relay
    message = {
        "type": "https://didcomm.org/coordinate-mediation/3.0/mediate-request",
        "id": str(uuid.uuid4()),
        "body": {},
        "from": my_did,
        "to": [relay_did],
    }
    message = await send_http_message(dmp, my_did, message, target=relay_did)

    # Verify that mediation-access has been granted
    if message["type"] == "https://didcomm.org/coordinate-mediation/3.0/mediate-deny":
        return
    if message["type"] != "https://didcomm.org/coordinate-mediation/3.0/mediate-grant":
        # We shouldn't run into this case, but it's possible
        raise Exception("Unknown response type received: %s" % message["type"])

    # Create a new DID with an updated service endpoint, pointing to our relay
    relay_did = message["body"]["routing_did"][0]
    new_did = generate(
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
                    "uri": relay_did,
                    "accept": ["didcomm/v2"],
                },
            }
        ],
    )
    LOG.info("relayed did: %s", new_did)

    # A couple of helpers variables to simplify the next few lines
    resolver = dmp.resolver
    secrets = dmp.secrets

    # Add the DID to our secrets manager so that we can unpack messages
    # destined to us via our new DID
    doc = await resolver.resolve_and_parse(new_did)
    # New format, key-# is in order of keys in did
    await secrets.add_secret(AskarSecretKey(verkey, f"{new_did}#key-1"))
    await secrets.add_secret(AskarSecretKey(xkey, f"{new_did}#key-2"))

    # Legacy formats
    # verkey
    await secrets.add_secret(AskarSecretKey(verkey, doc.authentication[0]))
    # xkey
    await secrets.add_secret(AskarSecretKey(xkey, doc.key_agreement[0]))

    # Send a message to the relay informing it of our new endpoint that people
    # should contact us by
    message = {
        "type": "https://didcomm.org/coordinate-mediation/3.0/recipient-update",
        "id": str(uuid.uuid4()),
        "body": {
            "updates": [
                {
                    "recipient_did": new_did,
                    "action": "add",
                },
            ],
        },
        "from": my_did,
        "to": [relay_did],
    }
    message = await send_http_message(dmp, my_did, message, target=relay_did)

    return new_did


async def _message_callback(msg: Dict[str, Any]) -> None:
    if msg["type"] == "https://didcomm.org/basicmessage/2.0/message":
        logmsg = msg.body["content"].replace("\n", " ").replace("\r", "")
        LOG.info("Got message: %s", logmsg)


async def fetch_relayed_messages(
    dmp: DIDCommMessaging,
    my_did: DID,
    relay_did: DID,
    callback: Callable[[Dict[str, Any]], Awaitable[None]] = _message_callback,
) -> None:
    """Fetch stored messages from the relay."""

    # Fetch a count of all stored messages
    message = {
        "type": "https://didcomm.org/messagepickup/3.0/status-request",
        "id": str(uuid.uuid4()),
        "body": {},
        "from": my_did,
        "to": [relay_did],
    }
    message = await send_http_message(dmp, my_did, message, target=relay_did)

    # If there's no messages, we can return early
    if message["body"]["message_count"] == 0:
        return []

    # Request messages that are stored at the relay, according to the
    # message_count returned in the previous call
    message = {
        "type": "https://didcomm.org/messagepickup/3.0/delivery-request",
        "id": str(uuid.uuid4()),
        "body": {
            "limit": message["body"]["message_count"],
        },
        "from": my_did,
        "to": [relay_did],
    }
    message = await send_http_message(dmp, my_did, message, target=relay_did)

    # Handle each stored message is order we receive it
    for attach in message["attachments"]:
        LOG.info("Received message %s", attach["id"][:-58])

        # Decrypt/Unpack the encrypted message attachment
        unpacked = await dmp.unpack(json.dumps(attach["data"]["json"]))
        msg = unpacked.message

        # Call callback if it exists, passing the message in
        if callback:
            await callback(msg)

    message = {
        "type": "https://didcomm.org/messagepickup/3.0/messages-received",
        "id": str(uuid.uuid4()),
        "body": {
            "message_id_list": [msg["id"] for msg in message["attachments"]],
        },
        "from": my_did,
        "to": [relay_did],
    }
    await send_http_message(dmp, my_did, message, target=relay_did)


# '##:::::'##:'########:'########:::'######:::'#######:::'######::'##:::'##:
#  ##:'##: ##: ##.....:: ##.... ##:'##... ##:'##.... ##:'##... ##: ##::'##::
#  ##: ##: ##: ##::::::: ##:::: ##: ##:::..:: ##:::: ##: ##:::..:: ##:'##:::
#  ##: ##: ##: ######::: ########::. ######:: ##:::: ##: ##::::::: #####::::
#  ##: ##: ##: ##...:::: ##.... ##::..... ##: ##:::: ##: ##::::::: ##. ##:::
#  ##: ##: ##: ##::::::: ##:::: ##:'##::: ##: ##:::: ##: ##::: ##: ##:. ##::
# . ###. ###:: ########: ########::. ######::. #######::. ######:: ##::. ##:
# :...::...:::........::........::::......::::.......::::......:::..::::..::

# The following functions are used for establishing a persistant WebSocket
# connection with a mediator/relay. This allows messages to be delivered as
# soon as they arrive instead of waiting to be picked up with the pickup
# protocol.

# Because the quickstart can be used without using websockets or connecting to
# an inbound relay/mediator. If we don't have the necessary libraries, we can
# just raise a warning about the lack of support.
try:
    import websockets
    import asyncio
except ImportError:
    import warnings

    warnings.warn(
        "Missing websockets or asyncio import, live-delivery support will be unavailable",
        ImportWarning,
    )


async def handle_websocket(
    dmp: DIDCommMessaging,
    relay_did: DID,
    mediator_websocket: Awaitable["websockets.WebSocketClientProtocol"],
    live_delivery_message: bytes,
    callback: Callable[[Dict[str, Any]], Awaitable[None]] = _message_callback,
):
    """Loop over messages received and process them."""

    # Using async with on the websocket allows us to wait for then loop over
    # new messages that come in over the websocket.
    async with mediator_websocket as websocket:
        # Send our live-delivery request to the inbound relay.
        await websocket.send(live_delivery_message)
        LOG.debug("Connected to WebSocket and requested Live Delivery.")

        # Loop over all incoming messages
        while True:
            message = await websocket.recv()
            LOG.debug("Received message over websocket")

            try:
                # Unpack/Decrypt the message, decode it, and load the JSON into
                # a native python object.
                unpacked_message = await dmp.unpack(message)
                msg = unpacked_message.message
                LOG.debug("Received websocket message %s", msg["type"])

                # If the message is not from the relay, process it via the callback
                if msg["from"] != relay_did:
                    await callback(msg)

                # NOTE: While out of scope for this example, when implementing
                # your own handler, it's advisable to handle messages that come
                # from the relay. For example: the relay will respond to the
                # live-delivery call with a pickup protocol status message. The
                # status message may contain a message count that is greater
                # than zero. If there are messages that are waiting, it is
                # advisable to request the messages and process them.

            except Exception as err:
                LOG.error("Error encountered while decrypting websocket message")
                LOG.exception(err)

        # Clean up the websocket
        await websocket.close()


async def activate_websocket(
    dmp: DIDCommMessaging,
    my_did: DID,
    relay_did: DID,
    callback: Callable[[Dict[str, Any]], Awaitable[None]] = _message_callback,
    create_task: bool = False,
) -> Union[Awaitable[None], "asyncio.Task"]:
    """Connect to a websocket and request message forwarding."""

    # Construct a message to request live-delivery and pack it
    message = {
        "type": "https://didcomm.org/messagepickup/3.0/live-delivery-change",
        "id": str(uuid.uuid4()),
        "body": {
            "live_delivery": True,
        },
        "from": my_did,
        "to": [relay_did],
    }
    packed = await dmp.pack(
        message=message,
        to=relay_did,
        frm=my_did,
    )

    # Get the websocket endpoint from the packed message. This will pull out
    # the endpoint that is closest to us, the sender.
    endpoint = packed.get_endpoint("ws")
    LOG.debug("Relay Websocket Address: %s", endpoint)

    if endpoint:
        # Connect to the websocket and prepare our handler function
        mediator_websocket = websockets.connect(uri=endpoint)
        websocket_handler = handle_websocket(
            dmp,
            relay_did,
            mediator_websocket,
            packed.message,
            callback,
        )

        # Create an asyncio task upon request to run in another async "thread",
        # otherwise we'll just return the function that runs in the thread.
        if create_task:
            return asyncio.create_task(websocket_handler)
        else:
            return websocket_handler


async def websocket_loop(
    dmp: DIDCommMessaging,
    my_did: DID,
    relay_did: DID,
    callback: Callable[[Dict[str, Any]], Awaitable[None]] = _message_callback,
) -> None:
    """Run the websocket handler in a task and reconnect on failure."""

    # Helper method to create the async task
    async def create_task():
        return await activate_websocket(dmp, my_did, relay_did, callback, True)

    # Create the initial task
    mediator_websocket_proc = await create_task()

    # Check to make sure the thread is still running every 5 seconds (to give
    # the OS some breathing room). Should the thread "crash" or exit for any
    # reason, log any exceptions and attempt to restart it.
    while True:
        await asyncio.sleep(5)
        if mediator_websocket_proc.done():
            LOG.exception(mediator_websocket_proc.exception())
            LOG.error("Websocket died, re-establishing connection!")
            mediator_websocket_proc = await create_task()
