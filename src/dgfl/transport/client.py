"""mTLS plus authenticated, confidential role RPC; exact retry is idempotent."""
import hashlib
import ssl
import tempfile
import threading
import time
import uuid
from pathlib import Path

import httpx

from dgfl.transport.binary import CanonicalPayload, unpack_from

from .chunking import (
    CHUNK_ACTION,
    CHUNK_BYTES,
    DOWNLOAD_ACTION,
    DOWNLOAD_COMPLETE_ACTION,
    DOWNLOAD_MARKER,
    MAX_CHUNKS,
    MAX_TOTAL_BYTES,
    SEND_THRESHOLD,
    EncodedMessage,
)
from .security import Identity

MAX_RESPONSE_BYTES = 64 * 1024 * 1024


class _PreparedMessage(dict):
    """One explicit local request snapshot; not a cache keyed by mutable data."""

    def __init__(self, message, encoded):
        super().__init__(message)
        self.encoded = encoded
        self.action = message['action']


class RPCClient:
    def prepare_payload(self,payload):
        """Reuse a bounded public snapshot; large bodies retain streamed encoding."""
        with EncodedMessage(payload,directory=getattr(self,'spool_dir',None),
                            memory_limit=SEND_THRESHOLD) as body:
            return body.canonical_payload() if body.size<=SEND_THRESHOLD else payload

    def __init__(self,runtime,nodes):
        self.identity=Identity(runtime/'keys','coordinator'); self.nodes=nodes; self.bytes_sent=0; self._counter_lock=threading.Lock()
        self.spool_dir=Path(runtime)/'nodes'/'coordinator'/'rpc-spool'
        self.spool_dir.mkdir(parents=True,exist_ok=True)
        context=ssl.create_default_context(cafile=str(runtime/'keys'/'ca.pem'))
        context.verify_flags|=ssl.VERIFY_X509_STRICT
        context.load_cert_chain(runtime/'keys'/'coordinator'/'tls.pem',runtime/'keys'/'coordinator'/'tls-key.pem')
        self.client=httpx.Client(verify=context,timeout=httpx.Timeout(600,connect=5),trust_env=False)

    def call(self,node,action,payload=None,*,retries=1,timeout=None):
        """Send one logical request, splitting it when it exceeds one RPC body."""
        message={'action':action,'payload':payload or {}}
        with EncodedMessage(message,directory=getattr(self,'spool_dir',None),
                            memory_limit=SEND_THRESHOLD) as body:
            if body.size<=SEND_THRESHOLD:
                prepared = _PreparedMessage(message,body.canonical_payload(max_bytes=SEND_THRESHOLD))
                return self._exchange(node,prepared,retries,timeout)
            total=(body.size+CHUNK_BYTES-1)//CHUNK_BYTES
            if total>MAX_CHUNKS:
                raise ValueError('chunk count outside the configured limit')
            result=None
            for index in range(total):
                spec={'action':action,'digest':body.digest,'index':index,'total':total,
                      'data':body.file.read(CHUNK_BYTES)}
                result=self._exchange(node,{'action':CHUNK_ACTION,'payload':spec},retries,timeout)
            if isinstance(result,dict) and set(result)=={'chunk','received','total'}:
                raise ValueError('chunked request did not complete; no action result was returned')
            return result

    def _download(self,node,descriptor,request_id,fingerprint,retries,timeout):
        fields={'version','token','request_id','request_fingerprint','digest','bytes','total','chunk_bytes'}
        if not isinstance(descriptor,dict) or set(descriptor)!=fields:
            raise ValueError('invalid response transfer manifest')
        def hex_digest(value):
            return isinstance(value,str) and len(value)==64 and all(c in '0123456789abcdef' for c in value)
        size,total,width=descriptor['bytes'],descriptor['total'],descriptor['chunk_bytes']
        if (type(descriptor['version']) is not int or descriptor['version'] not in (1,2)
                or descriptor['request_id']!=request_id or descriptor['request_fingerprint']!=fingerprint
                or not hex_digest(descriptor['token']) or not hex_digest(descriptor['digest'])
                or type(size) is not int or not 0<size<=MAX_TOTAL_BYTES
                or type(width) is not int or not 0<width<=CHUNK_BYTES
                or type(total) is not int or not 1<=total<=MAX_CHUNKS
                or total!=(size+width-1)//width):
            raise ValueError('response transfer manifest does not match its original request or limits')
        base={key:descriptor[key] for key in ('token','request_id','request_fingerprint','digest')}
        if descriptor['version'] == 2:
            base['download_id'] = uuid.uuid4().hex
        digest=hashlib.sha256()
        # One request and one disk block at a time: no unbounded download queue.
        with tempfile.TemporaryFile(dir=getattr(self,'spool_dir',None)) as stream:
            for index in range(total):
                spec={**base,'index':index}
                block=self._exchange(node,{'action':DOWNLOAD_ACTION,'payload':spec},retries,timeout)
                expected={**spec,**{key:descriptor[key] for key in ('bytes','total','chunk_bytes')}}
                if (not isinstance(block,dict) or set(block)!=set(expected)|{'data'}
                        or any(type(block[key]) is not type(value) or block[key]!=value for key,value in expected.items())
                        or not isinstance(block['data'],bytes)
                        or len(block['data'])!=min(width,size-index*width)):
                    raise ValueError('response chunk does not match its transfer manifest')
                stream.write(block['data'])
                digest.update(block['data'])
            if digest.hexdigest()!=descriptor['digest']:
                raise ValueError('downloaded response does not match its digest')
            stream.seek(0)
            result = unpack_from(stream)
        if descriptor['version'] == 2:
            # This is cache housekeeping after the result is fully verified.
            # A lost acknowledgement must not turn a delivered action into a
            # failure or cause its business logic to be repeated. Retaining its
            # response until expiry is the safe fallback if acknowledgement fails.
            try:
                acknowledgement = self._exchange(node, {'action': DOWNLOAD_COMPLETE_ACTION, 'payload': base}, retries, timeout)
                if acknowledgement != {**base, 'completed': True}:
                    raise ValueError('response completion acknowledgement does not match its download')
            except (httpx.HTTPError, ValueError):
                pass
        return result

    def _exchange(self,node,message,retries,timeout):
        request_id=uuid.uuid4().hex
        if isinstance(message,_PreparedMessage):
            encoded,action=message.encoded,message.action
        else:
            encoded,action=CanonicalPayload(message),message['action']
        body=self.identity.seal_encoded(node,'rpc',encoded,request_id)
        endpoint=self.nodes[node]['url']+'/rpc'
        for attempt in range(retries+1):
            try:
                with self._counter_lock: self.bytes_sent+=len(body)
                with self.client.stream('POST',endpoint,content=body,
                        headers={'Content-Type':'application/octet-stream','Accept-Encoding':'identity'},
                        **({'timeout':timeout} if timeout is not None else {})) as response:
                    if response.headers.get('content-encoding','identity')!='identity':
                        raise ValueError('RPC response must use uncompressed authenticated frames')
                    frame=bytearray()
                    for piece in response.iter_bytes(chunk_size=65536):
                        with self._counter_lock: self.bytes_sent+=len(piece)
                        if len(frame)+len(piece)>MAX_RESPONSE_BYTES:
                            raise ValueError('RPC response frame exceeds the configured size limit')
                        frame.extend(piece)
                    status=response.status_code
                if status!=200:
                    detail=bytes(frame[:200]).decode('utf8',errors='replace')
                    raise ValueError(f'{node}/{action}: {status} {detail}')
                result=self.identity.open(bytes(frame),'rpc-response',request_id,node)['payload']
                if isinstance(result,dict) and set(result)=={DOWNLOAD_MARKER}:
                    if action in (DOWNLOAD_ACTION, DOWNLOAD_COMPLETE_ACTION):
                        raise ValueError('response download cannot contain another transfer manifest')
                    return self._download(node,result[DOWNLOAD_MARKER],request_id,encoded.digest,retries,timeout)
                return result
            except (httpx.TimeoutException,httpx.NetworkError):
                if attempt>=retries: raise
                time.sleep(.2)

    def close(self): self.client.close()
