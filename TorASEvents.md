TorAS uses the standard ActionScript event model, so setting up listeners to TorControl or SOCKS5Tunnel instances is straightforward:

```
var torControl:TorControl=new TorControl();
torControl.addEventListener(TorControlEvent.ONAUTHENTICATE, onTorReady);
torControl.connect();

function onTorReady(eventObj:TorControlEvent):void {
   trace ("Tor control connection is authenticated and ready.");
}
```

```
var tunnel:SOCK5Tunnel = new SOCKS5Tunnel();
tunnel.addEventListener(SOCKS5TunnelEvent.ONHTTPRESPONSE, onSOCKSTunnelResponse);
tunnel.loadHTTP(request);       

function onSOCKSTunnelResponse(eventObj:SOCKS5TunnelEvent):void {
   trace ("Got response: ");
   trace (eventObj.httpResponse.body);
}
```

Additional examples can be found in the TorAS Developer document: https://code.google.com/p/toras/wiki/TorASDeveloperGuide


---


# `TorControl Events` #

The following events are broadcast by the TorControl instance:


**`TorControlEvent.ONCONNECT`** - Dispatched when the TorControl instance successfully connects to what is believed to be a Tor control socket. Until the ONAUTHENTICATE event is dispatched (and verified as a Tor connection), the socket is considered unavailable.


**`TorControlEvent.ONCONNECTERROR`** - Dispatched when the TorControl instance experiences an error connecting to the Tor control socket.  Error details are included in the event's _error_ object.


**`TorControlEvent.ONAUTHENTICATE`** - Dispatched when the Tor control connection has been authenticated and is ready to receive commands. For most applications, it's more useful to listen to this event rather than the ONCONNECT event.


**`TorControlEvent.ONRESPONSE`** - Dispatched when the Tor control connection responds to a synchronous response (for example, a _sendRawControlMessage_ call). The parsed response body will be included in the event's _body_ property, the response status code (similar to HTTP response status codes) will be included as the _status_ property, and the raw (unparsed) response will be included as the _rawMessage_ property.

### Asynchronous Tor Events ###

The following events are dispatched by the Tor process autonomously. Although TorAS dynamically binds to these events whenever listeners are assigned, it is not responsible for the event contents that Tor includes (the event _body_ property, for example).

For detailed information on the contents of each of the following Tor events, please see section 4 of the Tor Control Protocol v1 Specification: https://code.google.com/p/toras/wiki/TorControlProtocol_v1

**`TorControlEvent.ONLOGMSG`** - Dispatched whenever TorControl receives a Tor log message via STDOUT. This type of message will only ever be received if TorControl is used to start the Tor process. The Tor log message will be included in the event's _body_ property.


**`TorControlEvent.TOR_DEBUG`** - Dispatched when the Tor process dispatches an internal "DEBUG" event. The details of the event are included in the event object's _body_ property, and the raw (un-parsed) data received in the event is in the _rawMessage_ property. The Tor event name that was captured is included in the _torEvent_ property.


**`TorControlEvent.TOR_INFO`** - Dispatched when the Tor process dispatches an internal "INFO" event. The details of the event are included in the event object's _body_ property, and the raw (un-parsed) data received in the event is in the _rawMessage_ property. The Tor event name that was captured is included in the _torEvent_ property.


**`TorControlEvent.TOR_NOTICE`** - Dispatched when the Tor process dispatches an internal "NOTICE" event. The details of the event are included in the event object's _body_ property, and the raw (un-parsed) data received in the event is in the _rawMessage_ property. The Tor event name that was captured is included in the _torEvent_ property.


**`TorControlEvent.TOR_WARN`** - Dispatched when the Tor process dispatches an internal "WARN" event. The details of the event are included in the event object's _body_ property, and the raw (un-parsed) data received in the event is in the _rawMessage_ property. The Tor event name that was captured is included in the _torEvent_ property.


**`TorControlEvent.TOR_ERR`** - Dispatched when the Tor process dispatches an internal "ERR" event. The details of the event are included in the event object's _body_ property, and the raw (un-parsed) data received in the event is in the _rawMessage_ property. The Tor event name that was captured is included in the _torEvent_ property.


**`TorControlEvent.TOR_CIRC`** - Dispatched when the Tor process dispatches an internal "CIRC" event. The details of the event are included in the event object's _body_ property, and the raw (un-parsed) data received in the event is in the _rawMessage_ property. The Tor event name that was captured is included in the _torEvent_ property.

|More information on working with the TOR\_CIRC event, and with Tor circuits in general, can be found in the following Wiki entry: https://code.google.com/p/toras/wiki/TorASCircuits| ||
|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:|:|


**`TorControlEvent.TOR_STREAM`** - Dispatched when the Tor process dispatches an internal "STREAM" event. The details of the event are included in the event object's _body_ property, and the raw (un-parsed) data received in the event is in the _rawMessage_ property. The Tor event name that was captured is included in the _torEvent_ property.


**`TorControlEvent.TOR_ORCONN`** - Dispatched when the Tor process dispatches an internal "ORCONN" event. The details of the event are included in the event object's _body_ property, and the raw (un-parsed) data received in the event is in the _rawMessage_ property. The Tor event name that was captured is included in the _torEvent_ property.


**`TorControlEvent.TOR_BW`** - Dispatched when the Tor process dispatches an internal "BW" event. The details of the event are included in the event object's _body_ property, and the raw (un-parsed) data received in the event is in the _rawMessage_ property. The Tor event name that was captured is included in the _torEvent_ property.


**`TorControlEvent.TOR_NEWDESC`** - Dispatched when the Tor process dispatches an internal "NEWDESC" event. The details of the event are included in the event object's _body_ property, and the raw (un-parsed) data received in the event is in the _rawMessage_ property. The Tor event name that was captured is included in the _torEvent_ property.


**`TorControlEvent.TOR_AUTHDIR_NEWDESCS`** - Dispatched when the Tor process dispatches an internal "AUTHDIR\_NEWDESCS" event. The details of the event are included in the event object's _body_ property, and the raw (un-parsed) data received in the event is in the _rawMessage_ property. The Tor event name that was captured is included in the _torEvent_ property.


**`TorControlEvent.TOR_DESCCHANGED`** - Dispatched when the Tor process dispatches an internal "DESCCHANGED" event. The details of the event are included in the event object's _body_ property, and the raw (un-parsed) data received in the event is in the _rawMessage_ property. The Tor event name that was captured is included in the _torEvent_ property.

<sub>There are a number of additional asynchronous events that Tor dispatches which are not currently supported by TorAS. Since these support a variety of optional parameters, they have been excluded until a suitable way to include these parameters has been developed (so yes, they will be supported at some point).</sub>


---


# `SOCKS5Tunnel Events` #

The following events are broadcast by the SOCKS5Tunnel instance:


**`SOCKS5Tunnel.ONCONNECT`** - Dispatched when the SOCKS5Tunnel instance successfully connects to what is believed to be a Tor communications (SOCKS5) socket. During most successful requests, ONCONNECT is dispatched first, followed by ONAUTHENTICATE.


**`SOCKS5Tunnel.ONCONNECTERROR`** - Dispatched when the SOCKS5Tunnel instance experiences an error connecting to the Tor control socket. Error details are included in the event's _error_ object.


**`SOCKS5Tunnel.ONDISCONNECT`** - Dispatched when the SOCKS5Tunnel socket disconnects, either as the result of a local action, or because the connection was dropped remotely. Disconnection details are included in the event's _error_ object.


**`SOCKS5Tunnel.ONAUTHENTICATE`** - Dispatched when the SOCKS5 tunnel connection has been authenticated and is ready to receive commands. Most of the time this event is followed by the actual tunneled request itself.


**`SOCKS5Tunnel.ONHTTPSTATUS`** - Dispatched when the SOCKS5 tunnel has received enough information from a _loadHTTP_ call to parse the response status information. This includes items like the response status code (200, 301, 404, etc.), protocol ("HTTP/1.1", for example), and status information string, which are included in the event's _httpResponse_ object.


**`SOCKS5Tunnel.ONHTTPHEADERS`** - Dispatched when the SOCKS5 tunnel has received enough information from a _loadHTTP_ call to parse the response header. Typically this will follow an ONHTTPSTATUS event and will include the parsed header information in the event's _httpResponse.headers_ property (a vector array of _HTTPResponseHeader_ objects).


**`SOCKS5Tunnel.ONHTTPRESPONSE`** - Dispatched when the SOCKS5 tunnel connection has fully completed receiving the entire HTTP response from a _loadHTTP_ call. All of the event's _httpResponse_ object's properties should now contain valid information from the response. Note that not all responses include a response body (for example, a 302 redirect).