package org.torproject {
	
	import flash.events.EventDispatcher;
	import flash.net.Socket;
	import flash.net.SecureSocket;	
	import flash.events.Event;
	import flash.events.ProgressEvent;
	import flash.events.IOErrorEvent;	
	import flash.events.SecurityErrorEvent;	
	import flash.utils.ByteArray;
	import flash.utils.getDefinitionByName;
	import org.torproject.events.SOCKS5TunnelEvent;
	import org.torproject.model.HTTPResponse;
	import org.torproject.model.HTTPResponseHeader;
	import org.torproject.model.SOCKS5Model;
	import org.torproject.model.TorASError;
	import flash.net.URLRequest;
	import flash.net.URLRequestDefaults;
	import flash.net.URLRequestHeader;
	import flash.net.URLRequestMethod;
	import flash.net.URLVariables;
	import org.torproject.utils.URLUtil;	
	
	// TLS/SSL courtesy of as3crypto
	import com.hurlant.crypto.tls.*;
	
	/**
	 * Provides SOCKS5-capable transport services for proxied network requests. This protocol is also used by Tor to transport
	 * various network requests.
	 * 
	 * Since TorControl is used to manage the Tor services process, if this process is already correctly configured and running
	 * SOCKS5Tunnel can be used completely independently (TorControl may be entirely omitted).
	 * 
	 * @author Patrick Bay
	  * The MIT License (MIT)
	 * 
	 * Copyright (c) 2013 Patrick Bay
	 * 
	 * Permission is hereby granted, free of charge, to any person obtaining a copy
	 * of this software and associated documentation files (the "Software"), to deal
	 * in the Software without restriction, including without limitation the rights
	 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
	 * copies of the Software, and to permit persons to whom the Software is
	 * furnished to do so, subject to the following conditions:
	 * 
	 * The above copyright notice and this permission notice shall be included in
	 * all copies or substantial portions of the Software.
	 * 
	 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
	 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
	 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
	 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
	 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
	 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
	 * THE SOFTWARE. 
	 */
	public class SOCKS5Tunnel extends EventDispatcher {
		
		public static const defaultSOCKSIP:String = "127.0.0.1";
		public static const defaultSOCKSPort:int = 1080; //Standard SOCKS5 port
		public static const maxRedirects:int = 5;
		private var _tunnelSocket:Socket = null;
		private var _secureTunnelSocket:TLSSocket = null;
		private var _tunnelIP:String = null;
		private var _tunnelPort:int = -1;
		private var _connectionType:int = -1;
		private var _connected:Boolean = false;
		private var _authenticated:Boolean = false;
		private var _tunneled:Boolean = false;		
		private var _requestActive:Boolean = false;
		private var _requestBuffer:Array = new Array();
		private var _responseBuffer:ByteArray = new ByteArray();
		private var _HTTPStatusReceived:Boolean = false;
		private var _HTTPHeadersReceived:Boolean = false;
		private var _HTTPResponse:HTTPResponse;		
		private var _currentRequest:URLRequest;
		private var _redirectCount:int = 0;		
		
		/**
		 * Creates an instance of a SOCKS5 proxy tunnel.
		 * 
		 * @param	tunnelIP The SOCKS proxy IP to use. If not specified, the current static constant values are used by default.
		 * @param	tunnelPort The SOCKS proxy port to use. If not specified, the current static constant values are used by default.
		 */
		public function SOCKS5Tunnel(tunnelIP:String=null, tunnelPort:int=-1) {
			if ((tunnelIP == null) || (tunnelIP == "")) {
				this._tunnelIP = defaultSOCKSIP;
			}//if
			if (tunnelPort < 1) {
				this._tunnelPort = defaultSOCKSPort;
			}//if
		}//constructor
		
		/**
		 * The current SOCKS proxy tunnel IP being used by the instance.
		 */
		public function get tunnelIP():String {
			return (this._tunnelIP);
		}//get tunnelIP
		
		/**
		 * The current SOCKS proxy tunnel port being used by the instance.
		 */
		public function get tunnelPort():int {
			return (this._tunnelPort);
		}//get tunnelPort		
		
		/**
		 * The tunnel connection type being managed by this instance.
		 */
		public function get connectionType():int {
			return (this._connectionType);
		}//get connectionType
		
		/**
		 * The status of the tunnel connection (true=connected, false=not connected). Requests
		 * cannot be sent through the proxy unless it is both connected and tunneled.
		 */
		public function get connected():Boolean {
			return (this._connected);
		}//get connected
		
		/**
		 * The status of the proxy tunnel (true=ready, false=not ready). Requests
		 * cannot be sent through the proxy unless it is both connected and tunneled.
		 */
		public function get tunneled():Boolean {
			return (this._tunneled);
		}//get tunneled
			
		/**
		 * Sends a HTTP request through the socks proxy, sending any included information (such as form data) in the process. Additional
		 * requests via this tunnel connection will be disallowed until this one has completed (since replies may be multi-part).
		 * 
		 * @param request The URLRequest object holding the necessary information for the request.
		 * 
		 * @return True if the request was dispatched successfully, false otherwise.
		 */
		public function loadHTTP(request:URLRequest):Boolean {
			if (request == null) {
				return (false);
			}//if			
			try {				
				this._requestBuffer.push(request);			
				this._responseBuffer = new ByteArray();
				this._HTTPStatusReceived = false;
				this._HTTPHeadersReceived = false;				
				this.disconnectSocket();
				this._HTTPResponse = new HTTPResponse();
				this._connectionType = SOCKS5Model.SOCKS5_conn_TCPIPSTREAM;			
				this._tunnelSocket = new Socket();				
				this.addSocketListeners();				
				this._tunnelSocket.connect(this.tunnelIP, this.tunnelPort);
				return (true);
			} catch (err:*) {
				var eventObj:SOCKS5TunnelEvent = new SOCKS5TunnelEvent(SOCKS5TunnelEvent.ONCONNECTERROR);
				eventObj.error = new TorASError(err.toString());
				eventObj.error.rawMessage = err.toString();
				this.dispatchEvent(eventObj);
				return (false);
			}//catch
			return (false);
		}//loadHTTP				
		
		/**
		 * The currently active HTTP/HTTPS request being handled by the tunnel instance.
		 */
		public function get activeRequest():* {
			return (this._currentRequest);
		}//get activeRequest
		
		/**
		 * Attempts to establish a new Tor circuit through a running TorControl instance. 
		 * Future SOCKS5Tunnel instances will communicate through the new circuit while 
		 * existing and connected instances will continue to communicate through their existing circuits until closed.
		 * A TorControl instance must be instantiated and fully initialized before attempting to invoke this command.
		 * 
		 * @return True if TorControl is active and could be invoked to establish a new circuit, false
		 * if the invocation failed for any reason.
		 */
		public function establishNewCircuit():Boolean {
			try {
				//Dynamically evaluate so that there are no dependencies
				var tcClass:Class = getDefinitionByName("org.torproject.TorControl") as Class;
				if (tcClass == null) {
					return (false);
				}//if
				var tcInstance:*= new tcClass();
				if (tcClass.connected && tcClass.authenticated) {
					tcInstance.establishNewCircuit();
					return (true);
				}//if
			} catch (err:*) {
				return (false);
			}//catch
			return (false);
		}//establishNewCircuit
		
		private function disconnectSocket():void {				
			this._connected = false;
			this._authenticated = false;
			this._tunneled = false;			
			if (this._tunnelSocket != null) {
				this.removeSocketListeners();
				if (this._tunnelSocket.connected) {
					this._tunnelSocket.close();
				}//if
				this._tunnelSocket = null;
				var eventObj:SOCKS5TunnelEvent = new SOCKS5TunnelEvent(SOCKS5TunnelEvent.ONDISCONNECT);
				this.dispatchEvent(eventObj);
			}//if			
		}//disconnectSocket
		
		private function removeSocketListeners():void {
			if (this._tunnelSocket == null) { return;}
			this._tunnelSocket.removeEventListener(Event.CONNECT, this.onTunnelConnect);
			this._tunnelSocket.removeEventListener(SecurityErrorEvent.SECURITY_ERROR, this.onTunnelConnectError);
			this._tunnelSocket.removeEventListener(IOErrorEvent.IO_ERROR, this.onTunnelConnectError);
			this._tunnelSocket.removeEventListener(IOErrorEvent.NETWORK_ERROR, this.onTunnelConnectError);
			this._tunnelSocket.removeEventListener(ProgressEvent.SOCKET_DATA, this.onTunnelData);	
			this._tunnelSocket.removeEventListener(Event.CLOSE, this.onTunnelDisconnect);
		}//removeSocketListeners
				
		private function addSocketListeners():void {
			if (this._tunnelSocket == null) { return;}
			this._tunnelSocket.addEventListener(Event.CONNECT, this.onTunnelConnect);
			this._tunnelSocket.addEventListener(SecurityErrorEvent.SECURITY_ERROR, this.onTunnelConnectError);
			this._tunnelSocket.addEventListener(IOErrorEvent.IO_ERROR, this.onTunnelConnectError);
			this._tunnelSocket.addEventListener(IOErrorEvent.NETWORK_ERROR, this.onTunnelConnectError);			
			this._tunnelSocket.addEventListener(Event.CLOSE, this.onTunnelDisconnect);
		}//addSocketListeners
		
		private function onTunnelConnect(eventObj:Event):void {						
			this._connected = true;
			this._tunnelSocket.removeEventListener(Event.CONNECT, this.onTunnelConnect);			
			this._tunnelSocket.addEventListener(ProgressEvent.SOCKET_DATA, this.onTunnelData);			
			var connectEvent:SOCKS5TunnelEvent = new SOCKS5TunnelEvent(SOCKS5TunnelEvent.ONCONNECT);
			this.dispatchEvent(connectEvent);
			this.authenticateTunnel();
		}//onTunnelConnect	
		
		private function onTunnelConnectError(eventObj:IOErrorEvent):void {			
			this.removeSocketListeners();
			this._tunnelSocket = null;
			this._connected = false;
			this._authenticated = false;
			this._tunneled = false;
			var errorEventObj:SOCKS5TunnelEvent = new SOCKS5TunnelEvent(SOCKS5TunnelEvent.ONCONNECTERROR);
			errorEventObj.error = new TorASError(eventObj.toString());
			errorEventObj.error.status = eventObj.errorID;						
			errorEventObj.error.rawMessage = eventObj.toString();
			this.dispatchEvent(errorEventObj);
		}//onTunnelConnectError
		
		private function onTunnelDisconnect(eventObj:Event):void {				
			this.removeSocketListeners();			
			this._connected = false;
			this._authenticated = false;
			this._tunneled = false;			
			this._tunnelSocket = null;			
			var disconnectEvent:SOCKS5TunnelEvent = new SOCKS5TunnelEvent(SOCKS5TunnelEvent.ONDISCONNECT);
			this.dispatchEvent(disconnectEvent);			
		}//onTunnelDisconnect			
		
		private function authenticateTunnel():void {			
			this._tunnelSocket.writeByte(SOCKS5Model.SOCKS5_head_VERSION);
			this._tunnelSocket.writeByte(SOCKS5Model.SOCKS5_auth_NUMMETHODS);
			this._tunnelSocket.writeByte(SOCKS5Model.SOCKS5_auth_NOAUTH);			
			this._tunnelSocket.flush();
		}//authenticateTunnel
		
		private function onAuthenticateTunnel():void {				
			var currentRequest:* = this._requestBuffer[0];
			if (currentRequest is URLRequest) {
				this.establishHTTPTunnel();
			}//if
		}//onAuthenticateTunnel
		
		private function establishHTTPTunnel():void {			
			this._tunnelSocket.writeByte(SOCKS5Model.SOCKS5_head_VERSION);
			this._tunnelSocket.writeByte(SOCKS5Model.SOCKS5_conn_TCPIPSTREAM);
			this._tunnelSocket.writeByte(0); //Reserved
			this._tunnelSocket.writeByte(SOCKS5Model.SOCKS5_addr_DOMAIN); //Most secure when using DNS through proxy
			var currentRequest:* = this._requestBuffer[0];			
			var domain:String = URLUtil.getServerName(currentRequest.url);
		//	var domainSplit:Array = domain.split(".");			
		//	if (domainSplit.length>2) {
		//		domain = domainSplit[1] + "." + domainSplit[2]; //Ensure we have JUST the domain
		//	}//if				
			var domainLength:int = int(domain.length);
			var port:int = int(URLUtil.getPort(currentRequest.url));			
			this._tunnelSocket.writeByte(domainLength);
			var portMSB:int = (port & 0xFF00) >> 8;
			var portLSB:int = port & 0xFF;			
			this._tunnelSocket.writeMultiByte(domain, SOCKS5Model.charSetEncoding);			
			this._tunnelSocket.writeByte(portMSB); //Obviously swap these if LSB comes first
			this._tunnelSocket.writeByte(portLSB);			
			this._tunnelSocket.flush();			
		}//establishHTTPTunnel
		
		private function onEstablishTunnel():void {			
			var currentRequest:* = this._requestBuffer[0];
			if (currentRequest is URLRequest) {
				this.sendQueuedHTTPRequest();
			}//if		
		}//onEstablishHTTPTunnel
		
		private function sendQueuedHTTPRequest():void {
			var currentRequest:URLRequest = this._requestBuffer.shift() as URLRequest;
			this._currentRequest = currentRequest;					
			if (URLUtil.isHttpsURL(this._currentRequest.url)) {
				this.startTLSTunnel();
			} else {
				if (this._HTTPResponse!=null ) {
					if (this._currentRequest.manageCookies) {
						var requestString:String = SOCKS5Model.createHTTPRequestString(currentRequest, this._HTTPResponse.cookies);		
					} else {
						requestString = SOCKS5Model.createHTTPRequestString(currentRequest, null);
					}//else
				} else {
					requestString = SOCKS5Model.createHTTPRequestString(currentRequest, null);
				}//else
				this._HTTPResponse = new HTTPResponse();
				this._tunnelSocket.writeMultiByte(requestString, SOCKS5Model.charSetEncoding);			
				this._tunnelSocket.flush();
			}//else
		}//sendQueuedHTTPRequest
		
		/**
		 * Starts TLS for HTTPS requests/responses.
		 */
		private function startTLSTunnel():void {			
			if (this._HTTPResponse!=null ) {
				if (this._currentRequest.manageCookies) {
					var requestString:String = SOCKS5Model.createHTTPRequestString(this._currentRequest, this._HTTPResponse.cookies);		
				} else {
					requestString = SOCKS5Model.createHTTPRequestString(this._currentRequest, null);
				}//else
			} else {
				requestString = SOCKS5Model.createHTTPRequestString(this._currentRequest, null);
			}//else
			this._HTTPResponse = new HTTPResponse();		
			var domain:String = URLUtil.getServerName(this._currentRequest.url);
			this._secureTunnelSocket = new TLSSocket();
			this._tunnelSocket.removeEventListener(ProgressEvent.SOCKET_DATA, this.onTunnelData);	
			this._secureTunnelSocket.addEventListener(ProgressEvent.SOCKET_DATA, this.onTunnelData);
			this._secureTunnelSocket.startTLS(this._tunnelSocket, domain);
			this._secureTunnelSocket.writeMultiByte(requestString, SOCKS5Model.charSetEncoding); //This is queued to send on connect
		}//startTLSTunnel		
		
		private function authResponseOkay(respData:ByteArray):Boolean {
			respData.position = 0;
			var SOCKSVersion:int = respData.readByte();
			var authMethod:int = respData.readByte();
			if (SOCKSVersion != SOCKS5Model.SOCKS5_head_VERSION) {
				return (false);
			}//if
			if (authMethod != SOCKS5Model.SOCKS5_auth_NOAUTH) {
				return (false);
			}//if			
			return (true);
		}//authResponseOkay
		
		private function tunnelResponseOkay(respData:ByteArray):Boolean {
			respData.position = 0;
			var currentRequest:* = this._requestBuffer[0];
			if (currentRequest is URLRequest) {
				var SOCKSVersion:int = respData.readByte();
				var status:int = respData.readByte();
				if (SOCKSVersion != SOCKS5Model.SOCKS5_head_VERSION) {
					return (false);
				}//if
				if (status != 0) {
					return (false);
				}//if
				return (true);
			}//if
			return (false);
		}//tunnelResponseOkay
		
		private function tunnelRequestComplete(respData:ByteArray):Boolean {			
			var bodySize:int = -1;
			if (this._HTTPHeadersReceived) {
				try {
					//If content length header supplied, use it to determine if response body is fully completed...
					bodySize = int(this._HTTPResponse.getHeader("Content-Length").value);
					if (bodySize>-1) {
						var bodyReceived:int = this._HTTPResponse.body.length;					
						if (bodySize != bodyReceived) {
							return (false);
						}//if
						return (true);
					}//if
				} catch (err:*) {
					bodySize = -1;
				}//catch
			}//if		
			//Content-Length header not found so using raw data length instead...
			respData.position = respData.length - 4; //Not bytesAvailable since already read at this point!
			var respString:String = respData.readMultiByte(4, SOCKS5Model.charSetEncoding);						
			respData.position = 0;
			if (respString == SOCKS5Model.doubleLineEnd) {
				return (true);
			}//if
			return (false);
		}//tunnelRequestComplete
		
		private function handleHTTPRedirect(responseObj:HTTPResponse):Boolean {
			if (this._currentRequest.followRedirects) {				
				if ((responseObj.statusCode == 301) || (responseObj.statusCode == 302)) {					
					var redirectInfo:HTTPResponseHeader = responseObj.getHeader("Location");						
					if (redirectInfo != null) {		
						this._redirectCount++;						
						this._currentRequest.url = redirectInfo.value;
						this._HTTPStatusReceived = false;
						this._HTTPHeadersReceived = false;											
						this._responseBuffer = new ByteArray();
						if (this._redirectCount >= maxRedirects) {
							//Maximum redirects hit
							var statusEvent:SOCKS5TunnelEvent = new SOCKS5TunnelEvent(SOCKS5TunnelEvent.ONHTTPMAXREDIRECTS);			
							statusEvent.httpResponse = this._HTTPResponse;						
							this.dispatchEvent(statusEvent);							
							this.disconnectSocket();
							return (true);							
						}//if
						this._requestBuffer.push(this._currentRequest);
						statusEvent = new SOCKS5TunnelEvent(SOCKS5TunnelEvent.ONHTTPREDIRECT);			
						statusEvent.httpResponse = this._HTTPResponse;						
						this.dispatchEvent(statusEvent);	
						this.sendQueuedHTTPRequest();
						return (true);
					}//if
				}//if				
			}//if
			return (false);
		}//handleHTTPRedirect			
		
		private function handleHTTPResponse(rawData:ByteArray, secure:Boolean=false):void {
			rawData.readBytes(this._responseBuffer, this._responseBuffer.length);			
			if (!this._HTTPStatusReceived) {				
				if (this._HTTPResponse.parseResponseStatus(this._responseBuffer)) {
					this._HTTPStatusReceived = true;
					var statusEvent:SOCKS5TunnelEvent = new SOCKS5TunnelEvent(SOCKS5TunnelEvent.ONHTTPSTATUS);			
					statusEvent.httpResponse = this._HTTPResponse;						
					this.dispatchEvent(statusEvent);												
				}//if
			}//if
			if (!this._HTTPHeadersReceived) {			
				if (this._HTTPResponse.parseResponseHeaders(this._responseBuffer)) {
					this._HTTPHeadersReceived = true;
					statusEvent = new SOCKS5TunnelEvent(SOCKS5TunnelEvent.ONHTTPHEADERS);			
					statusEvent.httpResponse = this._HTTPResponse;
					this.dispatchEvent(statusEvent);						
				}//if
			}//if				
			if (this.handleHTTPRedirect(this._HTTPResponse)) {								
				return;
			}//if
			this._responseBuffer.position = 0;				
			this._HTTPResponse.parseResponseBody(this._responseBuffer);
			this._responseBuffer.position = 0;			
			if (!this.tunnelRequestComplete(rawData)) {				
				//Response not yet fully received...keep waiting.
				return;
			}//if			
			//Response fully received.
			var dataEvent:SOCKS5TunnelEvent = new SOCKS5TunnelEvent(SOCKS5TunnelEvent.ONHTTPRESPONSE);			
			dataEvent.secure = secure;			
			dataEvent.httpResponse = this._HTTPResponse;	
			dataEvent.httpResponse.rawResponse = new ByteArray();
			dataEvent.httpResponse.rawResponse.writeBytes(this._responseBuffer);	
			if (!secure) {
				this.disconnectSocket();
			}//if
			this.dispatchEvent(dataEvent);	
			this._responseBuffer = new ByteArray();		
			this._HTTPStatusReceived = false;
			this._HTTPHeadersReceived = false;			
		}//handleHTTPResponse		
		
		private function onTunnelData(eventObj:ProgressEvent):void {
			var rawData:ByteArray = new ByteArray();
			var stringData:String = new String();
			if (eventObj.target==this._tunnelSocket) {
				this._tunnelSocket.readBytes(rawData);	
			} else {
				this._secureTunnelSocket.readBytes(rawData);
			}
			rawData.position = 0;
			stringData = rawData.readMultiByte(rawData.length, SOCKS5Model.charSetEncoding);		
			rawData.position = 0;			
			if (!this._authenticated) {
				if (this.authResponseOkay(rawData)) {
					this._authenticated = true;
					this.onAuthenticateTunnel();
					return;
				}//if
			}//if		
			if (!this._tunneled) {
				if (this.tunnelResponseOkay(rawData)) {
					this._tunneled = true;					
					this.onEstablishTunnel();
					return;
				}//if
			}//if
			if (this._currentRequest is URLRequest) {
				if (eventObj.target is Socket) {					
					this.handleHTTPResponse(rawData, false);
				}//if
				if (eventObj.target is TLSSocket) {					
					this.handleHTTPResponse(rawData, true);
				}//if
			}//if
		}//onTunnelData
		
	}//SOCKS5Tunnel class

}//package