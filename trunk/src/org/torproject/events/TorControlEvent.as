package org.torproject.events {
	import flash.events.Event;
	
	/**
	 * Contains data and information from various events raised within a TorControl instance.
	 */
	public class TorControlEvent extends Event {
		
		/**
		 * Dispatched whenever Tor sends a STDOUT log message (included as both rawMessage and body properties). 
		 * The verbosity of log information is set in the config data for the Tor binary in TorControl.as
		 */
		public static const ONLOGMSG:String = "Event.TorControlEvent.ONLOGMSG";
		/**
		 * Dispatched once the Tor control connection is connected. Until authorized, the control connection should not be assumed to be usable.
		 */
		public static const ONCONNECT:String = "Event.TorControlEvent.ONCONNECT";
		/**
		 * Dispatched once the Tor control connection is authenticated and ready to accept commands.
		 */
		public static const ONAUTHENTICATE:String = "Event.TorControlEvent.ONAUTHENTICATE";
		/**
		 * Dispatched whenever the Tor control connection replies with a synchronous response. For asynchronous events registered with Tor, additional ASYNCHEVENT events
		 * will be broadcast.
		 */
		public static const ONRESPONSE:String = "Event.TorControlEvent.ONRESPONSE";
		/**
		 * Dispatched whenever the Tor control connection signals an asynchronous event. Only registered events will be processed, and these may be received at any time. 
		 * Refer to: "TC: A Tor control protocol (Version 1) -- 4.1. Asynchronous events"
		 * https://gitweb.torproject.org/torspec.git?a=blob_plain;hb=HEAD;f=control-spec.txt
		 * 
		 * The Tor event that triggered the event is stored in the torEvent property. Otherwise it is up to the listener to interpret the included message.
		 */
		public static const ONEVENT:String = "Event.TorControlEvent.ONEVENT";
		
		public var body:String = new String();
		public var status:int = 0;		
		public var rawMessage:String = new String();
		public var torEvent:String = null; //Used only by Event.TorControlEvent.ONEVENT
		
		public function TorControlEvent(p_type:String, p_bubbles:Boolean=false, p_cancelable:Boolean=false) {
			super(p_type, p_bubbles, p_cancelable);
		}//consructor
		
	}//TorControlEvent class

}//package