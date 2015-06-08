# Introduction #

The main purpose of the Tor network is to anonymize (hopefully) encrypted data so that the receiver (a web server for example), has no way of identifying who made the request. This is accomplished through the use of Tor "circuits".

A circuit is at the heart of Tor's onion routing system. It is essentially a secure and anonymous path between two or more participating Tor nodes through which data flows. Each node or stop along a circuit is called a "hop", and is identified using both a plain-text public name and an encrypted network address.

This is not unlike typical internet connectivity where a request between a client and server may go through any number of hops, except that data streams between a typical web client and server are highly visible and traceable.

Additionally, paths between clients and servers are usually established by the networking hardware between them, whereas in the Tor network it's the Tor software that decides how information is routed.

The remainder of this document describes how TorAS can be used to both analyze existing Tor circuits as well as manage and alter them.

## Capturing Tor Circuit Data ##

Once the Tor control connection has been successfully established (see: https://code.google.com/p/toras/wiki/TorASDeveloperGuide), it is a simple matter to add an event listener for the **`TorControlEvent.TOR_CIRC`** event (see: https://code.google.com/p/toras/wiki/TorASEvents).

The running Tor process dispatched CIRC events whenever a change occurs in an existing circuit. Examples of this can include when a circuit build is first launched, when a new hop has been added to a circuit, when a circuit is fully built, or when a circuit becomes unavailable.

To observe the local state of Tor's circuits, you only need to add an event listener to an active, connected, and authenticated **`TorControl`** instance. For example:

```
   import org.torproject.TorControl;
   import org.torproject.model.TorControlCircuit;
   import org.torproject.model.TorControlCircuitHop;	
   import org.torproject.events.TorControlEvent;

   public var torControl:TorControl=null;
              

   public function CircuitsDemo(torControl:TorControl) {
      torControl = new TorControl(null, -1, null, -1, "TorControlConnectionPassword");
      torControl.addEventListener(TorControlEvent.TOR_CIRC, this.onTorCIRCMessage);
      torControl.connect();
   }					
		
   private function onTorCIRCMessage(eventObj:TorControlEvent):void {			
      var circuitObj:TorControlCircuit = new TorControlCircuit(eventObj.body);
      trace ("---");
      trace ("Tor CIRC Event");
      trace (" ");
      trace ("Circuit ID: " + circuitObj.ID);
      trace ("Circuit status: " + circuitObj.status);
      trace ("Circuit purpose: " + circuitObj.purpose);
      trace ("Circuit time created: " + circuitObj.timeCreated);
      trace ("Circuit flags: " + circuitObj.flags);
      trace ("Circuit hops: ");
      if (circuitObj.hops!=null) {
      for (var count:uint = 0; count < circuitObj.hops.length; count++) {
         var currentHop:TorControlCircuitHop = circuitObj.hops[count];
         trace ("   Hop name:" + currentHop.name);
         trace ("   Hop address:" + currentHop.address);
      } else {
	trace ("   none");
      }
      trace ("---");			
   }
```

Note that unlike other examples, we don't have to wait for the **`TorControlEvent.ONAUTHENTICATE`** event to begin receiving **TOR\_CIRC** events.

The output from the **onTorCIRCMessage** listener in the above example would produce something like this:

```
Circuit ID: 4
Circuit status: EXTENDED
Circuit purpose: GENERAL
Circuit time created: 2013-12-11T23:09:50.171963
Circuit flags: IS_INTERNAL,NEED_CAPACITY,NEED_UPTIME
Circuit hops: 
   Hop name:MeikyuuButterfly
   Hop address:$0996A64109CAAB9800012B90CD175236BFB37D60
   Hop name:gssrelay2
   Hop address:$D851AC34FBB56F5C615C0E9816A7AAC2D8948568
   Hop name:fightcensorship
   Hop address:$7C88112DC842751193272851A85F1793BF77FFA8
```

Although it's not absolutely necessary, the **TorControlCircuit** class makes it easy to parse Tor's information into a usable format. The parsed information includes:

**ID**: The numeric ID of the circuit. Any circuit-specific operations require this identifier in order to target the appropriate circuit(s). This is an ActionScript _int_ type.

**status**: The status message associated with the circuit event. In the above example, the event signified that the circuit has just been EXTENDED with a new hop (usually the last one in the list). This is an ActionScript _String_ type.

**purpose**: The purpose, or usage, of the circuit. The above example shows a GENERAL purpose circuit that can be used for bidirectional communication. This is an ActionScript _String_ type.

**time**: The time stamp associated with the Tor circuit event. This is an ActionScript _String_ type.

**flags**: A list of flags associated with the Tor circuit. This is an ActionScript vector array of _String_ types.

**hops**: A list of individual hops for the associated Tor circuit.  This is an ActionScript vector array of _`TorControlCircuitHop`_ types. Each _`TorControlCircuitHop`_ instance contains the public _name_ of the hop and its encrypted / hashed _address_. Each hop is listed in order, so that a request will pass through hop 0, then hop 1, hop 2, and so on.

## Establishing New Circuits ##

Tor does a good job of ensuring that requests and responses are anonymous within existing circuits. However, you may wish to force Tor to establish new circuits after a certain amount of time or after a specific number of requests / responses. The easiest way to force Tor to build new circuits from scratch is by invoking the **`establishNewCircuit`** method of the connected and authenticated **`TorControl`** instance:

```
  import org.torproject.TorControl;
  import org.torproject.model.TorControlCircuit;
  import org.torproject.model.TorControlCircuitHop;	
  import org.torproject.events.TorControlEvent;

  public var torControl:TorControl=null;

  public function launchTorControl():void {
     if (torControl==null) {
        torControl = new TorControl(null, -1, null, -1, "TorControlConnectionPassword"); 
	torControl.addEventListener(TorControlEvent.ONAUTHENTICATE, this.onTorControlReady);
	torControl.connect();
      }
   }
						
   public function onTorControlReady(eventObj:TorControlEvent):void {
      torControl.establishNewCircuit();
   }	
```

Note that, unlike the first example above, we must first wait for the **`TorControl`** instance to fully authenticate before we can use it. This makes sense considering that Tor circuits can only be manipulated if Tor itself is running and available (i.e. if circuits are active).

It's also important to be aware that Tor has built-in limits on how many times this method can be invoked. The limit is not documented but typically it's between 3 to 5 seconds.