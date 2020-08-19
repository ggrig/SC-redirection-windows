/**
 * @description SCD Smart Card Authentication Server: client connection management class
 *  
 * https://github.com/SC-Develop/SCD_SMCAuthServer - git.sc.develop@gmail.com
 * 
 * Copyright (c) 2019 Ing. Salvatore Cerami (MIT) - dev.salvatore.cerami@gmail.com
 * 
 */

  /**
   * 
   * @class SCD_SmcAuthClient manage the connection with SCD Smartcard Authentication Server
   */
  class SCD_SmcAuthClient 
  {
    constructor(address,port)
    {
      this.opened = function() {};
      this.closed = function() {};
      this.error  = function() {};
      
      this.onGetATR         = function(e){};      
      this.onSmcError       = function(e){};
      this.onViewCert       = function(e){};
      this.onAuthenticate   = function(e){};
      this.onMsgToSign      = function(e){};
      this.onMsgSigned      = function(e){};
                              
      this.onmessage = function(event)
      {
         console.log("onmessage - " + event.data);
         var message = event.data.split('|');

         var appo = this;

         message[0] = message[0].trim().toUpperCase(); // command 
         message[1] = message[1].trim().toUpperCase(); // reply message
         
         var messageItems = message[1].trim().split(":");
         
         if (messageItems.length>1) // if message contains data or smartcard error
         {
            if (messageItems[0]==="ATR") 
            {
               var atrCode = messageItems[1];
               
               var event = new CustomEvent("getatr", { detail: {command: message[0], atr: atrCode} });
                
               this.dispatchEvent(event);
            }
            else if (messageItems[0]==="ERROR")
            {
               var smcError = message[1];

               var event = new CustomEvent("smcerror", { detail: {command: message[0], error: smcError} });

               this.dispatchEvent(event);
            }
            else if (messageItems[0]==="CERT")
            {
               var certificate = messageItems[1]; 
               
               var event = new CustomEvent("viewcert", { detail: {command: message[0], cert: certificate} });
                
               this.dispatchEvent(event);
            }    
            else if (messageItems[0]==="AUTH")
            {
               var certificate = messageItems[1]; 
               
               var event = new CustomEvent("authenticate", { detail: {command: message[0], cert: certificate} });
                
               this.dispatchEvent(event);
            }    
            else if (messageItems[0]==="TOSIGN")
            {
               var message = messageItems[1]; 
               
               var event = new CustomEvent("tosign", { detail: {command: message[0], msg: message} });
                
               this.dispatchEvent(event);
            }    
            else if (messageItems[0]==="SIGNED")
            {
               var message = messageItems[1]; 
               
               var event = new CustomEvent("signed", { detail: {command: message[0], msg: message} });
                
               this.dispatchEvent(event);
            }    
            
            return;
         }    
         
         if (message[1]==="SESSIONEXPIRED")
         {
            var event = new CustomEvent("sessionexpired", { detail: {command: message[0]} });
                
            this.dispatchEvent(event); 
         }
      };
      
      this.url = "ws://" + address +":" + port;   
    }

    open()
    {
       this.socket = new WebSocket(this.url);     
       
       this.socket.onopen    = this.opened;                 
       this.socket.onmessage = this.onmessage;                
       this.socket.onclose   = this.closed;                 
       this.socket.onerror   = this.error;           
       
       this.socket.addEventListener("smcerror"      , this.onSmcError);      
       this.socket.addEventListener("getatr"        , this.onGetATR);
       this.socket.addEventListener("viewcert"      , this.onViewCert);
       this.socket.addEventListener("authenticate"  , this.onAuthenticate);
       this.socket.addEventListener("tosign"        , this.onMsgToSign);
       this.socket.addEventListener("signed"        , this.onMsgSigned);
    }
    
    sendCommand(command) 
    {
       if (this.socket.readyState===1)
       {  
         this.socket.send(command);   
         
         return 1; // command sent
       }  
      
       return 0; // socket is closed
    }
      
    /**
     * Require to the server the ATR code 
     * 
     * @returns {Number}
     */ 
     getATR()
     {    
        return this.sendCommand("ATRCODE:");   
     }

     viewCert()
     {    
        return this.sendCommand("VIEWCERT:");   
     }

     toAuthenticate()
     {    
        return this.sendCommand("AUTHENTICATE:");   
     }
	 
	 msgToSign()
	 {
        return this.sendCommand("TOSIGN:");   
	 }
	 
	 msgSigned()
	 {
        return this.sendCommand("SIGNED:");   
	 }	 
  }