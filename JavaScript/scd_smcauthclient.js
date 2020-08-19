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
            else if (messageItems[0]==="CERT")
            {
               var seconds = messageItems[1]; 
               
               var event = new CustomEvent("viewcert", { detail: {command: message[0], timeout: seconds} });
                
               this.dispatchEvent(event);
            }    
            else if (messageItems[0]==="AUTH")
            {
               var smcError = message[1]; 
               
               var event = new CustomEvent("authenticate", { detail: {command: message[0], error: smcError} });
                
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

     getCertificate()
     {    
        return this.sendCommand("VIEWCERT:");   
     }

     Authenticate()
     {    
        return this.sendCommand("AUTHENTICATE:");   
     }

     /**
      * Require to the server the authentication ATR code for login
      * 
      * @returns {Number}
      */ 
     getLoginCode()
     {         
        return this.sendCommand("LOGINCODE:");
     }

     /**
      * Require to the server to authenticate the ATR code, and register it as 
      * current  authenticated code. If success, after this call if server reads 
      * from smart card an ATR code which not match to the authenticated code, 
      * unvalidates the authentication and emit NotAuthenticated and 
      * SessionExpired messages
      * 
      * @param {string} atr
      * @returns {Number}
     */
     setAuthenticationCode(atr)
     {
        return this.sendCommand("Authcode:"+atr);    
     }

     /**
      * check authentication
      * 
      * @returns {Number}
      */ 
     checkAuthentication()
     {
        return this.sendCommand("Checkcode:");         
     }

     /**
      * require server type
      * 
      * @returns {Number}
      */ 
     getServerType()
     {
        return this.sendCommand("Servertype:");        
     }
  
     /**
      * 
      * @param {String} timeout 
      * @returns {Number|undefined}
      */
     setPollTimeout(timeout)
     {
        return this.sendCommand("PollTimeout:" + timeout.trim());        
     }    
  }