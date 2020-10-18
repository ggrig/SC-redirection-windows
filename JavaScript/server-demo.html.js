/**
 * @description lib function for Smart Card Auth Server Demo - atr.hmtl
 * 
 * https://github.com/SC-Develop/SCD_SMCAuthServer - git.sc.develop@gmail.com
 * 
 * Copyright (c) 2019 Ing. Salvatore Cerami (MIT) - dev.salvatore.cerami@gmail.com
 * 
 */

  var atrCode=0;
  var maxEle=9;
  var client;
  var login=false;
 
  /**
   * Remove older excess  elments from top of list. The list can contain at most maxElements element.
   * 
   * @param {int} maxElements 
   * @returns {undefined}
   */  
  clear = function(maxElements)
  {
     var ul = document.getElementById("eventi_websocket");

     var elements = document.getElementsByTagName("LI");

     var len = elements.length;

     if (len<maxElements)
     {
       return;
     }  

     for (n=0; n<(len-maxElements); n++)
     {
        ul.removeChild(elements[0]);
     }
  };

  /**
   * Append the text to list
   * 
   * @param {tstring} text
   * @returns {undefined}
   */
  function append(text)
  {
     var ul = document.getElementById("eventi_websocket");

     ul.insertAdjacentHTML('beforeend', "<li>" + text + "</li>");        
  };

  /**
   * Set the text of 'data' element to data
   * 
   * @param {type} data
   * @returns {undefined}
   */
  function setData(data)
  {
     var id = document.getElementById("data");

     id.innerHTML = data;
  }

  /**
   * Set the text of error element to 'error'
   * 
   * @param {string} error
   * @returns {undefined}
   */ 
  function setError(error)
  {
     var id = document.getElementById("error");

     id.innerHTML = error;
  }
 
    
  function onOpened()
  {
    setData(" Opened");

    append("Connection opened");

    client.getLoginCode();    
  }
  
  /**
   * Open connection to SCD Smart Card Authentication Server
   * @param {string} atr
   * @returns {undefined}
   */
  
  function connect(atr)
  {  
    client = new SCD_SmcAuthClient('localhost',8080);
    remote = new SCD_SmcAuthClient('sc_server.com',8080);
    
    client.onSmcError = function(e)
    {
       clear(maxEle); 
       
       append("Command: " + e.detail.command + " => error: " + e.detail.error);
       
       remote.sendCommand(e.detail.error);
    };

    client.onGetATR = function(e)
    {
       clear(maxEle);  
	   //console.log("onGetATR:" + e.detail.command);
	   //console.log("onGetATR:" + e.detail.atr);
       append("Command: " + e.detail.command + " => Atr: " + e.detail.atr);

       remote.sendCommand("ATRCODE:" + e.detail.atr);
    };
	
    client.onViewCert       = function(e)
	{
       clear(maxEle);
	   //console.log("onViewCert:" + e.detail.command);
	   //console.log("onViewCert:" + e.detail.cert);
       append("Command: " + e.detail.command + " => Cert: " + e.detail.cert);

       remote.sendCommand("VIEWCERT:" + e.detail.cert);
	};
	
    client.onAuthenticate   = function(e)
	{
       clear(maxEle);  
	   //console.log("onAuthenticate:" + e.detail.command);
	   //console.log("onAuthenticate:" + e.detail.cert);	
       append("Command: " + e.detail.command + " => Auth: " + e.detail.cert);
	   
       remote.sendCommand("AUTHENTICATE:" + e.detail.cert);   
	};

    client.opened = function(e)
    {
       setData(" Opened");

       append("Local Connection Opened");
    };
          
    client.closed = function(e)
    {
       setData("Closed");
       
       append("Local Connection Closed");
    };
    
    client.error = function(e)
    {
       let message; 
       
       if (!e.message) 
       {
         message = "Open Local Connection Failure";
       }    
       else
       {
         message = e.message;  
       }
       
       setError(message); 
       
       append("Web socket error: " + message);  
    };

    client.onAuthenticate   = function(e)
	{
       clear(maxEle);  
	   //console.log("onAuthenticate:" + e.detail.command);
	   //console.log("onAuthenticate:" + e.detail.cert);	
       append("Command: " + e.detail.command + " => Auth: " + e.detail.cert);
	   
       remote.sendCommand("AUTHENTICATE:" + e.detail.cert);
	};
	
	client.onMsgSigned =  function(e)
    {
       clear(maxEle);

       append("Command: " + e.detail.command + " => signed: " + e.detail.msg);
	   
	   remote.sendCommand("SIGNED:" + e.detail.msg);
    };

    client.onBinData = function (e) {
       clear(maxEle);

       //append("Command: " + e.detail.command + " => bin_data: " + e.detail.msg);

       console.log("BIN_DATA -> remote: " + e.detail.msg);
       remote.sendCommand("BIN_DATA:" + e.detail.msg);
    };

// Remote Web server event handlers

	remote.onMsgToSign =  function(e)
    {
       clear(maxEle);

       append("Command: " + e.detail.command + " => tosign: " + e.detail.msg);
	   
	   client.sendCommand("TOSIGN:" + e.detail.msg);
    };
	
    remote.onSmcError = function(e)
    {
       clear(maxEle);

       append("Command: " + e.detail.command + " => error: " + e.detail.error);
    };

    remote.onBinData = function (e) {
       clear(maxEle);

       //append("Command: " + e.detail.command + " => bin_data: " + e.detail.msg);

       console.log("BIN_DATA -> local: " + e.detail.msg);
       client.sendCommand("BIN_DATA:" + e.detail.msg);
    };

    remote.opened = function(e)
    {
       setData(" Opened");

       append("Remote Connection Opened");
    };

    remote.closed = function(e)
    {
       setData("Closed");

       append("Remote Connection Closed");
    };

    remote.error = function(e)
    {
       let message;

       if (!e.message)
       {
         message = "Open Remote Connection Failure";
       }
       else
       {
         message = e.message;
       }

       setError(message);

       append("Web socket error: " + message);
    };
      
    client.open();
	remote.open();
  }   