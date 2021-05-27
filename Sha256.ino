#include <WiFi.h>
#include <WiFiClient.h>
#include <WebServer.h>
#include "mbedtls/aes.h"
#include <ESPmDNS.h>
#include <base64.h>
extern "C" {
#include "crypto/base64.h"
} 

//MDNSResponder mdns;
const char*  ssid = "D-Link_DIR-615";
const char* password = "rakesh1995";

const int gpio1_pin = LED_BUILTIN;
WebServer server(80);

//Check if header is present and correct
bool is_authentified() {
  Serial.println("Enter is_authentified");
  if (server.hasHeader("Cookie")) {
    Serial.print("Found cookie: ");
    String cookie = server.header("Cookie");
    Serial.println(cookie);
    if (cookie.indexOf("ESPSESSIONID=1") != -1) {
      Serial.println("Authentification Successful");
      return true;
    }
  }
  Serial.println("Authentification Failed");
  return false;
}

//login page, also called for disconnect
void handleLogin() {
  String msg;
  if (server.hasHeader("Cookie")) {
    Serial.print("Found cookie: ");
    String cookie = server.header("Cookie");
    Serial.println(cookie);
  }
  if (server.hasArg("DISCONNECT")) {
    Serial.println("Disconnection");
    server.sendHeader("Location", "/login");
    server.sendHeader("Cache-Control", "no-cache");
    server.sendHeader("Set-Cookie", "ESPSESSIONID=0");
    server.send(301);
    return;
  }
  if (server.hasArg("USERNAME") && server.hasArg("PASSWORD")) {
    //username = admin password=root
    if (server.arg("USERNAME") == "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918" &&  server.arg("PASSWORD") == "4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2") {
      server.sendHeader("Location", "/");
      server.sendHeader("Cache-Control", "no-cache");
      server.sendHeader("Set-Cookie", "ESPSESSIONID=1");
      server.send(301);
      Serial.println("Log in Successful");
      return;
    }
    msg = "Wrong username/password! try again.";
    Serial.println("Log in Failed");
  }
  String content ="<html>\n";
  content +="<script type='text/javascript'>\n";
  content +="function SHA256(s){\n";
  content +=" var chrsz = 8;\n";
  content +=" var hexcase = 0;\n";
  content +="\n";
  content +=" function safe_add (x, y) {\n";
  content +=" var lsw = (x & 0xFFFF) + (y & 0xFFFF);\n";
  content +=" var msw = (x >> 16) + (y >> 16) + (lsw >> 16);\n";
  content +=" return (msw << 16) | (lsw & 0xFFFF);\n";
  content +=" }\n";
  content +="\n";
  content +=" function S (X, n) { return ( X >>> n ) | (X << (32 - n)); }\n";
  content +=" function R (X, n) { return ( X >>> n ); }\n";
  content +=" function Ch(x, y, z) { return ((x & y) ^ ((~x) & z)); }\n";
  content +=" function Maj(x, y, z) { return ((x & y) ^ (x & z) ^ (y & z)); }\n";
  content +=" function Sigma0256(x) { return (S(x, 2) ^ S(x, 13) ^ S(x, 22)); }\n";
  content +=" function Sigma1256(x) { return (S(x, 6) ^ S(x, 11) ^ S(x, 25)); }\n";
  content +=" function Gamma0256(x) { return (S(x, 7) ^ S(x, 18) ^ R(x, 3)); }\n";
  content +=" function Gamma1256(x) { return (S(x, 17) ^ S(x, 19) ^ R(x, 10)); }\n";
  content +="\n";
  content +=" function core_sha256 (m, l) {\n";
  content +=" var K = new Array(0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5, 0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174, 0xE49B69C1, 0xEFBE4786, 0xFC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA, 0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x6CA6351, 0x14292967, 0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85, 0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070, 0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3, 0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2);\n";
  content +=" var HASH = new Array(0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19);\n";
  content +=" var W = new Array(64);\n";
  content +=" var a, b, c, d, e, f, g, h, i, j;\n";
  content +=" var T1, T2;\n";
  content +="\n";
  content +=" m[l >> 5] |= 0x80 << (24 - l % 32);\n";
  content +=" m[((l + 64 >> 9) << 4) + 15] = l;\n";
  content +="\n";
  content +=" for ( var i = 0; i<m.length; i+=16 ) {\n";
  content +=" a = HASH[0];\n";
  content +=" b = HASH[1];\n";
  content +=" c = HASH[2];\n";
  content +=" d = HASH[3];\n";
  content +=" e = HASH[4];\n";
  content +=" f = HASH[5];\n";
  content +=" g = HASH[6];\n";
  content +=" h = HASH[7];\n";
  content +="\n";
  content +=" for ( var j = 0; j<64; j++) {\n";
  content +=" if (j < 16) W[j] = m[j + i];\n";
  content +=" else W[j] = safe_add(safe_add(safe_add(Gamma1256(W[j - 2]), W[j - 7]), Gamma0256(W[j - 15])), W[j - 16]);\n";
  content +="\n";
  content +=" T1 = safe_add(safe_add(safe_add(safe_add(h, Sigma1256(e)), Ch(e, f, g)), K[j]), W[j]);\n";
  content +=" T2 = safe_add(Sigma0256(a), Maj(a, b, c));\n";
  content +="\n";
  content +=" h = g;\n";
  content +=" g = f;\n";
  content +=" f = e;\n";
  content +=" e = safe_add(d, T1);\n";
  content +=" d = c;\n";
  content +=" c = b;\n";
  content +=" b = a;\n";
  content +=" a = safe_add(T1, T2);\n";
  content +=" }\n";
  content +="\n";
  content +=" HASH[0] = safe_add(a, HASH[0]);\n";
  content +=" HASH[1] = safe_add(b, HASH[1]);\n";
  content +=" HASH[2] = safe_add(c, HASH[2]);\n";
  content +=" HASH[3] = safe_add(d, HASH[3]);\n";
  content +=" HASH[4] = safe_add(e, HASH[4]);\n";
  content +=" HASH[5] = safe_add(f, HASH[5]);\n";
  content +=" HASH[6] = safe_add(g, HASH[6]);\n";
  content +=" HASH[7] = safe_add(h, HASH[7]);\n";
  content +=" }\n";
  content +=" return HASH;\n";
  content +=" }\n";
  content +="\n";
  content +=" function str2binb (str) {\n";
  content +=" var bin = Array();\n";
  content +=" var mask = (1 << chrsz) - 1;\n";
  content +=" for(var i = 0; i < str.length * chrsz; i += chrsz) {\n";
  content +=" bin[i>>5] |= (str.charCodeAt(i / chrsz) & mask) << (24 - i % 32);\n";
  content +=" }\n";
  content +=" return bin;\n";
  content +=" }\n";
  content +="\n";
  content +=" function Utf8Encode(string) {\n";
  content +=" string = string.replace(/\\r\\n/g,'\\n');\n";
  content +=" var utftext = '';\n";
  content +="\n";
  content +=" for (var n = 0; n < string.length; n++) {\n";
  content +="\n";
  content +=" var c = string.charCodeAt(n);\n";
  content +="\n";
  content +=" if (c < 128) {\n";
  content +=" utftext += String.fromCharCode(c);\n";
  content +=" }\n";
  content +=" else if((c > 127) && (c < 2048)) {\n";
  content +=" utftext += String.fromCharCode((c >> 6) | 192);\n";
  content +=" utftext += String.fromCharCode((c & 63) | 128);\n";
  content +=" }\n";
  content +=" else {\n";
  content +=" utftext += String.fromCharCode((c >> 12) | 224);\n";
  content +=" utftext += String.fromCharCode(((c >> 6) & 63) | 128);\n";
  content +=" utftext += String.fromCharCode((c & 63) | 128);\n";
  content +=" }\n";
  content +="\n";
  content +=" }\n";
  content +="\n";
  content +=" return utftext;\n";
  content +=" }\n";
  content +="\n";
  content +=" function binb2hex (binarray) {\n";
  content +=" var hex_tab = hexcase ? '0123456789ABCDEF' : '0123456789abcdef';\n";
  content +=" var str = '';\n";
  content +=" for(var i = 0; i < binarray.length * 4; i++) {\n";
  content +=" str += hex_tab.charAt((binarray[i>>2] >> ((3 - i % 4)*8+4)) & 0xF) +\n";
  content +=" hex_tab.charAt((binarray[i>>2] >> ((3 - i % 4)*8 )) & 0xF);\n";
  content +=" }\n";
  content +=" return str;\n";
  content +=" }\n";
  content +="\n";
  content +=" s = Utf8Encode(s);\n";
  content +="\n";
  content +=" return binb2hex(core_sha256(str2binb(s), s.length * chrsz));\n";
  content +="}\n";
  content +="function encodeMyHtml(){var htmlToEncodeP = document.getElementById('password').value; \n";
  content +="var htmlToEncodeU = document.getElementById('username').value; \n";
  content +="var strP = String(htmlToEncodeP) ; \n";
  content +="var strU = String(htmlToEncodeU) ; \n";
  content +="var newString = SHA256(strP); \n";
  content +="var encodedHtmlP = escape(htmlToEncodeP); \n";
  content +="var newStr = SHA256(strU); \n";
  content +="var encodedHtmlU = escape(htmlToEncodeU); \n";
  content +="document.getElementById('password').value=newString; \n";
  content +="document.getElementById('username').value=newStr; return true;} </script>\n";
  content += "<body style='background-color:LightGray'><form id='form1' action='/login' method='POST'><p  align ='center' style='font-size:300%;'><u><b><i>  Log In  </i></b></u></p><br>";
  content += "<p  align ='center' style='font-size:160%'><b> UserName:<input type='text' id='username' name='USERNAME' placeholder='user name' required></b></p><br>";
  content += "<p  align ='center' style='font-size:160%'><b> Password:<input type='password' id='password' name='PASSWORD' placeholder='password' required></b></p><br>";
  content += "<p  align ='center' style='font-size:160%'><input type='submit' name='SUBMIT' onclick='return encodeMyHtml()' value='Submit'></form>" + msg + "</p><br> </body></html>";
  server.send(200, "text/html", content);
}
void handleRoot() {
  Serial.println("Enter handleRoot");
  String header;
  if (!is_authentified()) {
    server.sendHeader("Location", "/login");
    server.sendHeader("Cache-Control", "no-cache");
    server.send(301);
    return;
  }
  String content =  "<body style='background: #80c6f7'><h1 align ='center'><b><u><i><strong>Authentication using SHA256 Encryption Protocol</strong></i></u></b></h1><br><p align ='center'>Switch #1 <a href=\"switch1On\"><button>ON</button></a>&nbsp;<a href=\"switch1Off\"><button>OFF</button></a></p>";
  content += "<br><p><marquee direction='right'>Developed by Rakesh Podder</marquee></p>";
  content += "<br><br><br><br></body>"; 
  
   if (server.hasHeader("User-Agent")){
    content += "the user agent used is : " + server.header("User-Agent") + "<br><br>";
    
    
  }
  content += "You can access this page until you <a href=\"/login?DISCONNECT=YES\">disconnect</a></body></html>";
  server.send(200, "text/html", content);
}

//no need authentification
void handleNotFound() {
  String message = "File Not Found\n\n";
  message += "URI: ";
  message += server.uri();
  message += "\nMethod: ";
  message += (server.method() == HTTP_GET) ? "GET" : "POST";
  message += "\nArguments: ";
  message += server.args();
  message += "\n";
  for (uint8_t i = 0; i < server.args(); i++) {
    message += " " + server.argName(i) + ": " + server.arg(i) + "\n";
  }
  server.send(404, "text/plain", message);
}

void setup(void) {
  pinMode(gpio1_pin, OUTPUT);
  digitalWrite(gpio1_pin, LOW);
  
  Serial.begin(115200);
  WiFi.mode(WIFI_STA);
  WiFi.begin(ssid, password);
  Serial.println("");

  // Wait for connection
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println("");
  Serial.print("Connected to ");
  Serial.println(ssid);
  Serial.print("IP address: ");
  Serial.println(WiFi.localIP());
//
//    if (!MDNS.begin("esp32")) {
//        Serial.println("Error setting up MDNS responder!");
//        while(1) {
//            delay(1000);
//        }
//    }
//    Serial.println("mDNS responder started");


  server.on("/", handleRoot);
  server.on("/login", handleLogin);
  server.on("/inline", []() {
    server.send(200, "text/plain", "this works without need of authentification");
  });

  server.onNotFound(handleNotFound);
  //here the list of headers to be recorded
  const char * headerkeys[] = {"User-Agent", "Cookie"} ;
  size_t headerkeyssize = sizeof(headerkeys) / sizeof(char*);
  //ask server to track these headers
  server.collectHeaders(headerkeys, headerkeyssize);
  

  server.on("/",[](){
   //
  });
  server.on("/switch1On", [](){
   //
    if (is_authentified()){ 
      digitalWrite(gpio1_pin, HIGH);
      delay(1000);}
  });
  server.on("/switch1Off", [](){
 // 
    if (is_authentified()){ 
      digitalWrite(gpio1_pin, LOW);
      delay(1000); }
  });
  
  server.begin();
  server.begin();  Serial.println("HTTP server started");
  // Add service to MDNS-SD
//  MDNS.addService("http", "tcp", 80);
}

void loop(void) {
  server.handleClient();
}
