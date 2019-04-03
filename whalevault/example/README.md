WHALEVAULT :: *Secure Graphene Cross-Chain Key Store Extension*
---
Putting private keys directly into websites is not safe or secure. Even ones run by SteemIt, Inc. Yet this is currently how nearly every Steem-based site or service currently works. On top of that, most Steem users likely use their master password which is even worse

The Vessel desktop wallet software is a secure alternative, but it is too difficult to use for the majority of Steem users and does not easily interact with websites - which is Steem's primary use case.

On Ethereum, you never have to enter your private key into a website to use a dApp, you can just use a browser extension like Metamask, which dApp websites can interface with to securely store your keys and broadcast transactions to the blockchain.

Steem Keychain aims to bring the security and ease-of-use of Metamask to the Steem blockchain platform.

WhaleVault, based on Steem Keychain, is a better, safer cross-chain way to access all your graphene accounts from the Chrome browser.  Graphene blockchains supported out-of-the-box include WhaleShares, BitShares, Eos, Steem, Smoke, Telos, Worbli, Golos, Peerplays, Scorum, and Vice.  WhaleVault is also the "key vault of choice" for ShareBits.

The extension injects the WhaleVault API into each website's javascript context, so that any website that you authorize can safely and securely request a signature or encrypt/decrypt a memo without ever having direct access to any of your private keys.

Because it adds functionality to the normal browser context, WhaleVault requires permission to read and write any web page that wishes to access the extension. You can always "view source" of WhaleVault the way you would any Chrome extension, or from the soon to be available github repo.

WhaleVault is a multi-chain fork by @alexpmorris of the Steem Keychain browser extension.  Steem Keychain (available at https://github.com/MattyIce/steem-keychain) was originally created by @yabapmatt, developed by @stoodkev, and funded by @aggroed. Many thanks to them for creating a great template upon which to build WhaleVault!

## Features
The WhaleVault extension includes the following features:
- Store an unlimited number of Graphene account keys, encrypted with AES
- Securely sign transactions in multiple formats for multiple purposes
- Securely encrypt/decrypt memos
- Securely interact with Graphene-based sites such as WhaleShares, STEEM, 
  BitShares, and EOS, that have integrated with WhaleVault
- Manage transaction confirmation preferences by account and by website
- Locks automatically on browser shutdown or manually using the lock button
- News/alerts feed with domain warnings for alerting users to related 
  crypto site hacks, scams, and other potential phishing attempts

## Website Integration
Websites can currently request the WhaleVault extension to perform the following functions / broadcast operations:
- Send a handshake to make sure the extension is installed
- Encrypt/Decrypt messages encrypted by a private key
- Securely sign transactions in multiple formats for multiple purposes,
  including identity verification for login purposes
- Methods available can return either callbacks or promises

## Installation
Make sure you only install the extension directly from:
- Chrome Web Store: https://chrome.google.com/webstore/detail/hcoigoaekhfajcoingnngmfjdidhmdon
- Firefox Add-ons: https://addons.mozilla.org/en-US/firefox/addon/whalevault/

Or directly from the official github repo: https://github.com/alexpmorris/whalevault/releases

For your own safety and security, **DO NOT INSTALL FROM ANYWHERE ELSE!**

As an additional precaution, you should only allow **"site access"** to the WhaleVault extension in Chrome for those trusted websites that require it.

## Example

An example of a web page that interacts with the extension is included in the "example" folder in the repo. You can test it by running a local HTTP server and going to http://localhost:1337/main.html in your browser.

`cd example`
`node node_serve.js  //static server via nodejs`
`py3_serve  //static server via python3`

NOTE: On localhost, it will only run on port 1337.

## API Documentation

The WhaleVault extension will inject a "whalevault" JavaScript object into all web pages opened in the browser while the extension is running. You can therefore check if the current user has the extension installed using the following code:

```
if (window.whalevault) {
    // WhaleVault extension installed...
} else {
    // WhaleVault extension not installed...
}
```

### Handshake

Additionally, you can request a "handshake" from the extension to further ensure it's installed and that your page is able to connect to it:

*as callback:*
```
window.whalevault.requestHandshake("appId", function(response) {
    console.log('whalevault: Handshake received!');
    console.log(response);
});
```

*as promise:*
```
var response = await window.whalevault.promiseHandshake("appId");
```
