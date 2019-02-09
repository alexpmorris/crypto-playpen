// Send Handshake event
$("#sw-handshake").click(function() {
    whalevault.requestHandshake("demo", function(response) {
        console.log('WhaleVault Handshake Received!');
        console.log(response);
    });
});

// All transactions are sent via a swRequest event

// Send PubKeys request
$("#send_pubkeys").click(function() {
    whalevault.requestPubKeys("demo", $("#pubkeys_username").val(), function(response) {
        console.log('whalevault response: PubKeys');
        console.log(response);
    });
});

// Encrypt Memo
$("#send_encrypt").click(function() {
    whalevault.requestEncryptMemo("demo", $("#encrypt_username").val(), $("#encrypt_message").val(), $("#encrypt_keytype option:selected").text(), 
                                  $("#encrypt_to_pubkey").val(), $("#encrypt_memotype option:selected").text(), $("#encrypt_reason").val(),
                                    function(response) {
                                        console.log('whalevault response: encryptMemo');
                                        console.log(response);
                                    });
});

// Decrypt Memo
$("#send_decrypt").click(function() {
    whalevault.requestDecryptMemo("demo", $("#decrypt_username").val(), $("#decrypt_message").val(), $("#decrypt_keytype option:selected").text(), 
                                  $("#encrypt_reason").val(),
                                    function(response) {
                                        console.log('whalevault response: DecryptMemo');
                                        console.log(response);
                                    });
});

// Sign Buffer
$("#send_signbuffer").click(function() {
    whalevault.requestSignBuffer("demo", $("#sb_username").val(), $("#sb_message").val(), $("#sb_keytype option:selected").text(), 
                                  $("#sb_reason").val(), $("#sb_sigtype option:selected").text(),
                                    function(response) {
                                        console.log('whalevault response: SignBuffer');
                                        console.log(response);
                                    });
});

// Sign Buffer Demos

var steem_ops = {"ref_block_num":31525,"ref_block_prefix":1680218073,chainId: "optional","operations":[[0,{"voter":"voter1","author":"author1","permlink":"permlink-for-post","weight":2500}],
                [0,{"voter":"voter2","author":"author2","permlink":"another-permlink-for-post","weight":2500}]]};
//whalevault.requestSignBuffer('stm:stmuser', steem_ops, 'Posting', 'testOp', 'raw', function (r) { console.log(r); });

// in most cases, `network = {"chain":"eos"};` should suffice
var eos_chainId = "e70aaab8997e1dfce58fbfac80cbbb8fecec7b99cf982a9444273cbc64c41473";
var eos_rpc_url = "https://api.jungle.alohaeos.com";
var eos_ops = {"network": {"chain":"eos", chainId: eos_chainId, url: eos_rpc_url }, "actions":[{"account":"eosio.token","name":"transfer","authorization":[{"actor":"eosuser","permission":"active"}],"data":{"from":"eosuser","to":"eosuserTo","quantity":"0.0001 JUNGLE","memo":"test transfer"}}]};
//whalevault.requestSignBuffer('eos:eosuser', eos_ops, 'Active', 'testTx', 'tx', function (r) { console.log(r); });

var sb_demos = "var steem_ops = " + JSON.stringify(steem_ops, null, 2) + 
               "<br/>whalevault.requestSignBuffer('appid', 'stm:stmuser', steem_ops, 'Posting', 'testOp', 'raw', \n           function (response) { console.log(response); });<br/>" +
               "whalevault.requestSignBuffer('appid', 'wls:wlsuser', wls_ops, 'Posting', 'testOp', 'raw', \n           function (response) { console.log(response); });" +
               "<br/><br/>(if successful, result will include signature in hex, \n and expiration in response.data.message.expiration)<br/>" +
               "<br/>(experimental, if steem_ops.url is included w/o ref_block data, \n tx will be signed and broadcast and result will include tx_id and block_num)<br/><br/>" +
               "<br/>var eos_ops = " + JSON.stringify(eos_ops, null, 2) + 
               "<br/>whalevault.requestSignBuffer('appid', 'eos:eosuser', eos_ops, 'Active', 'testTx', 'tx', \n           function (response) { console.log(response); })" +
               "<br/><br/>(if successful, result will include tx_id and block_num)<br/>" +
               "<br/>note: additional network data (chainId, etc) is generally optional\n      (ie. for testnets, alternate rpc nodes, etc)<br/>";
$('#sig_demos').html('<pre style="overflow:auto;">'+sb_demos+'</pre>');
