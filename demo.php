<?php

                        require_once './EnsLib.php';

			$enslib = new EnsLib();

			// your private secp256k1 key
                        $enslib->key = '';
			// your public secp256k1 key
                        $enslib->address = '';
			// API endpoint
                        //$enslib->url = 'https://api.cartouche.co/v2/';
                        $enslib->url = 'https://api-test.cartouche.co/v2/';

                        // registered domain
                        $domain = '';
                        // Ethereum  address to associate with domain
                        $owner = '0x21D4161657F09f312a5BDE300A853252A026EC77';
			// IANA ID of registrar
			$ianaId = '';

                        $response = $enslib->ping();
                        echo("ping\n");
                        var_dump($response);

                        $response = $enslib->namehash($domain);
			$namehash = $response->result;
                        echo("namehash\n");
                        var_dump($response);
                        echo("$namehash\n");

                        $response = $enslib->nonce($domain);
                        $nonce = $response->result;
                        echo("nonce\n");
                        var_dump($response);
                        echo("$nonce\n");

                        $response = $enslib->associate($domain, $owner, $nonce, $namehash);
                        echo("associate\n");
                        var_dump($response);

                        $response = $enslib->query($domain);
                        echo("query\n");
                        var_dump($response);

                        $response = $enslib->transactions('luxe');
                        echo("transactions\n");
                        var_dump($response);

                        $response = $enslib->isRegistrarAuthorised($ianaId, $enslib->address);
                        echo("isRegistrarAuthorised\n");
                        var_dump($response);
