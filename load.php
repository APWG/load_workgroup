<?php
// url to the eCX API
$api_url = "https://api.ecrimex.net";

// note both endpoints that we'll be using
$mal_domain_endpoint = "/mal_domain?page=2";
$sandbox_endpoint = "/groups/331af39c802ee13f442e4954004365cab4697bb4";

// and we'll need a valid eCX API token key that has access to both mal_domain and the mal_domain sandbox
$api_token_key="<your eCX API key goes here>";

// set up 2 curl instances, could do it with 1 and use curl_setopt() to flip the curl params around, but...
// first
$curl_get = curl_init();
curl_setopt_array($curl_get, array(
	CURLOPT_URL => $api_url . $mal_domain_endpoint,
	CURLOPT_CUSTOMREQUEST => "GET",
	CURLOPT_RETURNTRANSFER => TRUE,
	CURLOPT_HEADER => 0,
	CURLOPT_ENCODING => "",
	CURLOPT_MAXREDIRS => 10,
	CURLOPT_TIMEOUT => 30,
	CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
	CURLOPT_USERAGENT => 'cURL, Bulk Import, Malicious Domain Sandbox',
	CURLOPT_HTTPHEADER => array(
		"Authorization: " . $api_token_key,
		"Content-Type: application/json"
	),
));
// second
$curl_post = curl_init();
curl_setopt_array($curl_post, array(
	CURLOPT_URL => $api_url . $sandbox_endpoint,
	CURLOPT_CUSTOMREQUEST => "POST",
	CURLOPT_RETURNTRANSFER => TRUE,
	CURLOPT_HEADER => 0,
	CURLOPT_ENCODING => "",
	CURLOPT_MAXREDIRS => 10,
	CURLOPT_TIMEOUT => 30,
	CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
	CURLOPT_USERAGENT => 'cURL, Bulk Import, Malicious Domain Sandbox',
	CURLOPT_HTTPHEADER => array(
		"Authorization: " . $api_token_key,
		"Content-Type: application/json"
	),
));

// if an exception file exists, delete it, if errors are found later on in the logic then the file will be created prior to writing it
if (file_exists('exceptions.csv')) {
	unlink('exceptions.csv');
}

// run the GET to grab data out of the mal_domain module
$response = curl_exec($curl_get);
// test for error
$err = curl_error($curl_get);
if ($err) {
	// die off if there was a problem
	die("cURL Error #: " . $err);
} else {
	// check the eCX API response code that was returned
	$status = curl_getinfo($curl_get, CURLINFO_HTTP_CODE);
	// successful?
	if ($status != 200) {
		// unsuccessful, die off, there was something wrong with our GET command
		die("\nerror in the GET, aborting..\n");
	} elseif ($status == 200) {
		// we're good

		// put the data into a $json variable
		$json = json_decode($response);

		// keep track of how many we've processed
		$counter = 0;

		// this is just going to stuff the 500 records returned into the mal_domain sandbox, no pagination
		foreach($json->_embedded->entities as $data) {
			// for each of the 500 results returned, create the POST data payload, and save it as JSON into $post
			$post = json_encode(array(
				'discovered' => $data->discovered,
				'domain' => $data->domain,
				'confidence' => $data->confidence,
				'classification' => $data->classification,
				'status' => $data->status
			), JSON_PRETTY_PRINT);
			// stuff $post into the curl object
			curl_setopt($curl_post, CURLOPT_POSTFIELDS, $post);
			// SEND IT!
			$response = curl_exec($curl_post);
			// same as above, did we get an error?
			$err = curl_error($curl_post);
			if ($err) {
				die("cURL Error #: " . $err);
			} else {
				// success will get us a 201
				$status = curl_getinfo($curl_post, CURLINFO_HTTP_CODE);
				if ($status != 201) {
					// if it was anything other than a 201/success then dump an error
					$error = json_decode($response);
					$fields['payload'] = $post;
					$fields['error'] = implode('|', $error->error->messages);
					$fp = fopen('exceptions.csv', 'a');
					fputcsv($fp, $fields);
					fclose($fp);
				} else {
					$counter++;
					echo "Data POSTed successfully, " . $counter . "/500\n";
				}
			}
		}
	}
}
