#!/usr/bin/ruby

load 'acme-connect.rb'

# Staging Instance
endpoint_url = "https://acme-staging.api.letsencrypt.org"
aggrement_url = "https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf"

# Here you get the real stuff
#endpoint_url = "https://acme-v01.api.letsencrypt.org/"

# Initialize ACME Connection
acme = ACME_Connect.new(endpoint_url, aggrement_url)
acme.account('account.key','hostmaster@example.com')
acme.register

# Request Domain authorization [ 1 ]
authz = acme.authorize("www.example.com")
acme.push_response("/srv/www/www.example.com/.well-known/acme-challenge/", authz["token"])
acme.verify(authz["token"], authz["uri"])
while !acme.verify_check(authz["uri"])
  sleep 1
end

# Request Domain authorization [ 2 ]
authz = acme.authorize("www.example.org")
acme.push_response("/srv/www/www.example.org/.well-known/acme-challenge", authz["token"])
acme.verify(authz["token"], authz["uri"])
while !acme.verify_check(authz["uri"])
  sleep 1
end

# Download Certificate
cert = acme.get_cert('domain.key', 'www.example.com,www.example.org')
File.write('domain.pem', cert)

