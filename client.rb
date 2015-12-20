#!/usr/bin/ruby

load 'acme-connect.rb'

# Staging Instance
endpoint_url = "https://acme-staging.api.letsencrypt.org"
aggrement_url = "https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf"

# Here you get the real stuff
#endpoint_url = "https://acme-v01.api.letsencrypt.org/"

acme = ACME_Connect.new(endpoint_url, aggrement_url)
acme.account('account.key','hostmaster@example.com')
acme.register

out = acme.authorize("www.example.com")
acme.push_response("/srv/www/www.example.com/.well-known/acme-challenge", out["token"])
acme.verify(out["token"], out["uri"])

while !acme.verify_check(out["uri"])
  sleep 1
end

cert = acme.get_cert('domain.key', 'www.example.com')
File.write('domain.pem', cert)

