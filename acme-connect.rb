require 'openssl'
require 'base64'
require 'net/https'
require 'uri'
require 'json'
require 'logger'

class ACME_Connect

  # Initialize ACME CA Address and Aggrement Document
  def initialize(endpoint, aggrement)
    # Define Logger output
    @logger = Logger.new(STDERR)
    #@logger.level = Logger::WARN
    @logger.level = Logger::INFO

    # ACME instance
    @ACME = endpoint
    @Agreement = aggrement

    # Initialize ACME directory entries
    init_acme_dir
  end

  private
  def b64url(data)
    @b64 = Base64.urlsafe_encode64(data).tr('=','')
  end

  # Load private key
  def load_key(key_file)
    f = File.open(key_file, "r")
    @key = OpenSSL::PKey::RSA.new f.read
  rescue StandardError
    @logger.error("cannot load private key: #{cert_file}")
  ensure
    f.close unless f.nil?
  end

  # Load certificate
  def load_cert(cert_file)
    f = File.open(cert_file, "r")
    @cert = OpenSSL::X509::Certificate.new f.read
  rescue StandardError
    @logger.error("cannot load certificate: #{cert_file}")
  ensure
    f.close unless f.nil?
  end

  # Create Certificate Signing Request from private key and domain name
  def create_csr(key, dom)
    domains = dom.split(",");
    main_domain = domains[0]

    request = OpenSSL::X509::Request.new
    request.version = 0
    request.subject = OpenSSL::X509::Name.new [['CN', main_domain]]
    if domains.length > 1
      dns_names = domains.map {|name| "DNS:#{name}" }.join(", ")
      attrval = create_ext_req([["subjectAltName", dns_names, false]])
      extreq = OpenSSL::X509::Attribute.new("Extension Request", attrval)
      request.add_attribute(extreq)
    end
    request.public_key = key.public_key
    request.sign(key, OpenSSL::Digest::SHA1.new)

    @csr = b64url(request.to_der)
  end

  # Get Account Key Exponent
  def get_exponent
    @exponent = b64url(@account_key.params["e"].to_s(2))
  end

  # Get Account Key Modulus
  def get_modulus
    @modulus = b64url(@account_key.params["n"].to_s(2))
  end

  # Sign Data with Account Key
  def sign_data(key, data)
    digest = OpenSSL::Digest::SHA256.new
    @signature = b64url(key.sign digest, data)
  end

  # Create Certificate Request Extension
  def create_ext_req(exts)
    ef = OpenSSL::X509::ExtensionFactory.new
    exts = exts.collect{|e| ef.create_extension(*e) }
    return OpenSSL::ASN1::Set([OpenSSL::ASN1::Sequence(exts)])
  end

  # Initialize ACME directory entries
  def init_acme_dir
    resp = http_get("#{@ACME}/directory")
    if resp.code == "200"
      @ACME_dir = JSON.parse resp.body
    else
      @logger.error("Cannot initialize ACME server directory [code: #{resp.code}] #{resp.body}")
    end
  end

  # Get new nonce from ACME server
  def get_nonce
    resp = http_get("#{@ACME}/directory")
    if resp.code == "200"
      nonce = resp["replay-nonce"]
      @nonce_response = b64url("{\"nonce\":\"#{nonce}\"}")
    else
      @logger.error("Cannot extract nonce from ACME server [code: #{resp.code}] #{resp.body}")
    end
  end

  # HTTP Get request
  def http_get(url)
    uri = URI.parse(url)
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true

    request = Net::HTTP::Get.new(uri.request_uri)
    @response = http.request(request)
  end

  # HTTP Post request
  def http_post(url, data)
    uri = URI.parse(url)
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true

    request = Net::HTTP::Post.new(uri.path)
    request.add_field('Content-Type', 'application/json')
    request.body = data
    @response = http.request(request)
  end

  # Send signed data to url
  def req_send(url, data)
    payload = b64url(data)
    nonce = get_nonce
    req_signature = sign_data(@account_key, "#{nonce}.#{payload}")

    data = '{"header":'"#{@request_jwks}"',"protected":"'"#{nonce}"'",' +
           '"payload":"'"#{payload}"'","signature":"'"#{req_signature}"'"}'

    @response = http_post(url, data)
  end

  public
  # Set Account details
  def account(key_file, email)
    @account_key = load_key(key_file)
    @account_email = email

    account_jwk = '{"e":"'"#{get_exponent}"'","kty":"RSA","n":"'"#{get_modulus}"'"}'
    @request_jwks = '{"alg":"RS256","jwk":'"#{account_jwk}"'}'
    sha256 = OpenSSL::Digest::SHA256.new
    @account_thumb = b64url(sha256.digest(account_jwk))
  end

  # Register Account
  def register
    new_reg = '{"resource":"new-reg","contact":["mailto:'"#{@account_email}"'"],' +
              '"agreement":"'"#{@Agreement}"'"}'
    resp = req_send(@ACME_dir["new-reg"], new_reg)

    # Check for HTTP return code and parse response   
    case resp.code
      when "201"
        json_resp = JSON.parse resp.body
        @logger.info("New key registered with id: #{json_resp["id"]}")
        return true
      when "400", "409"
        json_resp = JSON.parse resp.body
        @logger.info("#{json_resp["detail"]}")
        return false
      else
        @logger.error("Error during registration Code: #{resp.code}\n#{resp.body}")
        return false
    end
  end

  # Request authorization token and uri for 'domain'
  def authorize(domain)
    new_authz ='{"resource":"new-authz","identifier":{"type":"dns","value":"'"#{domain}"'"}}'
    resp = req_send(@ACME_dir["new-authz"], new_authz)

    # Check for HTTP return code and parse response
    case resp.code
      when "201"
        json_resp = JSON.parse resp.body
        json_resp["challenges"].each do |challenge|
          if challenge["type"] == "http-01"
            @authz = { "token" => challenge["token"], "uri" => challenge["uri"] }
          end
        end
      else
        @logger.error("Error during domain '#{domain}' authorization: #{resp.code}\n#{resp.body}")
        return false
    end
    return @authz
  end

  # Write doamin response to the acme-challenge directory
  def push_response(directory, token)
    domain_response = "#{token}.#{@account_thumb}"

    # Write domain response
    File.write("#{directory}/#{token}", "#{domain_response}\n")
  end

  # Request domain token verification  
  def verify(token, uri)
    data = '{"resource":"challenge","type":"http-01","keyAuthorization":"'"#{token}.#{@account_thumb}"'","token":"'"#{token}"'"}'
    resp = req_send(uri, data)

    # Check for HTTP return code and parse response
    if resp.code == "202"
      json_resp = JSON.parse resp.body
      @logger.info("Triggered domain verification. Status: #{json_resp["status"]}")
    else
      @logger.error("Error during domain verification: #{resp.code}\n#{resp.body}")
    end
  end

  # Check domain verification status
  def verify_check(uri)
    resp = http_get(uri)

    # Check for HTTP return code and parse response
    if resp.code == "202"
      json_resp = JSON.parse resp.body
      @logger.info("Checked domain verification. Status: #{json_resp["status"]}")
      if json_resp["status"] == "valid"
        return true
      else
        return false
      end
    else
      @logger.error("Error during domain verification check: #{resp.code}\n#{resp.body}")
    end
  end

  # Download certificate for domain
  def get_cert(key_file, domain)
    key = load_key(key_file)
    csr = create_csr(key, domain)

    new_csr = '{"resource":"new-cert","csr":"'"#{csr}"'"}'
    resp = req_send(@ACME_dir["new-cert"], new_csr)

    # Check for HTTP return code and write response
    if resp.code == "201"
      cert = OpenSSL::X509::Certificate.new resp.body
      @logger.info("Got certificate for domain '#{domain}'.")
      @cert_pem = cert.to_pem
    else
      @logger.error("Error during domain '#{domain}' certificate download: #{resp.code}\n#{resp.body}")
    end
  end
end

