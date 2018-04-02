import datetime
import json
import os
import sys
import time

import acme.challenges
import acme.client
import acme.jose

import click

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

import boto3
import pdb
import OpenSSL.crypto

import rfc3986

from tld import get_tld
import requests
import dns.exception
import dns.resolver

#DEFAULT_ACME_DIRECTORY_URL = "https://acme-v01.api.letsencrypt.org/directory"
DEFAULT_ACME_DIRECTORY_URL = "https://acme-staging.api.letsencrypt.org/directory"
CERTIFICATE_EXPIRATION_THRESHOLD = datetime.timedelta(days=45)
# One day
PERSISTENT_SLEEP_INTERVAL = 60 * 60 * 24
DNS_TTL = 30


class Logger(object):
    def __init__(self):
        self._out = sys.stdout

    def emit(self, event, **data):
        formatted_data = " ".join(
            "{}={!r}".format(k, v) for k, v in data.iteritems()
        )
        self._out.write("{} [{}] {}\n".format(
            datetime.datetime.utcnow().replace(microsecond=0),
            event,
            formatted_data
        ))


class CertificateRequest(object):
    def __init__(self, cert_location, dns_challenge_completer, hosts,
                 key_type):
        self.cert_location = cert_location
        self.dns_challenge_completer = dns_challenge_completer

        self.hosts = hosts
        self.key_type = key_type


class ELBCertificate(object):
    def __init__(self, elb_client, iam_client, elb_name, elb_port):
        self.elb_client = elb_client
        self.iam_client = iam_client
        self.elb_name = elb_name
        self.elb_port = elb_port

    def get_current_certificate(self):
        elb_response = self.elb_client.describe_load_balancers(
            Names=[self.elb_name]
        )

        [description] = elb_response["LoadBalancers"]
        elb_arn = description["LoadBalancerArn"]

        listener_response = self.elb_client.describe_listeners(
            LoadBalancerArn=elb_arn,
        )

        #[certificate_id] = [
        #    listener["Listener"]["SSLCertificateId"]
        #    for listener in description["ListenerDescriptions"]
        #    if listener["Listener"]["LoadBalancerPort"] == self.elb_port
        #]

        for listener in listener_response["Listeners"]:
            if listener["Port"] == self.elb_port:
                cert_list = listener["Certificates"]
                certificate_id = cert_list[0]["CertificateArn"]

        paginator = self.iam_client.get_paginator("list_server_certificates")
        for page in paginator.paginate():
            for server_certificate in page["ServerCertificateMetadataList"]:
                if server_certificate["Arn"] == certificate_id:
                    cert_name = server_certificate["ServerCertificateName"]
                    response = self.iam_client.get_server_certificate(
                        ServerCertificateName=cert_name,
                    )
                    return x509.load_pem_x509_certificate(
                        response["ServerCertificate"]["CertificateBody"],
                        default_backend(),
                    )

    def update_certificate(self, logger, hosts, private_key, pem_certificate,
                           pem_certificate_chain):
        logger.emit(
            "updating-elb.upload-iam-certificate", elb_name=self.elb_name
        )

        response = self.iam_client.upload_server_certificate(
            ServerCertificateName=generate_certificate_name(
                hosts,
                x509.load_pem_x509_certificate(
                    pem_certificate, default_backend()
                )
            ),
            PrivateKey=private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ),
            CertificateBody=pem_certificate,
            CertificateChain=pem_certificate_chain,
        )
        new_cert_arn = response["ServerCertificateMetadata"]["Arn"]
        
        elb_response = self.elb_client.describe_load_balancers(
            Names=[self.elb_name]
        )
 
        [description] = elb_response["LoadBalancers"]
        elb_arn = description["LoadBalancerArn"]

        listener_response = self.elb_client.describe_listeners(
            LoadBalancerArn=elb_arn,
        )

        for listener in listener_response["Listeners"]:
            if listener["Port"] == self.elb_port:
                listener_arn = listener["ListenerArn"]

        # Sleep before trying to set the certificate, it appears to sometimes
        # fail without this.
        time.sleep(15)
        logger.emit("updating-elb.set-elb-certificate", elb_name=self.elb_name)
        #self.elb_client.set_load_balancer_listener_ssl_certificate(
        #    LoadBalancerName=self.elb_name,
        #    SSLCertificateId=new_cert_arn,
        #    LoadBalancerPort=self.elb_port,
        #)
        #self.elb_client.add_listener_certificates(
        self.elb_client.modify_listener(
             ListenerArn=listener_arn,
             Certificates=[
                 {
                     'CertificateArn': new_cert_arn,
                     #'IsDefault': False
                 },
             ]
        )


class CloudFlareChallengeCompleter(object):
    def __init__(self, logger):
        try:
            self.CF_HEADERS = {'X-Auth-Email': os.environ['CF_EMAIL'],
                               'X-Auth-Key': os.environ['CF_KEY'],
                               'Content-Type': 'application/json'}
        except KeyError:
            logger.emit(' + Unable to locate Cloudflare credentials in environment!')
            sys.exit(1)
        try:
            self.dns_servers = os.environ['CF_DNS_SERVERS']
            self.dns_servers = self.dns_servers.split()
        except KeyError:
            self.dns_servers = False

    # https://api.cloudflare.com/#zone-list-zones
    def _get_zone_id(self, domain):
        tld = get_tld('http://' + domain)
        url = "https://api.cloudflare.com/client/v4/zones?name={0}".format(tld)
        r = requests.get(url, headers=self.CF_HEADERS)
        r.raise_for_status()
        return r.json()['result'][0]['id']

    # https://api.cloudflare.com/#dns-records-for-a-zone-dns-record-details
    def _get_txt_record_id(self, logger, zone_id, name, token):
        url = "https://api.cloudflare.com/client/v4/zones/{0}/dns_records?type=TXT&name={1}&content={2}".format(zone_id, name, token)
        r = requests.get(url, headers=self.CF_HEADERS)
        r.raise_for_status()
        try:
            record_id = r.json()['result'][0]['id']
        except IndexError:
            logger.emit(" + Unable to locate record named {0}".format(name))
            return
        return record_id

    # https://api.cloudflare.com/#dns-records-for-a-zone-create-dns-record
    def create_txt_record(self, logger, domain, challenge, token):
        logger.emit(' + Creating TXT record: {0} => {1}'.format(domain, token))
        logger.emit(' + Challenge: {0}'.format(challenge))
        zone_id = self._get_zone_id(domain)
        name = "{0}.{1}".format('_acme-challenge', domain)
        record_id = self._get_txt_record_id(logger, zone_id, name, token)
        if record_id:
            logger.emit(" + TXT record exists, skipping creation.")
            return
        url = "https://api.cloudflare.com/client/v4/zones/{0}/dns_records".format(zone_id)
        payload = {
            'type': 'TXT',
            'name': name,
            'content': token,
            'ttl': 120,
        }
        r = requests.post(url, headers=self.CF_HEADERS, json=payload)
        r.raise_for_status()
        record_id = r.json()['result']['id']
        logger.emit(" + TXT record created, CFID: {0}".format(record_id))

    # https://api.cloudflare.com/#dns-records-for-a-zone-delete-dns-record
    def delete_txt_record(self, logger, domain, token):
        if not domain:
            logger.emit(" + http_request() error in letsencrypt.sh?")
            return

        zone_id = self._get_zone_id(domain)
        name = "{0}.{1}".format('_acme-challenge', domain)
        record_id = self._get_txt_record_id(logger, zone_id, name, token)

        if record_id:
            url = "https://api.cloudflare.com/client/v4/zones/{0}/dns_records/{1}".format(zone_id, record_id)
            r = requests.delete(url, headers=self.CF_HEADERS)
            r.raise_for_status()
            logger.emit(" + Deleted TXT {0}, CFID {1}".format(name, record_id))
        else:
            logger.emit(" + No TXT {0} with token {1}".format(name, token))

    def _has_dns_propagated(self, logger, name, token):
        try:
            if self.dns_servers:
                self.custom_resolver = dns.resolver.Resolver()
                self.custom_resolver.nameservers = self.dns_servers
                self.dns_response = self.custom_resolver.query(name, 'TXT')
            else:
                self.dns_response = dns.resolver.query(name, 'TXT')
            
            for rdata in self.dns_response:
                if token in [b.decode('utf-8') for b in rdata.strings]:
                    return True
                
        except dns.exception.DNSException as e:
            logger.emit(" + {0}. Retrying query...".format(e))
        
        return False


class Route53ChallengeCompleter(object):
    def __init__(self, route53_client, route53_cross_client=None):
        self.route53_client = route53_client
        self.route53_cross_client = route53_cross_client

    # return the session where the DNS zone is located
    def _find_client_for_domain(self, domain):
        if not self.route53_cross_client:
            return self.route53_client

        zones = []
        for client in (self.route53_client, self.route53_cross_client):
            paginator = client.get_paginator("list_hosted_zones")
            for page in paginator.paginate():
                for zone in page["HostedZones"]:    
                    if (
                        domain.endswith(zone["Name"]) or
                        (domain + ".").endswith(zone["Name"])
                       ) and not zone["Config"]["PrivateZone"]:
                           return client

        raise ValueError(
            "Unable to find a Route53 hosted zone for {}".format(domain)
        )

    def _find_zone_id_for_domain(self, domain):
        zones = []
        for client in (self.route53_client, self.route53_cross_client):
            if not client:
                continue
            paginator = client.get_paginator("list_hosted_zones")
            for page in paginator.paginate():
                for zone in page["HostedZones"]:
                    if (
                        domain.endswith(zone["Name"]) or
                        (domain + ".").endswith(zone["Name"])
                       ) and not zone["Config"]["PrivateZone"]:
                           zones.append((zone["Name"], zone["Id"]))

        if not zones:
            raise ValueError(
                "Unable to find a Route53 hosted zone for {}".format(domain)
            )

        # Order the zones that are suffixes for our desired to domain by
        # length, this puts them in an order like:
        # ["foo.bar.baz.com", "bar.baz.com", "baz.com", "com"]
        # And then we choose the last one, which will be the most specific.
        zones.sort(key=lambda z: len(z[0]), reverse=True)
        return zones[0][1]

    def _change_txt_record(self, action, zone_id, domain, value):
        client = self._find_client_for_domain(domain)
        response = client.change_resource_record_sets(
            HostedZoneId=zone_id,
            ChangeBatch={
                "Changes": [
                    {
                        "Action": action,
                        "ResourceRecordSet": {
                            "Name": domain,
                            "Type": "TXT",
                            "TTL": DNS_TTL,
                            "ResourceRecords": [
                                # For some reason TXT records need to be
                                # manually quoted.
                                {"Value": '"{}"'.format(value)}
                            ],
                        }
                    }
                ]
            }
        )
        return response["ChangeInfo"]["Id"]

    def create_txt_record(self, host, value):
        zone_id = self._find_zone_id_for_domain(host)
        change_id = self._change_txt_record(
            "CREATE",
            zone_id,
            host,
            value,
        )
        return (zone_id, change_id)

    def delete_txt_record(self, change_id, host, value):
        zone_id, _ = change_id
        self._change_txt_record(
            "DELETE",
            zone_id,
            host,
            value
        )

    def wait_for_change(self, change_id, host):
        _, change_id = change_id
        client = self._find_client_for_domain(host)

        while True:
            response = client.get_change(Id=change_id)
            if response["ChangeInfo"]["Status"] == "INSYNC":
                return
            time.sleep(5)


def generate_rsa_private_key():
    return rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )


def generate_ecdsa_private_key():
    return ec.generate_private_key(ec.SECP256R1(), backend=default_backend())


def generate_csr(private_key, hosts):
    csr_builder = x509.CertificateSigningRequestBuilder().subject_name(
        # This is the same thing the official letsencrypt client does.
        x509.Name([
            x509.NameAttribute(x509.NameOID.COMMON_NAME, hosts[0]),
        ])
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName(host)
            for host in hosts
        ]),
        # TODO: change to `critical=True` when Let's Encrypt supports it.
        critical=False,
    )
    return csr_builder.sign(private_key, hashes.SHA256(), default_backend())


def find_dns_challenge(authz):
    for combo in authz.body.resolved_combinations:
        if (
            len(combo) == 1 and
            isinstance(combo[0].chall, acme.challenges.DNS01)
        ):
            yield combo[0]


def generate_certificate_name(hosts, cert):
    return "{serial}-{expiration}-{hosts}".format(
        serial=cert.serial,
        expiration=cert.not_valid_after.date(),
        hosts="-".join(h.replace(".", "_") for h in hosts),
    )[:128]


class AuthorizationRecord(object):
    def __init__(self, host, authz, dns_challenge, change_id):
        self.host = host
        self.authz = authz
        self.dns_challenge = dns_challenge
        self.change_id = change_id


def start_dns_challenge(logger, acme_client, dns_challenge_completer,
                        elb_name, host):
    logger.emit(
        "updating-elb.request-acme-challenge", elb_name=elb_name, host=host
    )
    authz = acme_client.request_domain_challenges(
        host, acme_client.directory.new_authz
    )

    [dns_challenge] = find_dns_challenge(authz)

    logger.emit(
        "updating-elb.create-txt-record", elb_name=elb_name, host=host
    )

    domain=host    
    challenge='dns-01'
    token=dns_challenge.validation(acme_client.key)

    dns_challenge_completer.create_txt_record(logger, domain, challenge, token)
    change_id = ''

    return AuthorizationRecord(
        host,
        authz,
        dns_challenge,
        change_id,
    )


def complete_dns_challenge(logger, acme_client, dns_challenge_completer,
                           elb_name, authz_record):
    logger.emit(
        "updating-elb.wait-for-route53",
        elb_name=elb_name, host=authz_record.host
    )

    response = authz_record.dns_challenge.response(acme_client.key)

    logger.emit(
        "updating-elb.local-validation",
        elb_name=elb_name, host=authz_record.host
    )

    name=authz_record.dns_challenge.validation_domain_name(authz_record.host)
    token=authz_record.dns_challenge.validation(acme_client.key)

    while(dns_challenge_completer._has_dns_propagated(logger, name, token) == False):
        logger.emit(" + DNS not propagated, waiting 30s...")
        time.sleep(30)

    verified = response.simple_verify(
        authz_record.dns_challenge.chall,
        authz_record.host,
        acme_client.key.public_key()
    )
    if not verified:
        raise ValueError("Failed verification")

    logger.emit(
        "updating-elb.answer-challenge",
        elb_name=elb_name, host=authz_record.host
    )
    acme_client.answer_challenge(authz_record.dns_challenge, response)


def request_certificate(logger, acme_client, elb_name, authorizations, csr):
    logger.emit("updating-elb.request-cert", elb_name=elb_name)
    cert_response, _ = acme_client.poll_and_request_issuance(
        acme.jose.util.ComparableX509(
            OpenSSL.crypto.load_certificate_request(
                OpenSSL.crypto.FILETYPE_ASN1,
                csr.public_bytes(serialization.Encoding.DER),
            )
        ),
        authzrs=[authz_record.authz for authz_record in authorizations],
    )
    pem_certificate = OpenSSL.crypto.dump_certificate(
        OpenSSL.crypto.FILETYPE_PEM, cert_response.body
    )
    pem_certificate_chain = "\n".join(
        OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
        for cert in acme_client.fetch_chain(cert_response)
    )
    return pem_certificate, pem_certificate_chain


def update_elb(logger, acme_client, force_issue, cert_request):
    logger.emit("updating-elb", elb_name=cert_request.cert_location.elb_name)

    current_cert = cert_request.cert_location.get_current_certificate()

    if current_cert:
        logger.emit(
            "updating-elb.certificate-expiration",
            elb_name=cert_request.cert_location.elb_name,
            expiration_date=current_cert.not_valid_after
        )
        days_until_expiration = (
            current_cert.not_valid_after - datetime.datetime.today()
        )

        try:
            san_extension = current_cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            )
        except x509.ExtensionNotFound:
            # Handle the case where an old certificate doesn't have a SAN extension
            # and always reissue in that case.
            current_domains = []
        else:
            current_domains = san_extension.value.get_values_for_type(x509.DNSName)

        if (
            days_until_expiration > CERTIFICATE_EXPIRATION_THRESHOLD and
            # If the set of hosts we want for our certificate changes, we update
            # even if the current certificate isn't expired.
            sorted(current_domains) == sorted(cert_request.hosts) and
            not force_issue
        ):
            return

    if cert_request.key_type == "rsa":
        private_key = generate_rsa_private_key()
    elif cert_request.key_type == "ecdsa":
        private_key = generate_ecdsa_private_key()
    else:
        raise ValueError(
            "Invalid key_type: {!r}".format(cert_request.key_type)
        )
    csr = generate_csr(private_key, cert_request.hosts)

    authorizations = []
    try:
        for host in cert_request.hosts:
            authz_record = start_dns_challenge(
                logger, acme_client, cert_request.dns_challenge_completer,
                cert_request.cert_location.elb_name, host,
            )
            authorizations.append(authz_record)

        for authz_record in authorizations:
            complete_dns_challenge(
                logger, acme_client, cert_request.dns_challenge_completer,
                cert_request.cert_location.elb_name, authz_record
            )

        pem_certificate, pem_certificate_chain = request_certificate(
            logger, acme_client, cert_request.cert_location.elb_name,
            authorizations, csr
        )

        cert_request.cert_location.update_certificate(
            logger, cert_request.hosts,
            private_key, pem_certificate, pem_certificate_chain
        )
    finally:
        for authz_record in authorizations:
            logger.emit(
                "updating-elb.delete-txt-record",
                elb_name=cert_request.cert_location.elb_name,
                host=authz_record.host
            )
            dns_challenge = authz_record.dns_challenge

            cert_request.dns_challenge_completer.delete_txt_record(
                logger,
                authz_record.host,
                dns_challenge.validation(acme_client.key),
            )


def update_elbs(logger, acme_client, force_issue, certificate_requests):
    for cert_request in certificate_requests:
        update_elb(
            logger,
            acme_client,
            force_issue,
            cert_request,
        )


def setup_acme_client(s3_client, acme_directory_url, acme_account_key):
    uri = rfc3986.urlparse(acme_account_key)
    if uri.scheme == "file":
        if uri.host is None:
            path = uri.path
        elif uri.path is None:
            path = uri.host
        else:
            path = os.path.join(uri.host, uri.path)
        with open(path) as f:
            key = f.read()
    elif uri.scheme == "s3":
        # uri.path includes a leading "/"
        response = s3_client.get_object(Bucket=uri.host, Key=uri.path[1:])
        key = response["Body"].read()
    else:
        raise ValueError(
            "Invalid acme account key: {!r}".format(acme_account_key)
        )

    key = serialization.load_pem_private_key(
        key, password=None, backend=default_backend()
    )
    return acme_client_for_private_key(acme_directory_url, key)


def acme_client_for_private_key(acme_directory_url, private_key):
    return acme.client.Client(
        # TODO: support EC keys, when acme.jose does.
        acme_directory_url, key=acme.jose.JWKRSA(key=private_key)
    )


@click.group()
def cli():
    pass


@cli.command(name="update-certificates")
@click.option(
    "--persistent", is_flag=True, help="Runs in a loop, instead of just once."
)
@click.option(
    "--force-issue", is_flag=True, help=(
        "Issue a new certificate, even if the old one isn't close to "
        "expiration."
    )
)
@click.option(
    "--cross-profile", help="Specify your profile for ELB and IAM modifications."
)
def update_certificates(persistent=False, force_issue=False, cross_profile=False):
    logger = Logger()
    logger.emit("startup")

    if persistent and force_issue:
        raise ValueError("Can't specify both --persistent and --force-issue")

    session = boto3.Session()
    s3_client = session.client("s3")
    route53_client = session.client("route53")
    if cross_profile:
        cross_session = boto3.Session(profile_name=cross_profile)
        elb_client = cross_session.client("elbv2")
        iam_client = cross_session.client("iam")
        route53_cross_client = cross_session.client("route53")
    else:
        elb_client = session.client("elbv2")
        iam_client = session.client("iam")
        route53_cross_client = None

    config = json.loads(os.environ["LETSENCRYPT_AWS_CONFIG"])
    domains = config["domains"]
    acme_directory_url = config.get(
        "acme_directory_url", DEFAULT_ACME_DIRECTORY_URL
    )
    acme_account_key = config["acme_account_key"]
    acme_client = setup_acme_client(
        s3_client, acme_directory_url, acme_account_key
    )

    certificate_requests = []
    for domain in domains:
        if "elb" in domain:
            cert_location = ELBCertificate(
                elb_client, iam_client,
                domain["elb"]["name"], int(domain["elb"].get("port", 443))
            )
        else:
            raise ValueError(
                "Unknown certificate location: {!r}".format(domain)
            )

        certificate_requests.append(CertificateRequest(
            cert_location,
            CloudFlareChallengeCompleter(logger),
            #Route53ChallengeCompleter(route53_client, route53_cross_client),
            domain["hosts"],
            domain.get("key_type", "rsa"),
        ))

    if persistent:
        logger.emit("running", mode="persistent")
        while True:
            update_elbs(
                logger, acme_client,
                force_issue, certificate_requests
            )
            # Sleep before we check again
            logger.emit("sleeping", duration=PERSISTENT_SLEEP_INTERVAL)
            time.sleep(PERSISTENT_SLEEP_INTERVAL)
    else:
        logger.emit("running", mode="single")
        update_elbs(
            logger, acme_client,
            force_issue, certificate_requests
        )


@cli.command()
@click.argument("email")
@click.option(
    "--out",
    type=click.File("w"),
    default="-",
    help="Where to write the private key to. Defaults to stdout."
)
def register(email, out):
    logger = Logger()
    config = json.loads(os.environ.get("LETSENCRYPT_AWS_CONFIG", "{}"))
    acme_directory_url = config.get(
        "acme_directory_url", DEFAULT_ACME_DIRECTORY_URL
    )

    logger.emit("acme-register.generate-key")
    private_key = generate_rsa_private_key()
    acme_client = acme_client_for_private_key(acme_directory_url, private_key)

    logger.emit("acme-register.register", email=email)
    registration = acme_client.register(
        acme.messages.NewRegistration.from_data(email=email)
    )
    logger.emit("acme-register.agree-to-tos")
    acme_client.agree_to_tos(registration)
    out.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ))


if __name__ == "__main__":
    cli()
