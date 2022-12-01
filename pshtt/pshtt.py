#!/usr/bin/env python

from . import utils
from .models import Domain, Endpoint
from publicsuffix import PublicSuffixList
from publicsuffix import fetch

import requests
import re
import base64
import json
import os
import shutil
import logging
import sys
import codecs
import OpenSSL
import threading
import datetime

from OpenSSL import crypto
import certifi
from OpenSSL.crypto import X509Store, X509StoreContext

try:
    from urllib import parse as urlparse  # Python 3
except ImportError:
    import urlparse  # Python 2

try:
    from urllib.error import URLError
except ImportError:
    from urllib2 import URLError

import sslyze
from sslyze.server_connectivity_tester import ServerConnectivityTester, ServerConnectivityError
import sslyze.synchronous_scanner

# We're going to be making requests with certificate validation
# disabled.  Commented next line due to pylint warning that urllib3 is
# not in requests.packages
# requests.packages.urllib3.disable_warnings()
import urllib3
urllib3.disable_warnings()

# Default, overrideable via --user-agent
USER_AGENT = "pshtt, https scanning"

# Defaults to 5 second, overrideable via --timeout
TIMEOUT = 5

# Defaults to not scanning special ADFS URLs for HSTS headers
# overrrideable via --scan-adfs
SCAN_ADFS = False

# Synchronization lock between threads to ensure that only one thread runs the
# initialization function, but that all threads wait for it to finish before
# they continue
init_lock = threading.RLock()

# Global DNS resovers
DNS_RESOLVER = None
DNS_RESOLVERS_DEFAULT = ['8.8.8.8, 8.8.4.4, 1.1.1.1, 9.9.9.9']

# The fields we're collecting, will be keys in JSON and
# column headers in CSV.
HEADERS = [
    "Domain", "Base Domain", "Canonical URL", "Live",
    "HTTPS Live", "HTTPS Full Connection", "HTTPS Client Auth Required",
    "Redirect", "Redirect To",
    "Valid HTTPS", "HTTPS Publicly Trusted", "HTTPS Custom Truststore Trusted",
    "Defaults to HTTPS", "Downgrades HTTPS", "Strictly Forces HTTPS",
    "HTTPS Bad Chain", "HTTPS Bad Hostname", "HTTPS Expired Cert",
    "HTTPS Self Signed Cert",
    "HSTS", "HSTS Header", "HSTS Max Age", "HSTS Entire Domain",
    "HSTS Preload Ready", "HSTS Preload Pending", "HSTS Preloaded",
    "Base Domain HSTS Preloaded", "Domain Supports HTTPS",
    "Domain Enforces HTTPS", "Domain Uses Strong HSTS", "IP",
    "Server Header", "Server Version", "Status Code", "HTTPS Cert Chain Length",
    "HTTPS Probably Missing Intermediate Cert", "Notes", "Unknown Error",
]

# Used for caching the HSTS preload list from Chromium's source.
cache_preload_list_default = "preloaded.json"
preload_list = None

# Used for caching the HSTS pending preload list from hstspreload.org.
cache_preload_pending_default = "preload-pending.json"
preload_pending = None

# Used for determining base domain via Mozilla's public suffix list.
cache_suffix_list_default = "public-suffix-list.txt"
suffix_list = None

# Directory to cache all third party responses, if set by user.
THIRD_PARTIES_CACHE = None

# Set if user wants to use a custom CA bundle
CA_FILE = None
STORE = "Mozilla"
PT_INT_CA_FILE = None

# Flag for whether to save names in certificates to a file to gather data for other efforts
SAVE_CERT_NAMES = False
CERT_NAMES_FILENAME = "./cache/cert_names.csv"

# Variable to cache DNS responses
DNS_CACHE = {}

def inspect(base_domain, options=None):
    domain = Domain(base_domain)
    domain.http = Endpoint("http", "root", base_domain)
    domain.httpwww = Endpoint("http", "www", base_domain)
    domain.https = Endpoint("https", "root", base_domain)
    domain.httpswww = Endpoint("https", "www", base_domain)

    # Load preload lists into the Domain object so we don't lose them to other slices
    if options is not None:
        domain.preload_list = options.get('preload_list', None)
        domain.preload_pending = options.get('preload_pending', None)

    # Analyze HTTP endpoint responsiveness and behavior.
    basic_check(domain.http)
    basic_check(domain.httpwww)
    basic_check(domain.https)
    basic_check(domain.httpswww)

    # Analyze HSTS header, if present, on each HTTPS endpoint.
    hsts_check(domain.https)
    hsts_check(domain.httpswww)

    return result_for(domain)


def result_for(domain):

    # print(utils.json_for(domain.to_object()))

    # Because it will inform many other judgments, first identify
    # an acceptable "canonical" URL for the domain.
    domain.canonical = canonical_endpoint(domain.http, domain.httpwww, domain.https, domain.httpswww)

    # First, the basic fields the CSV will use.
    result = {
        'Domain': domain.domain,
        'Base Domain': parent_domain_for(domain.domain),
        'Canonical URL': domain.canonical.url,
        'Live': is_live(domain),
        'Redirect': is_redirect_domain(domain),
        'Redirect To': redirects_to(domain),

        'HTTPS Live': is_https_live(domain),
        'HTTPS Full Connection': is_full_connection(domain),
        'HTTPS Client Auth Required': is_client_auth_required(domain),

        'Valid HTTPS': is_valid_https(domain),
        'HTTPS Publicly Trusted': is_publicly_trusted(domain),
        'HTTPS Custom Truststore Trusted': is_custom_trusted(domain),
        'Defaults to HTTPS': is_defaults_to_https(domain),
        'Downgrades HTTPS': is_downgrades_https(domain),
        'Strictly Forces HTTPS': is_strictly_forces_https(domain),

        'HTTPS Bad Chain': is_bad_chain(domain),
        'HTTPS Bad Hostname': is_bad_hostname(domain),
        'HTTPS Expired Cert': is_expired_cert(domain),
        'HTTPS Self Signed Cert': is_self_signed_cert(domain),
        'HTTPS Cert Chain Length': cert_chain_length(domain),
        'HTTPS Probably Missing Intermediate Cert': is_missing_intermediate_cert(domain),

        'HSTS': is_hsts(domain),
        'HSTS Header': hsts_header(domain),
        'HSTS Max Age': hsts_max_age(domain),
        'HSTS Entire Domain': is_hsts_entire_domain(domain),
        'HSTS Preload Ready': is_hsts_preload_ready(domain),
        'HSTS Preload Pending': is_hsts_preload_pending(domain),
        'HSTS Preloaded': is_hsts_preloaded(domain),
        'Base Domain HSTS Preloaded': is_parent_hsts_preloaded(domain),

        'Domain Supports HTTPS': is_domain_supports_https(domain),
        'Domain Enforces HTTPS': is_domain_enforces_https(domain),
        'Domain Uses Strong HSTS': is_domain_strong_hsts(domain),

        'IP': get_domain_ip(domain),
        'Server Header': get_domain_server_header(domain),
        'Server Version': get_domain_server_version(domain),
        'Status Code': get_domain_status_code(domain),
        'Notes': get_domain_notes(domain),
        'Unknown Error': did_domain_error(domain),
    }

    # But also capture the extended data for those who want it.
    result['endpoints'] = domain.to_object()

    # Convert Header fields from None to False, except for a bunch that should remain None to indicate an unknown status:
    for header in HEADERS:
        if header in ('HSTS Header', 'HSTS Max Age', 'Redirect To', 
            'IP', 'Server Header', 'Server Version', 'HTTPS Cert Chain Length', 
            'Valid HTTPS', 'HTTPS Publicly Trusted', 'HTTPS Custom Truststore Trusted',
            'HTTPS Bad Chain', 'HTTPS Bad Hostname', 'HTTPS Expired Cert', 'HTTPS Self Signed Cert',
            'HTTPS Probably Missing Intermediate Cert'):
            continue

        if not result['HTTPS Full Connection'] or result['HSTS'] is None:
            if header in ('HSTS', 'HSTS Entire Domain', 'HSTS Preload Ready', 'Domain Uses Strong HSTS'):
                result[header] = None
                continue

        if result[header] is None:
            result[header] = False

    return result


sock_requests = requests.packages.urllib3.contrib.pyopenssl.WrappedSocket


def new_getpeercertchain(self, *args, **kwargs):
    x509 = self.connection.get_peer_cert_chain()
    return x509


sock_requests.getpeercertchain = new_getpeercertchain

HTTPResponse = requests.packages.urllib3.response.HTTPResponse
orig_HTTPResponse__init__ = HTTPResponse.__init__


def new_HTTPResponse__init__(self, *args, **kwargs):
    orig_HTTPResponse__init__(self, *args, **kwargs)
    try:
        self.peercertchain = self._connection.sock.getpeercertchain()
    except AttributeError:
        pass


HTTPResponse.__init__ = new_HTTPResponse__init__

HTTPAdapter = requests.adapters.HTTPAdapter
orig_HTTPAdapter_build_response = HTTPAdapter.build_response


def new_HTTPAdapter_build_response(self, request, resp):
    response = orig_HTTPAdapter_build_response(self, request, resp)
    try:
        response.peercertchain = resp.peercertchain
    except AttributeError:
        pass
    return response


HTTPAdapter.build_response = new_HTTPAdapter_build_response

from urllib3.util import connection
import dns.resolver


def do_dns_lookup(hostname):
    answer = None
    if hostname in DNS_CACHE:
        # logging.debug('{}: Getting from DNS cache {}'.format(hostname, hostname))
        answer = DNS_CACHE[hostname]
        if isinstance(answer, Exception):
            # logging.debug('{}: Found exception in DNS cache {}'.format(hostname, hostname))
            raise answer
    else:
        try:
            answer = DNS_RESOLVER.query(hostname)
            DNS_CACHE[hostname] = answer
        except Exception as ex:
            DNS_CACHE[hostname] = ex
            raise ex
    return answer


_orig_create_connection = connection.create_connection


def patched_create_connection(address, *args, **kwargs):
    """Wrap urllib3's create_connection to resolve the name elsewhere"""
    host, port = address
    answer = do_dns_lookup(host)
    ip = answer.rrset[0].address
    return _orig_create_connection((ip, port), *args, **kwargs)


# from sslyze.server_connectivity_tester import ServerConnectivityTester _orig_do_dns_lookup = ServerConnectivityTester._do_dns_lookup


def patched_do_dns_lookup(cls, hostname: str, port: int) -> str:
    """Wrap sslyze's _do_dns_lookup to resolve the name using specified DNS"""
    answer = do_dns_lookup(hostname)
    ip = answer.rrset[0].address
    return ip


def initialize_dns_resolver(options=None):
    """ Initializes a DNS resolver with the DNS nameservers from
    the command-line argument or the default system ones
    """
    global DNS_RESOLVER, DNS_RESOLVERS_DEFAULT, TIMEOUT
    # ensure that only one thread runs this init function, and have all threads wait until it finishes
    init_lock.acquire()
    if DNS_RESOLVER is not None:
        init_lock.release()
        return
    DNS_RESOLVER = dns.resolver.Resolver()
    DNS_RESOLVER.timeout = TIMEOUT
    DNS_RESOLVER.lifetime = TIMEOUT
    if options and options.get('dns'):
        DNS_RESOLVER.nameservers = options['dns']
        logging.debug('Initializing DNS resolver using passed in DNS nameservers: {}'.format(DNS_RESOLVER.nameservers))
    if not DNS_RESOLVER.nameservers:
        DNS_RESOLVER.nameservers = DNS_RESOLVERS_DEFAULT
        logging.debug('Initializing DNS resolver using default DNS nameservers: {}'.format(DNS_RESOLVER.nameservers))
    connection.create_connection = patched_create_connection
    ServerConnectivityTester._do_dns_lookup = patched_do_dns_lookup
    init_lock.release()
    return


def ping(url, allow_redirects=False, verify=True):
    """
    If there is a custom CA file and we want to verify
    use that instead when pinging with requests

    By changing the verify param from a boolean to a .pem file, the
    requests module will use the .pem to validate HTTPS connections.

    Note that we are using the streaming variant of the
    python-requests library here and we are not actually reading the
    content of the request.  As a result, the close() method MUST be
    called on the Request object returned by this method.  That is the
    ONLY way the connection can be closed and released back into the
    pool.  One way to ensure this happens is to use the "with" Python
    construct.

    If we ever begin reading response bodies, they will need to be
    explicitly read from Response.content, and we will also want to
    use conditional logic to read from response bodies where they
    exist and are useful. We'll also need to watch for Content-Type
    values like multipart/x-mixed-replace;boundary=ffserver that
    indicate that the response body will stream indefinitely.
    """
    global CA_FILE
    if CA_FILE and verify:
        verify = CA_FILE
        # logging.debug("Using CA_FILE from {}".format(verify))

    return requests.get(
        url,

        allow_redirects=allow_redirects,

        # Validate certificates.
        verify=verify,

        # Setting this to true delays the retrieval of the content
        # until we access Response.content.  Since we aren't
        # interested in the actual content of the request, this will
        # save us time and bandwidth.
        #
        # This will also stop pshtt from hanging on URLs that stream
        # neverending data, like webcams.  See issue #138:
        # https://github.com/dhs-ncats/pshtt/issues/138
        stream=True,

        # set by --user_agent
        headers={'User-Agent': USER_AGENT},

        # set by --timeout, connect timeout is timeout, 
        # read timeout is 5 times longer for slow servers
        timeout=(TIMEOUT, 5 * TIMEOUT)
    )


def basic_check(endpoint):
    """
    Test the endpoint. At first:

    * Don't follow redirects. (Will only follow if necessary.)
      If it's a 3XX, we'll ping again to follow redirects. This is
      necessary to reliably scope any errors (e.g. TLS errors) to
      the original endpoint.

    * Validate certificates. (Will figure out error if necessary.)
    """
    global SCAN_ADFS

    utils.debug("Pinging %s..." % endpoint.url, divider=True)

    req = None

    try:
        with ping(endpoint.url) as req:
            endpoint.live = True
            if endpoint.protocol == "https":
                endpoint.https_full_connection = True
                endpoint.https_valid = True

    except requests.exceptions.SSLError as err:
        if (
                "bad handshake" in str(err) and (
                    "sslv3 alert handshake failure" in str(err) or (
                        "Unexpected EOF" in str(err)
                    )
                )
        ):
            logging.warning("{}: Error completing TLS handshake usually due to required client authentication.".format(endpoint.url))
            utils.debug("  {}: {}".format(endpoint.url, err))
            endpoint.live = True
            if endpoint.protocol == "https":
                # The https can still be valid with a handshake error,
                # sslyze will run later and check if it is not valid
                endpoint.https_valid = True
                endpoint.https_full_connection = False

        else:
            logging.warning("{}: Error connecting over SSL/TLS or validating certificate.".format(endpoint.url))
            utils.debug("  {}: {}".format(endpoint.url, err))

            # Retry with certificate validation disabled.
            try:
                with ping(endpoint.url, verify=False) as req:
                    endpoint.live = True
                    if endpoint.protocol == "https":
                        endpoint.https_full_connection = True
                        # sslyze later will actually check if the cert is valid
                        endpoint.https_valid = True
            except requests.exceptions.SSLError as err:
                # If it's a protocol error or other, it's not a full connection,
                # but it is live.
                endpoint.live = True
                if endpoint.protocol == "https":
                    endpoint.https_full_connection = False
                    # HTTPS may still be valid, sslyze will double-check later
                    endpoint.https_valid = True
                logging.warning("{}: Unexpected SSL protocol (or other) error during retry.".format(endpoint.url))
                utils.debug("  {}: {}".format(endpoint.url, err))
                # continue on to SSLyze to check the connection
            except requests.exceptions.RequestException as err:
                endpoint.live = False
                logging.warning("{}: Unexpected requests exception during retry.".format(endpoint.url))
                utils.debug("  {}: {}".format(endpoint.url, err))
                return
            except OpenSSL.SSL.Error as err:
                endpoint.live = False
                logging.warning("{}: Unexpected OpenSSL exception during retry.".format(endpoint.url))
                utils.debug("  {}: {}".format(endpoint.url, err))
                return
            except Exception as err:
                endpoint.unknown_error = True
                logging.warning("{}: Unexpected other unknown exception during requests retry.".format(endpoint.url))
                utils.debug("  {}: {}".format(endpoint.url, err))
                return

            # If HTTPS, examine certificate to see if there are intermediate certificates that can be trusted that are missing
            if endpoint.protocol == "https" and req:
                try:
                    certchain = req.peercertchain
                    checkCertChain(endpoint, certchain)
                except Exception as err:
                    logging.debug("{}: Error getting peercertchain to check for intermediate certs.".format(endpoint.url))

        # If it was a certificate error of any kind, it's live,
        # unless SSLyze encounters a connection error later
        endpoint.live = True

    except requests.exceptions.ConnectionError as err:
        # We can get this for some endpoints that are actually live,
        # so if it's https let's try sslyze to be sure
        if(endpoint.protocol == "https"):
            # https check later will set whether the endpoint is live and valid
            endpoint.https_full_connection = False
            endpoint.https_valid = True
        else:
            endpoint.live = False
        logging.warning("{}: Error connecting.".format(endpoint.url))
        utils.debug("  {}: {}".format(endpoint.url, err))

    except dns.exception.DNSException as err:
        endpoint.live = False
        logging.warning("{}: DNS exception performing web request.".format(endpoint.url))
        utils.debug("  {}: {}".format(endpoint.url, err))
        return

    # And this is the parent of ConnectionError and other things.
    # For example, "too many redirects".
    # See https://github.com/kennethreitz/requests/blob/master/requests/exceptions.py
    except requests.exceptions.RequestException as err:
        endpoint.live = False
        logging.warning("{}: Unexpected other requests exception.".format(endpoint.url))
        utils.debug("  {}: {}".format(endpoint.url, err))
        return

    except Exception as err:
        endpoint.unknown_error = True
        logging.warning("{}: Unexpected other unknown exception during initial request.".format(endpoint.url))
        utils.debug("  {}: {}".format(endpoint.url, err))
        return

    # Run SSLyze to see if there are any errors
    if(endpoint.protocol == "https"):
        https_check(endpoint)
        # Double-check in case sslyze failed the first time, but the regular conneciton succeeded
        if(endpoint.live is False and req is not None):
            logging.warning("{}: Trying sslyze again since it connected once already.".format(endpoint.url))
            endpoint.live = True
            endpoint.https_valid = True
            https_check(endpoint)
            if(endpoint.live is False):
                # sslyze failed so back everything out and don't continue analyzing the existing response
                req = None
                endpoint.https_valid = False
                endpoint.https_full_connection = False

    if req is None:
        # Ensure that full_connection is set to False if we didn't get a response
        if endpoint.protocol == "https":
            endpoint.https_full_connection = False
        return

    # try to get IP address if we can
    try:
        if req.raw.closed is False:
            ip = req.raw._connection.sock.socket.getpeername()[0]
            if endpoint.ip is None:
                endpoint.ip = ip
            else:
                if endpoint.ip != ip:
                    utils.debug("{}: Endpoint IP is already {}, but requests IP is {}.".format(endpoint.url, endpoint.ip, ip))
    except Exception:
        # if the socket has already closed, it will throw an exception, but this is just best effort, so ignore it
        pass

    # Endpoint is live, analyze the response.
    endpoint.headers = req.headers

    endpoint.status = req.status_code

    if (req.headers.get('Server') is not None):
        endpoint.server_header = req.headers.get('Server')
        # *** in the future add logic to convert header to server version if known

    if (req.headers.get('Location') is not None) and str(endpoint.status).startswith('3'):
        endpoint.redirect = True
        logging.warning("{}: Found redirect.".format(endpoint.url))

    endpoint.ultimate_req = req
    ultimate_req = None
    if endpoint.redirect:
        try:
            location_header = req.headers.get('Location')
            # Absolute redirects (e.g. "https://example.com/Index.aspx")
            if location_header.startswith("http:") or location_header.startswith("https:"):
                immediate = location_header

            # Relative redirects (e.g. "Location: /Index.aspx").
            # Construct absolute URI, relative to original request.
            else:
                immediate = urlparse.urljoin(endpoint.url, location_header)

            # Chase down the ultimate destination, ignoring any certificate warnings.
            ultimate_req = None
        except Exception as err:
            endpoint.unknown_error = True
            logging.warning("{}: Unexpected other unknown exception when handling Requests Header.".format(endpoint.url))
            utils.debug("  {} {}".format(endpoint.url, err))

        try:
            with ping(endpoint.url, allow_redirects=True, verify=False) as ultimate_req:
                pass
        except requests.exceptions.RequestException as err:
            # Swallow connection errors, but we won't be saving redirect info.
            logging.debug("{}: Unexpected exception when trying to follow redirect. {}.".format(endpoint.url, err))
            pass
        except OpenSSL.SSL.Error as err:
            # Swallow connection errors, but we won't be saving redirect info.
            logging.debug("{}: Unexpected exception when trying to follow redirect. {}.".format(endpoint.url, err))
            pass
        except dns.exception.DNSException as err:
            logging.debug("{}: Unexpected exception when trying to follow redirect. {}.".format(endpoint.url, err))
            pass
        except Exception as err:
            endpoint.unknown_error = True
            logging.warning("{}: Unexpected other unknown exception when handling redirect.".format(endpoint.url))
            utils.debug("  {}: {}".format(endpoint.url, err))
            pass

        try:
            # Now establish whether the redirects were:
            # * internal (same exact hostname),
            # * within the zone (any subdomain within the parent domain)
            # * external (on some other parent domain)

            # The hostname of the endpoint (e.g. "www.agency.gov")
            subdomain_original = urlparse.urlparse(endpoint.url).hostname
            # The parent domain of the endpoint (e.g. "agency.gov")
            base_original = parent_domain_for(subdomain_original)

            # The hostname of the immediate redirect.
            # The parent domain of the immediate redirect.
            subdomain_immediate = urlparse.urlparse(immediate).hostname
            base_immediate = parent_domain_for(subdomain_immediate)

            endpoint.redirect_immediately_to = immediate
            endpoint.redirect_immediately_to_https = immediate.startswith("https://")
            endpoint.redirect_immediately_to_http = immediate.startswith("http://")
            endpoint.redirect_immediately_to_external = (base_original != base_immediate)
            endpoint.redirect_immediately_to_subdomain = (
                (base_original == base_immediate) and
                (subdomain_original != subdomain_immediate)
            )

            # We're interested in whether an endpoint redirects to the www version
            # of itself (not whether it redirects to www prepended to any other
            # hostname, even within the same parent domain).
            endpoint.redirect_immediately_to_www = (
                subdomain_immediate == ("www.%s" % subdomain_original)
            )

            if ultimate_req is not None:
                # For ultimate destination, use the URL we arrived at,
                # not Location header. Auto-resolves relative redirects.
                eventual = ultimate_req.url

                # The hostname of the eventual destination.
                # The parent domain of the eventual destination.
                subdomain_eventual = urlparse.urlparse(eventual).hostname
                base_eventual = parent_domain_for(subdomain_eventual)

                endpoint.redirect_eventually_to = eventual
                endpoint.redirect_eventually_to_https = eventual.startswith("https://")
                endpoint.redirect_eventually_to_http = eventual.startswith("http://")
                endpoint.redirect_eventually_to_external = (base_original != base_eventual)
                endpoint.redirect_eventually_to_subdomain = (
                    (base_original == base_eventual) and
                    (subdomain_original != subdomain_eventual)
                )

                # Store the redirected response to check for HSTS later
                endpoint.ultimate_req = ultimate_req

            # If we were able to make the first redirect, but not the ultimate redirect,
            # and if the immediate redirect is external, then it's accurate enough to
            # say that the eventual redirect is the immediate redirect, since you're capturing
            # the domain it's going to.
            # This also avoids "punishing" the domain for configuration issues of the site
            # it redirects to.
            elif endpoint.redirect_immediately_to_external:
                endpoint.redirect_eventually_to = endpoint.redirect_immediately_to
                endpoint.redirect_eventually_to_https = endpoint.redirect_immediately_to_https
                endpoint.redirect_eventually_to_http = endpoint.redirect_immediately_to_http
                endpoint.redirect_eventually_to_external = endpoint.redirect_immediately_to_external
                endpoint.redirect_eventually_to_subdomain = endpoint.redirect_immediately_to_subdomain
        except Exception as err:
            endpoint.unknown_error = True
            logging.warning("{}: Unexpected other unknown exception when establishing redirects.".format(endpoint.url))
            utils.debug("  {}: {}".format(endpoint.url, err))

    # if HTTPS and no HSTS check ADFS URL for HSTS (special case)
    try:
        if SCAN_ADFS and endpoint.protocol == "https" and not endpoint.https_bad_hostname:
            hsts_check(endpoint)
            if endpoint.hsts is not True:
                try:
                    utils.debug("{}: Trying ADFS URL for HSTS check at {}.".format(endpoint.url, endpoint.url + "/adfs/ls/"))
                    with ping(endpoint.url + "/adfs/ls/", allow_redirects=False, verify=False) as adfs_req:
                        pass
                except requests.exceptions.RequestException:
                    # Swallow connection errors
                    pass
                except OpenSSL.SSL.Error:
                    # Swallow connection errors, but we won't be saving redirect info.
                    pass
                except Exception as err:
                    logging.warning("{}: Unexpected other unknown exception when handling adfs test.".format(endpoint.url))
                    utils.debug("  {}: {}".format(endpoint.url, err))

                if adfs_req is not None:
                    header = adfs_req.headers.get("Strict-Transport-Security")
                    if header is None:
                        utils.debug("{}: Found ADFS URL (status code {}), but no HSTS.".format(endpoint.url, adfs_req.status_code))
                    else:
                        if adfs_req.status_code == 200:
                            endpoint.adfs_req = adfs_req
                            utils.debug("{}: Found ADFS URL (status code {}) with HSTS '{}'.".format(endpoint.url, adfs_req.status_code, header))
                        else:
                            utils.debug("{}: Found ADFS URL, but not using since status is not 200 (status code {}) with HSTS '{}'.".format(endpoint.url, adfs_req.status_code, header))
                else:
                    utils.debug("{}: No response for ADFS URL.".format(endpoint.url))
    except Exception as err:
        logging.warning("{}: Unexpected other unknown exception when handling adfs test.".format(endpoint.url))
        utils.debug("  {}: {}".format(endpoint.url, err))

    check_redirect_chain(endpoint)


def check_redirect_chain(endpoint):
    try:
        downgrade = False
        https = False
        if "https://" in endpoint.url:
            https = True
        redirects = []
        redirect_chain = []
        if endpoint.ultimate_req is not None:
            if endpoint.ultimate_req.history:
                redirects.extend(endpoint.ultimate_req.history)
            redirects.append(endpoint.ultimate_req)
        else:
            redirects.append(endpoint)
        if endpoint.adfs_req:
            redirects.append(endpoint.adfs_req)
        for redirect_entry in redirects:
            entry_downgrade = ""
            entry_https = "HTTP"
            entry_hsts = ""
            entry_status = ""
            if redirect_entry.status_code:
                entry_status = str(redirect_entry.status_code)
            if "https://" in redirect_entry.url:
                https = True
                entry_https = "HTTPS"
                if "/adfs/" in redirect_entry.url:
                    entry_https = "ADFS_HTTPS"
                if redirect_entry.headers.get("Strict-Transport-Security"):
                    entry_hsts = "+HSTS"
                if redirect_entry.status_code == 307 and redirect_entry.headers and "/adfs/ls?" in redirect_entry.headers.get("Location"):
                    entry_status = "307+ADFS_REDIRECT (No HSTS Check)"
            if https and "http://" in redirect_entry.url:
                downgrade = True
                entry_downgrade = "-Downgrade"
                logging.warning("{}: Downgrade in redirect to {}.".format(endpoint.url, redirect_entry.url))
            redirect_chain.append("{} ({}{}{} {})".format(redirect_entry.url, entry_https, entry_hsts, entry_downgrade, entry_status))
        if downgrade:
            logging.warning("{}: Downgrade found in redirect chain {}.".format(endpoint.url, redirect_chain))
        endpoint.redirect_chain = redirect_chain
        endpoint.notes = str(redirect_chain)
    except Exception as err:
        logging.warning("{}: Unexpected exception when checking for downgrades in redirects.".format(endpoint.url))
        utils.debug("  {}: {}".format(endpoint.url, err))


def hsts_check(endpoint):
    """
    Given an endpoint and its detected headers, extract and parse
    any present HSTS header, decide what HSTS properties are there.

    Disqualify domains with a bad host, they won't work as valid HSTS.
    """
    global SCAN_ADFS
    try:
        if not endpoint.live or len(endpoint.headers) == 0:
            return

        header = endpoint.headers.get("Strict-Transport-Security")

        if header is None and endpoint.ultimate_req and endpoint.url in endpoint.ultimate_req.url:
            header = endpoint.ultimate_req.headers.get("Strict-Transport-Security")

        if header is None and endpoint.ultimate_req and endpoint.ultimate_req.history:
            for entry in endpoint.ultimate_req.history:
                if header is None and endpoint.url in entry.url:
                    header = entry.headers.get("Strict-Transport-Security")

        if header is None and endpoint.adfs_req:
            header = endpoint.adfs_req.headers.get("Strict-Transport-Security")

        if header is None:
            if SCAN_ADFS and endpoint.status == 307 and "/adfs/ls?" in endpoint.headers.get("Location"):
                endpoint.hsts = None
                logging.warning("{}: Found 307 redirect to ADFS, so not checking HSTS.".format(endpoint.url))
                return
            else:
                endpoint.hsts = False
                return

        endpoint.hsts_header = header

        if endpoint.https_bad_hostname:
            endpoint.hsts = False
            return

        endpoint.hsts = True

        # Set max age to the string after max-age
        # TODO: make this more resilient to pathological HSTS headers.

        # handle multiple HSTS directives, requests comma-separates them
        first_pass = re.split(r',\s?', header)[0]
        second_pass = re.sub(r'\'', '', first_pass)
        third_pass = re.sub(r'\s', '', second_pass)

        temp = re.split(r';\s?', third_pass)

        # only looks for max-age in the first directive, technically should look at each directive
        if "max-age" in header.lower():
            endpoint.hsts_max_age = int(temp[0][len("max-age="):])

        if endpoint.hsts_max_age is None or endpoint.hsts_max_age <= 0:
            endpoint.hsts = False
            return

        # check if hsts includes sub domains
        if 'includesubdomains' in header.lower():
            endpoint.hsts_all_subdomains = True

        # Check is hsts has the preload flag
        if 'preload' in header.lower():
            endpoint.hsts_preload = True
    except Exception as err:
        endpoint.unknown_error = True
        logging.warning("{}: Unknown exception when handling HSTS check.".format(endpoint.url))
        utils.debug("  {}: {}".format(endpoint.url, err))
        return

from sslyze.server_connectivity_info import ServerConnectivityInfo
from sslyze.utils.ssl_connection import SslConnection
_orig_get_preconfigured_ssl_connection = ServerConnectivityInfo.get_preconfigured_ssl_connection

def patched_get_preconfigured_ssl_connection(
        self,
        override_ssl_version = None,
        ssl_verify_locations = None,
        should_use_legacy_openssl = None,
    ) -> SslConnection:
	return _orig_get_preconfigured_ssl_connection(
        self,
        override_ssl_version,
        ssl_verify_locations,
        should_use_legacy_openssl = False
    )


# Perform one-time initialization
def init(environment, options):
    utils.debug("Initializing pshtt (patching sslyze legacy ssl client function)...")
    ServerConnectivityInfo.get_preconfigured_ssl_connection = patched_get_preconfigured_ssl_connection

    if SAVE_CERT_NAMES:
        utils.debug("Initializing cert names file...")
        with open(CERT_NAMES_FILENAME, 'w+') as cert_names_file:
            cert_names_file.write("URL,Name\r\n")

    utils.debug("Initializing pshtt (running inspect_domains with no domains to initialize)...")
    inspect_domains(None, options)


# Perform one-time finalization
def finalize(environment, options):
    utils.debug("Finalizing pshtt (unpatching sslyze legacy ssl client function)...")
    ServerConnectivityInfo.get_preconfigured_ssl_connection = _orig_get_preconfigured_ssl_connection


def https_check(endpoint, check_for_intermediate_cert=True):
    """
    Uses sslyze to figure out the reason the endpoint wouldn't verify.
    """
    global CA_FILE, PT_INT_CA_FILE, STORE
    utils.debug("sslyzing {}...".format(endpoint.url))

    # remove the https:// from prefix for sslyze
    try:
        hostname = endpoint.url[8:]
        server_tester = ServerConnectivityTester(hostname=hostname, port=443)
        server_info = server_tester.perform()
        endpoint.live = True
        ip = server_info.ip_address
        if endpoint.ip is None:
            endpoint.ip = ip
        else:
            if endpoint.ip != ip:
                utils.debug("{}: Endpoint IP is already {}, but requests IP is {}.".format(endpoint.url, endpoint.ip, ip))
        if server_info.client_auth_requirement.name == 'REQUIRED':
            endpoint.https_client_auth_required = True
            logging.warning("{}: Client Authentication REQUIRED".format(endpoint.url))
    except ServerConnectivityError as err:
        endpoint.live = False
        endpoint.https_valid = False
        logging.warning("{}: Error in sslyze server connectivity check when connecting to {}".format(endpoint.url, err.server_info.hostname))
        utils.debug("  {}: {}".format(endpoint.url, err))
        return
    except dns.exception.DNSException as err:
        endpoint.live = False
        endpoint.https_valid = False
        logging.warning("{}: DNS exception in sslyze connectivity check.".format(endpoint.url))
        utils.debug("  {}: {}".format(endpoint.url, err))
        return
    except Exception as err:
        endpoint.unknown_error = True
        logging.warning("{}: Unknown exception in sslyze server connectivity check.".format(endpoint.url))
        utils.debug("  {}: {}".format(endpoint.url, err))
        return

    try:
        cert_plugin_result = None
        command = sslyze.plugins.certificate_info_plugin.CertificateInfoScanCommand(ca_file=CA_FILE)
        scanner = sslyze.synchronous_scanner.SynchronousScanner()
        cert_plugin_result = scanner.run_scan_command(server_info, command)
    except Exception as err:
        try:
            if("timed out" in str(err)):
                logging.warning("{}: Retrying sslyze scanner certificate plugin.".format(endpoint.url))
                cert_plugin_result = scanner.run_scan_command(server_info, command)
        except Exception:
            pass
        if(cert_plugin_result is None):
            logging.warning("{}: Unknown exception in sslyze scanner certificate plugin.".format(endpoint.url))
            utils.debug("  {}: {}".format(endpoint.url, err))
            endpoint.unknown_error = True
            endpoint.https_valid = None  # could make this False, but there was an error so we don't know
            return

    try:
        public_trust = True
        custom_trust = True
        public_not_trusted_string = ""
        validation_results = cert_plugin_result.path_validation_result_list
        for result in validation_results:
            is_trusted = True
            functions = dir(result)
            if "is_certificate_trusted" in functions:
                is_trusted = result.is_certificate_trusted
            elif "was_validation_successful" in functions:
                is_trusted = result.was_validation_successful
            else: 
                logging.warning("{}: Can't test trust because sslyze missing needed function.".format(endpoint.url))
                raise Exception("Missing sslyze function for testing certificate trust")
            if is_trusted:
                # We're assuming that it is trusted to start with
                pass
            else:
                if 'Custom' in result.trust_store.name:
                    custom_trust = False
                else:
                    public_trust = False
                    if len(public_not_trusted_string) > 0:
                        public_not_trusted_string += ", "
                    public_not_trusted_string += result.trust_store.name
        if public_trust:
            logging.warning("{}: Publicly trusted by common trust stores.".format(endpoint.url))
        else:
            logging.warning("{}: Not publicly trusted - not trusted by {}.".format(endpoint.url, public_not_trusted_string))
        if CA_FILE is not None:
            if custom_trust:
                logging.warning("{}: Trusted by custom trust store.".format(endpoint.url))
            else:
                logging.warning("{}: Not trusted by custom trust store.".format(endpoint.url))
        else:
            custom_trust = None

        if check_for_intermediate_cert and not public_trust and not custom_trust:
            # Try to see if there is a missing intermediate cert
            try:
                # Served chain.
                served_chain = None
                functions = dir(cert_plugin_result)
                if "certificate_chain" in functions:
                    served_chain = cert_plugin_result.certificate_chain
                elif "received_certificate_chain" in functions:
                    served_chain = cert_plugin_result.received_certificate_chain
                else:
                    raise Exception("Missing sslyze function to get certificate chain")
                (valid, missingCert) = checkCertChain(endpoint, served_chain)
                if valid:
                    https_check(endpoint, False)
                    return
            except Exception as err:
                utils.debug("{}: Error checking for missing intermediate cert in sslyze results: {}".format(endpoint.url, err))
        
        # Check for names in certificate
        try:
            # Served chain.
            served_chain = None
            functions = dir(cert_plugin_result)
            if "certificate_chain" in functions:
                served_chain = cert_plugin_result.certificate_chain
            elif "received_certificate_chain" in functions:
                served_chain = cert_plugin_result.received_certificate_chain
            else:
                raise Exception("Missing sslyze function to get certificate chain")
            findNamesInCertChain(endpoint, served_chain)
        except Exception as err:
            utils.debug("{}: Error checking for names in server certificate: {}".format(endpoint.url, err))

        endpoint.https_public_trusted = public_trust
        endpoint.https_custom_trusted = custom_trust
        if not public_trust and not custom_trust:
            endpoint.https_valid = False
    except Exception as err:
        # Ignore exception
        utils.debug("{}: Unknown exception examining trust: {}".format(endpoint.url, err))

    try:
        cert_response = cert_plugin_result.as_text()
    except AttributeError:
        logging.warning("{}: Known error in sslyze 1.X with EC public keys. See https://github.com/nabla-c0d3/sslyze/issues/215".format(endpoint.url))
        return None
    except Exception as err:
        endpoint.unknown_error = True
        logging.warning("{}: Unknown exception in cert plugin.".format(endpoint.url))
        utils.debug("  {}: {}".format(endpoint.url, err))
        return

    # Debugging
    # for msg in cert_response:
    #     print(msg)

    # Default endpoint assessments to False until proven True.
    endpoint.https_expired_cert = False
    endpoint.https_self_signed_cert = False
    endpoint.https_bad_chain = False
    endpoint.https_bad_hostname = False

    # STORE will be either "Mozilla" or "Custom"
    # depending on what the user chose.

    # A certificate can have multiple issues.
    for msg in cert_response:

        # Check for missing SAN.
        if (
            (("DNS Subject Alternative Names") in msg) and
            (("[]") in msg)
        ):
            endpoint.https_bad_hostname = True

        # Check for certificate expiration.
        if (
            (STORE in msg) and
            (("FAILED") in msg) and
            (("certificate has expired") in msg)
        ):
            endpoint.https_expired_cert = True

        # Check to see if the cert is self-signed
        if (
            (STORE in msg) and
            (("FAILED") in msg) and
            (("self signed certificate") in msg)
        ):
            endpoint.https_self_signed_cert = True

        # Check to see if there is a bad chain

        # NOTE: If this is the only flag that's set, it's probably
        # an incomplete chain
        # If this isnt the only flag that is set, it's might be
        # because there is another error. More debugging would
        # need to be done at this point, but not through sslyze
        # because sslyze doesn't have enough granularity

        if (
            (STORE in msg) and
            (("FAILED") in msg) and
            (
                (("unable to get local issuer certificate") in msg) or
                (("self signed certificate") in msg)
            )
        ):
            endpoint.https_bad_chain = True

        # Check for whether the hostname validates.
        if (
            (("Hostname Validation") in msg) and
            (("FAILED") in msg) and
            (("Certificate does NOT match") in msg)
        ):
            endpoint.https_bad_hostname = True

    try:
        certificate_chain = None
        functions = dir(cert_plugin_result)
        if "certificate_chain" in functions:
            certificate_chain = cert_plugin_result.certificate_chain
        elif "received_certificate_chain" in functions:
            certificate_chain = cert_plugin_result.received_certificate_chain
        else:
            logging.warning("{}: Missing sslyze function to check for missing intermediate certificate.".format(endpoint.url))
            utils.debug("  {}: Missing sslyze certificate_chain or received_certificate_chain function".format(endpoint.url))
        if certificate_chain:
            endpoint.https_cert_chain_len = len(certificate_chain)
            if (
                    endpoint.https_self_signed_cert is False and (
                        endpoint.https_cert_chain_len < 4
                    )
            ):
                # *** TODO check that it is not a bad hostname and that the root cert is trusted before suggesting that it is an intermediate cert issue.
                endpoint.https_missing_intermediate_cert = True
                if(cert_plugin_result.verified_certificate_chain is None):
                    logging.warning("{}: Untrusted certificate chain, probably due to missing intermediate certificate.".format(endpoint.url))
                    utils.debug("  {}: Only {} certificates in certificate chain received.".format(endpoint.url, endpoint.https_cert_chain_len))
                elif(custom_trust is True and public_trust is False):
                    # recheck public trust using custom public trust store with manually added intermediate certificates
                    if(PT_INT_CA_FILE is not None):
                        try:
                            cert_plugin_result = None
                            command = sslyze.plugins.certificate_info_plugin.CertificateInfoScanCommand(ca_file=PT_INT_CA_FILE)
                            cert_plugin_result = scanner.run_scan_command(server_info, command)
                            if(cert_plugin_result.verified_certificate_chain is not None):
                                public_trust = True
                                endpoint.https_public_trusted = public_trust
                                logging.warning("{}: Trusted by special public trust store with intermediate certificates.".format(endpoint.url))
                        except Exception:
                            pass
            else:
                endpoint.https_missing_intermediate_cert = False
    except Exception:
        # Squash exceptions
        pass

    # If anything is wrong then https is not valid
    if (
        endpoint.https_expired_cert or
        endpoint.https_self_signed_cert or
        endpoint.https_bad_chain or
        endpoint.https_bad_hostname
    ):
        endpoint.https_valid = False


def canonical_endpoint(http, httpwww, https, httpswww):
    """
    Given behavior for the 4 endpoints, make a best guess
    as to which is the "canonical" site for the domain.

    Most of the domain-level decisions rely on this guess in some way.

    A domain is "canonically" at www if:
     * at least one of its www endpoints responds
     * both root endpoints are either down or redirect *somewhere*
     * either both root endpoints are down, *or* at least one
       root endpoint redirect should immediately go to
       an *internal* www endpoint
    This is meant to affirm situations like:
      http:// -> https:// -> https://www
      https:// -> http:// -> https://www
    and meant to avoid affirming situations like:
      http:// -> http://non-www,
      http://www -> http://non-www
    or like:
      https:// -> 200, http:// -> http://www
    """

    at_least_one_www_used = httpswww.live or httpwww.live

    def root_unused(endpoint):
        return (
            endpoint.redirect or
            (not endpoint.live) or
            endpoint.https_bad_hostname or  # harmless for http endpoints
            (not str(endpoint.status).startswith("2"))
        )

    def root_down(endpoint):
        return (
            (not endpoint.live) or
            endpoint.https_bad_hostname or
            (
                (not str(endpoint.status).startswith("2")) and
                (not str(endpoint.status).startswith("3"))
            )
        )

    all_roots_unused = root_unused(https) and root_unused(http)

    all_roots_down = root_down(https) and root_down(http)

    is_www = (
        at_least_one_www_used and
        all_roots_unused and (
            all_roots_down or
            https.redirect_immediately_to_www or
            http.redirect_immediately_to_www
        )
    )

    # A domain is "canonically" at https if:
    #  * at least one of its https endpoints is live and
    #    doesn't have an invalid hostname
    #  * both http endpoints are either down or redirect *somewhere*
    #  * at least one http endpoint redirects immediately to
    #    an *internal* https endpoint
    # This is meant to affirm situations like:
    #   http:// -> http://www -> https://
    #   https:// -> http:// -> https://www
    # and meant to avoid affirming situations like:
    #   http:// -> http://non-www
    #   http://www -> http://non-www
    # or:
    #   http:// -> 200, http://www -> https://www
    #
    # It allows a site to be canonically HTTPS if the cert has
    # a valid hostname but invalid chain issues.

    def https_used(endpoint):
        return endpoint.live and (not endpoint.https_bad_hostname)

    def http_unused(endpoint):
        return (
            endpoint.redirect or
            (not endpoint.live) or
            (not str(endpoint.status).startswith("2"))
        )

    def http_upgrades(endpoint):
        return (
            endpoint.redirect_immediately_to_https and
            (not endpoint.redirect_immediately_to_external)
        )

    at_least_one_https_endpoint = https_used(https) or https_used(httpswww)
    all_http_unused = http_unused(http) and http_unused(httpwww)
    both_http_down = (not http.live) and (not httpwww.live)
    at_least_one_http_upgrades = http_upgrades(http) or http_upgrades(httpwww)

    is_https = (
        at_least_one_https_endpoint and
        all_http_unused and
        (
            both_http_down or at_least_one_http_upgrades
        )
    )

    if is_www and is_https:
        return httpswww
    elif is_www and (not is_https):
        return httpwww
    elif (not is_www) and is_https:
        return https
    elif (not is_www) and (not is_https):
        return http


def get_certificates(self):
    from OpenSSL.crypto import _lib, _ffi, X509
    """
    https://github.com/pyca/pyopenssl/pull/367/files#r67300900

    Returns all certificates for the PKCS7 structure, if present. Only
    objects of type ``signedData`` or ``signedAndEnvelopedData`` can embed
    certificates.

    :return: The certificates in the PKCS7, or :const:`None` if
        there are none.
    :rtype: :class:`tuple` of :class:`X509` or :const:`None`
    """

    certs = _ffi.NULL
    if self.type_is_signed():
        certs = self._pkcs7.d.sign.cert
    elif self.type_is_signedAndEnveloped():
        certs = self._pkcs7.d.signed_and_enveloped.cert

    pycerts = []
    for i in range(_lib.sk_X509_num(certs)):
        pycert = X509.__new__(X509)
        pycert._x509 = _lib.sk_X509_value(certs, i)
        pycerts.append(pycert)

    if not pycerts:
        return None
    return tuple(pycerts)


def extract_certs(certs_txt: str):
    """Extracts pycrypto X509 objects from SSL certificates chain string.

    Args:
        certs_txt: SSL certificates chain string.

    Returns:
        result: List of pycrypto X509 objects.
    """
    pattern = b'-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----'
    certs_txt = re.findall(pattern, certs_txt, flags=re.DOTALL)
    certs = [crypto.load_certificate(crypto.FILETYPE_PEM, cert_txt) for cert_txt in certs_txt]
    return certs


def findIntermediateCertURLsInCert(cert):
    urls = []
    logging.debug("Examining cert - Subject '{}', Issuer '{}', NotBefore '{}', NotAfter '{}'".format(cert.get_subject(), cert.get_issuer(), cert.get_notBefore(), cert.get_notAfter()))
    extension_count = cert.get_extension_count()
    for ext_number in range(extension_count):
        if cert.get_extension(ext_number).get_short_name() == b'authorityInfoAccess':
            aia = cert.get_extension(ext_number).get_data()
            logging.debug("Found AIA info: {}".format(aia))
            pieces = str(aia).split('\\x')
            for piece in pieces:
                # pattern = "http:[a-zA-Z0-9_./\-]+(.crt|.cer|.pem|.p7b|.p7c)"
                pattern = '(https?:\S+(\.crt|\.cer|\.pem|\.p7b|\.p7c))'
                matches = re.findall(pattern, piece)
                # print("Possible matches: {}".format(matches))
                for m1 in matches:
                    for m2 in m1:
                        if m2.startswith("http"):
                            # probably what we're looking for
                            logging.debug("Found probable intermediate cert at: {}".format(m2))
                            int_url = m2
                            urls.append(int_url)
    return urls


def downloadCerts(endpoint, url, filename, extension):
    certs_to_return = []
    logging.debug("{}: Downloading cert from url: {}".format(endpoint.url, url))
    try:
        r = requests.get(url, verify=False)
    except Exception as err:
        logging.debug("{}: Error downloading certs from {}: {}".format(endpoint.url, url, err))
        return None
    if(extension == "p7b"):
        cert_data = crypto.load_pkcs7_data(crypto.FILETYPE_PEM, r.content)
        certs = get_certificates(cert_data)
    elif(extension == "p7c"):
        cert_data = crypto.load_pkcs7_data(crypto.FILETYPE_ASN1, r.content)
        certs = get_certificates(cert_data)
    else:
        cert_data = crypto.load_certificate(crypto.FILETYPE_ASN1, r.content)
        certs = [cert_data]
    logging.debug("{}: Found {} certs in downloaded cert file.".format(endpoint.url, len(certs)))
    for cert in certs:
        pem_cert = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
        new_cert = crypto.load_certificate(crypto.FILETYPE_PEM, pem_cert)
        certs_to_return.append(new_cert)
    return certs_to_return


def addPublicCAsToStore(endpoint, store, filename):
    # if CA_FILE then use it, otherwise use PT_INT_CA_FILE, otherwise use certifi
    logging.debug("{}: Adding publicly trusted CA certs to trust store to test from: {}".format(endpoint.url, filename))
    with open(filename, 'rb') as certs_file:
        ca_certs = extract_certs(certs_file.read())
        for ca_cert in ca_certs:
            store.add_cert(ca_cert)
        logging.debug("{}: Added {} Public CA certs.".format(endpoint.url, len(ca_certs)))
    return ca_certs


def findIntCertURLsInSSLyzeCert(cert):
    urls = []
    print("Examining cert - Subject '{}', Issuer '{}', NotBefore '{}', NotAfter '{}'".format(cert.subject, cert.issuer, cert.not_valid_before, cert.not_valid_after))
    for extension in cert.extensions:
        if extension.oid._name == 'authorityInfoAccess':
            aias = extension.value
            print("Found AIA info: {}".format(aias))
            for aia in aias:
                url = aia.access_location.value
                pattern = '(https?:\S+(\.crt|\.cer|\.pem|\.p7b|\.p7c))'
                matches = re.findall(pattern, url)
                # print("Possible matches: {}".format(matches))
                for m1 in matches:
                    for m2 in m1:
                        if m2.startswith("http"):
                            # probably what we're looking for
                            print("Found probable intermediate cert at: {}".format(m2))
                            int_url = m2
                            urls.append(int_url)
    return urls


def findIntCertURLsInCert(endpoint, cert):
    if str(type(cert)) == "<class 'cryptography.hazmat.backends.openssl.x509._Certificate'>":
        return findIntCertURLsInSSLyzeCert(cert)
    urls = []
    logging.debug("{}: Examining cert - Subject '{}', Issuer '{}', NotBefore '{}', NotAfter '{}'".format(endpoint.url, cert.get_subject(), cert.get_issuer(), cert.get_notBefore(), cert.get_notAfter()))
    extension_count = cert.get_extension_count()
    for ext_number in range(extension_count):
        if cert.get_extension(ext_number).get_short_name() == b'authorityInfoAccess':
            aia = cert.get_extension(ext_number).get_data()
            logging.debug("{}: Found AIA info: {}".format(endpoint.url, aia))
            pieces = str(aia).split('\\x')
            for piece in pieces:
                pattern = '(https?:\S+(\.crt|\.cer|\.pem|\.p7b|\.p7c))'
                matches = re.findall(pattern, piece)
                for m1 in matches:
                    for m2 in m1:
                        if m2.startswith("http"):
                            # probably what we're looking for
                            logging.debug("{}: Found probable intermediate cert at: {}".format(endpoint.url, m2))
                            int_url = m2
                            urls.append(int_url)
    return urls


def checkIfCertAlreadyTrusted(endpoint, cert, ca_certs):
    for ca_cert in ca_certs:
        if(ca_cert.get_subject() == cert.get_subject() and ca_cert.digest("SHA256") == cert.digest("SHA256")):
            logging.debug("{}: Certificate already trusted: {}".format(endpoint.url, cert.get_subject()))
            return True
    return False


def checkIfCertIsTrusted(endpoint, cert, store):
    try:
        store_ctx = X509StoreContext(store, cert)
        store_ctx.verify_certificate()
        logging.debug("{}: New intermediate cert verified: {}".format(endpoint.url, cert.get_subject()))
        return True
    except Exception as err:
        try:
            logging.debug("{}: Possible new intermediate cert not able to be verified: {}.".format(endpoint.url, cert.get_subject()))
        except Exception:
            logging.debug("{}: Possible new intermediate cert not able to be verified.".format(endpoint.url))
    return False


def findCN(names, subject):
    pattern = "CN=([^,\)]+)"
    matches = re.findall(pattern, str(subject))
    for m1 in matches:
        # logging.debug("  Found probable CN at: {}".format(m1))
        if m1 not in names:
            names.append(m1)
    return names


def findSAN(names, san):
    pattern = "value='(\S+)'"
    matches = re.findall(pattern, str(san))
    for m1 in matches:
        # logging.debug("  Found probable SAN at: {}".format(m1))
        if m1 not in names:
            names.append(m1)
    return names


def findNamesInSSLyzeCert(endpoint, cert):
    names = []
    print("sslyze Server cert subject: {}".format(cert.subject))
    names = findCN(names, cert.subject)
    for extension in cert.extensions:
        if extension.oid._name == 'subjectAltName':
            san = extension.value
            logging.debug("{}: Found SAN info: {}".format(endpoint.url, san))
            names = findSAN(names, san)
    return names


def findNamesInCert(endpoint, cert):
    if str(type(cert)) == "<class 'cryptography.hazmat.backends.openssl.x509._Certificate'>":
        return findNamesInSSLyzeCert(endpoint, cert)
    names = []
    logging.debug("{}: Server cert subject: {}".format(endpoint.url, cert.get_subject()))
    names = findCN(names, cert.get_subject())
    extension_count = cert.get_extension_count()
    for ext_number in range(extension_count):
        if cert.get_extension(ext_number).get_short_name() == b'subjectAltName':
            san = cert.get_extension(ext_number).get_data()
            logging.debug("{}: Found SAN info: {}".format(endpoint.url, san))
            names = findSAN(names, san)
    return names


def findNamesInCertChain(endpoint, certchain):
    try:
        # logging.debug("{}: Looking for names in cert chain...".format(endpoint.url))
        if SAVE_CERT_NAMES and certchain:
            names = findNamesInCert(endpoint, certchain[0])
            with open(CERT_NAMES_FILENAME, 'a+') as cert_names_file:
                for name in names:
                    cert_names_file.write("{},{}\r\n".format(endpoint.url, name))
    except Exception as err:
        logging.debug("{}: Error looking for cert names: {}".format(endpoint.url, err))


def checkCertChain(endpoint, certchain):
    global CA_FILE, PT_INT_CA_FILE, STORE
    valid = None
    missingCert = None
    try: 
        logging.debug("Looking for intermediate certs from: {}".format(endpoint.url))
        int_cert_urls = []
        for cert in certchain:
            cert_urls = findIntCertURLsInCert(endpoint, cert)
            for new_cert_url in cert_urls:
                if new_cert_url not in int_cert_urls:
                    int_cert_urls.append(new_cert_url)
        certs_to_add_to_all_file = []
        certs_to_add_to_pt_file = []
        all_file = None
        pt_file = None
        if CA_FILE:
            all_file = CA_FILE
        if PT_INT_CA_FILE:
            pt_file = PT_INT_CA_FILE
        if all_file is None:
            all_file = certifi.where()
        if pt_file is None:
            pt_file = certifi.where()
        for int_cert_url in int_cert_urls:
            try:
                filename = str(int_cert_url).rsplit('/', 1)[1].strip("'").replace("%20", "_")
                logging.debug("{}: New possible intermediate cert filename is: {}".format(endpoint.url, filename))
                parts = filename.split('.')
                extension = parts[(len(parts) - 1)].lower()
                certs = downloadCerts(endpoint, int_cert_url, filename, extension)

                store = X509Store()
                ca_certs = addPublicCAsToStore(endpoint, store, all_file)
                for cert in certs:
                    if not checkIfCertAlreadyTrusted(endpoint, cert, ca_certs):
                        if checkIfCertIsTrusted(endpoint, cert, store):
                            certs_to_add_to_all_file.append(cert)
                store = X509Store()
                ca_certs = addPublicCAsToStore(endpoint, store, pt_file)
                for cert in certs:
                    if not checkIfCertAlreadyTrusted(endpoint, cert, ca_certs):
                        if checkIfCertIsTrusted(endpoint, cert, store):
                            certs_to_add_to_pt_file.append(cert)                   
            except Exception as err:
                logging.debug("{}: Error checking a possible intermediate cert url: {}".format(endpoint.url, err))
        for (cert_type, certs_to_add, certs_filename) in [("ALL", certs_to_add_to_all_file, all_file), ("PT", certs_to_add_to_pt_file, pt_file)]:        
            if certs_to_add and len(certs_to_add) > 0:
                # Add validated trusted intermediate cert to trust store to use
                new_certs_filename = "pshtt_" + certs_filename.rsplit('/', 1)[1]
                if os.path.exists("./cache/"):
                    new_certs_filename = "./cache/" + new_certs_filename
                else:
                    new_certs_filename = "/tmp/" + new_certs_filename
                if new_certs_filename != certs_filename:
                    shutil.copyfile(certs_filename, new_certs_filename)
                with open(new_certs_filename, 'ab') as new_certs_file:
                    for cert_to_add in certs_to_add:
                        logging.debug("{}: Adding to trust store at {} cert: {}".format(endpoint.url, new_certs_filename, cert_to_add.get_subject()))
                        certPEM = crypto.dump_certificate(crypto.FILETYPE_PEM, cert_to_add)
                        new_certs_file.write(certPEM)
                # Update trust stores to use going forward
                if cert_type == "ALL":
                    CA_FILE = new_certs_filename
                if cert_type == "PT":
                    PT_INT_CA_FILE = new_certs_filename
                STORE = "Custom"
                valid = True
                missingCert = True
            logging.debug("{}: Finished adding {} certs to {} trust store.".format(endpoint.url, len(certs_to_add), cert_type))
    except Exception as err:
        logging.debug("{}: Error checking cert chain for missing intermediate certs: {}".format(endpoint.url, err))
    return (valid, missingCert)

##
# Judgment calls based on observed endpoint data.
##


def is_live(domain):
    """
    Domain is "live" if *any* endpoint is live.
    """
    http, httpwww, https, httpswww = domain.http, domain.httpwww, domain.https, domain.httpswww

    return http.live or httpwww.live or https.live or httpswww.live


def is_https_live(domain):
    """
    Domain is https live if any https endpoint is live.
    """
    https, httpswww = domain.https, domain.httpswww

    return https.live or httpswww.live


def is_full_connection(domain):
    """
    Domain is "fully connected" if any https endpoint is fully connected.
    """
    https, httpswww = domain.https, domain.httpswww

    return https.https_full_connection or httpswww.https_full_connection


def is_client_auth_required(domain):
    """
    Domain requires client authentication if *any* HTTPS endpoint requires it for full TLS connection.
    """
    https, httpswww = domain.https, domain.httpswww

    return https.https_client_auth_required or httpswww.https_client_auth_required


def is_redirect_or_down(endpoint):
    """
    Endpoint is a redirect or down if it is a redirect to an external site or it is down in any of 3 ways:
    it is not live, it is HTTPS and has a bad hostname in the cert, or it responds with a 4xx error code
    """
    return (
        endpoint.redirect_eventually_to_external or
        (not endpoint.live) or
        (
            endpoint.protocol == "https" and
            endpoint.https_bad_hostname
        ) or
        (
            endpoint.status is not None and
            endpoint.status >= 400
        )
    )


def is_redirect(endpoint):
    """
    Endpoint is a redirect if it is a redirect to an external site
    """
    return endpoint.redirect_eventually_to_external


def is_redirect_domain(domain):
    """
    Domain is "a redirect domain" if at least one endpoint is
    a redirect, and all endpoints are either redirects or down.
    """
    http, httpwww, https, httpswww = domain.http, domain.httpwww, domain.https, domain.httpswww

    return is_live(domain) and (
        (
            is_redirect(http) or is_redirect(httpwww) or is_redirect(https) or is_redirect(httpswww)
        ) and
        is_redirect_or_down(https) and
        is_redirect_or_down(httpswww) and
        is_redirect_or_down(httpwww) and
        is_redirect_or_down(http)
    )


def is_http_redirect_domain(domain):
    """
    Domain is "an http redirect domain" if at least one http endpoint
    is a redirect, and all other http endpoints are either redirects
    or down.
    """
    http, httpwww, = domain.http, domain.httpwww

    return is_live(domain) and (
        (
            is_redirect(http) or is_redirect(httpwww)
        ) and
        is_redirect_or_down(httpwww) and
        is_redirect_or_down(http)
    )


def redirects_to(domain):
    """
    If a domain is a "redirect domain", where does it redirect to?
    """
    canonical = domain.canonical

    if is_redirect_domain(domain):
        return canonical.redirect_eventually_to
    else:
        return None


def is_valid_https(domain):
    """
    A domain has "valid HTTPS" if it responds on port 443 at its canonical
    hostname with an unexpired valid certificate for the hostname.
    """
    canonical, https, httpswww = domain.canonical, domain.https, domain.httpswww

    # Evaluate the HTTPS version of the canonical hostname
    if canonical.host == "root":
        evaluate = https
    else:
        evaluate = httpswww

    return evaluate.live and evaluate.https_valid


def is_defaults_to_https(domain):
    """
    A domain "defaults to HTTPS" if its canonical endpoint uses HTTPS.
    """
    canonical = domain.canonical

    return (canonical.protocol == "https")


def is_downgrades_https(domain):
    """
    Domain downgrades if HTTPS is supported in some way, but
    its canonical HTTPS endpoint immediately redirects internally to HTTP.
    """
    canonical, https, httpswww = domain.canonical, domain.https, domain.httpswww

    # The domain "supports" HTTPS if any HTTPS endpoint responds with
    # a certificate valid for its hostname.
    supports_https = (
        https.live and (not https.https_bad_hostname)
    ) or (
        httpswww.live and (not httpswww.https_bad_hostname)
    )

    if canonical.host == "www":
        canonical_https = httpswww
    else:
        canonical_https = https

    # Explicitly convert to bool to avoid unintentionally returning None,
    # which may happen if the site doesn't redirect.
    return bool(
        supports_https and
        canonical_https.redirect_immediately_to_http and
        (not canonical_https.redirect_immediately_to_external)
    )


def is_strictly_forces_https(domain):
    """
    A domain "Strictly Forces HTTPS" if one of the HTTPS endpoints is
    "live", and if both *HTTP* endpoints are either:

     * down, or
     * redirect immediately to an HTTPS URI.

    This is different than whether a domain "Defaults" to HTTPS.

    * An HTTP redirect can go to HTTPS on another domain, as long
      as it's immediate.
    * A domain with an invalid cert can still be enforcing HTTPS.
    """
    http, httpwww, https, httpswww = domain.http, domain.httpwww, domain.https, domain.httpswww

    def down_or_redirects(endpoint):
        return ((not endpoint.live) or endpoint.redirect_immediately_to_https)

    https_somewhere = https.live or httpswww.live
    all_http_unused = down_or_redirects(http) and down_or_redirects(httpwww)

    return https_somewhere and all_http_unused


def is_publicly_trusted(domain):
    """
    A domain has a "Publicly Trusted" certificate if its canonical
    endpoint has a publicly trusted certificate.
    """
    canonical, https, httpswww = domain.canonical, domain.https, domain.httpswww

    # Evaluate the HTTPS version of the canonical hostname
    if canonical.host == "root":
        evaluate = https
    else:
        evaluate = httpswww

    return evaluate.live and evaluate.https_public_trusted


def is_custom_trusted(domain):
    """
    A domain has a "Custom Trusted" certificate if its canonical
    endpoint has a certificate that is trusted by the custom
    truststore.
    """
    canonical, https, httpswww = domain.canonical, domain.https, domain.httpswww

    # Evaluate the HTTPS version of the canonical hostname
    if canonical.host == "root":
        evaluate = https
    else:
        evaluate = httpswww

    return evaluate.live and evaluate.https_custom_trusted


def is_bad_chain(domain):
    """
    Domain has a bad chain if its canonical https endpoint has a bad
    chain
    """
    canonical, https, httpswww = domain.canonical, domain.https, domain.httpswww

    if canonical.host == "www":
        canonical_https = httpswww
    else:
        canonical_https = https

    return canonical_https.https_bad_chain


def is_bad_hostname(domain):
    """
    Domain has a bad hostname if its canonical https endpoint fails
    hostname validation
    """
    canonical, https, httpswww = domain.canonical, domain.https, domain.httpswww

    if canonical.host == "www":
        canonical_https = httpswww
    else:
        canonical_https = https

    return canonical_https.https_bad_hostname


def is_expired_cert(domain):
    """
    Returns if its canonical https endpoint has an expired cert
    """
    canonical, https, httpswww = domain.canonical, domain.https, domain.httpswww

    if canonical.host == "www":
        canonical_https = httpswww
    else:
        canonical_https = https

    return canonical_https.https_expired_cert


def is_self_signed_cert(domain):
    """
    Returns if its canonical https endpoint has a self-signed cert cert
    """
    canonical, https, httpswww = domain.canonical, domain.https, domain.httpswww

    if canonical.host == "www":
        canonical_https = httpswww
    else:
        canonical_https = https

    return canonical_https.https_self_signed_cert


def cert_chain_length(domain):
    """
    Returns the cert chain length for the canonical HTTPS endpoint
    """
    canonical, https, httpswww = domain.canonical, domain.https, domain.httpswww

    if canonical.host == "www":
        canonical_https = httpswww
    else:
        canonical_https = https

    return canonical_https.https_cert_chain_len


def is_missing_intermediate_cert(domain):
    """
    Returns whether the served cert chain is probably missing the
    needed intermediate certificate for the canonical HTTPS endpoint
    """
    canonical, https, httpswww = domain.canonical, domain.https, domain.httpswww

    if canonical.host == "www":
        canonical_https = httpswww
    else:
        canonical_https = https

    return canonical_https.https_missing_intermediate_cert


def is_hsts(domain):
    """
    Domain has HSTS if both https and httpswww endpoints have HSTS when live.
    """
    https, httpswww = domain.https, domain.httpswww

    if not https.live and not httpswww.live:
        return None

    utils.debug("{}: Testing HSTS - https.hsts is '{}', httpswww.hsts is '{}'.".format(domain.domain, https.hsts, httpswww.hsts))

    hsts = None
    if https.live and (https.hsts is not None):
        hsts = https.hsts
    if httpswww.live and (httpswww.hsts is not None):
        if hsts is None:
            hsts = httpswww.hsts
        else:
            hsts &= httpswww.hsts

    if domain.canonical.host == "www":
        canonical_https = httpswww
    else:
        canonical_https = https

    old_hsts = canonical_https.hsts
    if old_hsts != hsts:
        utils.debug("{}: Difference in HSTS - old {} != new (for both https endpoints) {}.".format(domain.domain, old_hsts, hsts))

    # should be the following, but that is stricter than currently
    # return hsts
    return canonical_https.hsts


def hsts_header(domain):
    """
    Domain's HSTS header is its canonical endpoint's header.
    """
    canonical, https, httpswww = domain.canonical, domain.https, domain.httpswww

    if canonical.host == "www":
        canonical_https = httpswww
    else:
        canonical_https = https

    return canonical_https.hsts_header


def hsts_max_age(domain):
    """
    Domain's HSTS max-age is its canonical endpoint's max-age.
    """
    canonical, https, httpswww = domain.canonical, domain.https, domain.httpswww

    if canonical.host == "www":
        canonical_https = httpswww
    else:
        canonical_https = https

    return canonical_https.hsts_max_age


def is_hsts_entire_domain(domain):
    """
    Whether a domain's ROOT endpoint includes all subdomains.
    """
    https = domain.https

    return https.hsts_all_subdomains


def is_hsts_preload_ready(domain):
    """
    Whether a domain's ROOT endpoint is preload-ready.
    """
    https = domain.https

    eighteen_weeks = ((https.hsts_max_age is not None) and (https.hsts_max_age >= 10886400))
    preload_ready = (eighteen_weeks and https.hsts_all_subdomains and https.hsts_preload)

    return preload_ready


def is_hsts_preload_pending(domain):
    """
    Whether a domain is formally pending inclusion in Chrome's HSTS preload
    list.

    If preload_pending is None, the caches have not been initialized, so do
    that.
    """
    if preload_pending is None:
        logging.error('`preload_pending` has not yet been initialized!')
        raise RuntimeError(
            '`initialize_external_data()` must be called explicitly before '
            'using this function'
        )

    if domain.preload_pending is not None and domain.domain in domain.preload_pending:
        return True

    return domain.domain in preload_pending


def is_hsts_preloaded(domain):
    """
    Whether a domain is contained in Chrome's HSTS preload list.

    If preload_list is None, the caches have not been initialized, so do that.
    """
    if preload_list is None:
        logging.error('`preload_list` has not yet been initialized!')
        raise RuntimeError(
            '`initialize_external_data()` must be called explicitly before '
            'using this function'
        )

    result = None
    if domain.preload_list is not None and domain.domain in domain.preload_list:
        result = True
        logging.debug("Checked if {} is in domain's preload list: {}".format(domain.domain, result))

    if not result:
        result = domain.domain in preload_list
        logging.debug("Checking if {} is in preload list: {}".format(domain.domain, result))
    return result


def is_parent_hsts_preloaded(domain):
    """
    Whether a domain's parent domain is in Chrome's HSTS preload list.
    """
    parent_domain = Domain(parent_domain_for(domain.domain))
    parent_domain.preload_list = domain.preload_list
    return is_hsts_preloaded(parent_domain)


def parent_domain_for(hostname):
    """
    For "x.y.domain.gov", return "domain.gov".

    If suffix_list is None, the caches have not been initialized, so do that.
    """
    if suffix_list is None:
        logging.error('`suffix_list` has not yet been initialized!')
        raise RuntimeError(
            '`initialize_external_data()` must be called explicitly before '
            'using this function'
        )
    result = suffix_list.get_public_suffix(hostname)
    logging.debug("Getting parent domain of {}: {}".format(hostname, result))
    return result


def is_domain_supports_https(domain):
    """
    A domain 'Supports HTTPS' when it doesn't downgrade and has valid HTTPS,
    or when it doesn't downgrade and has a bad chain but not a bad hostname.
    Domains with a bad chain "support" HTTPS but user-side errors should be expected.
    """
    return (
        (not is_downgrades_https(domain)) and
        is_valid_https(domain)
    ) or (
        (not is_downgrades_https(domain)) and
        is_bad_chain(domain) and
        (not is_bad_hostname(domain))
    )


def is_domain_enforces_https(domain):
    """A domain that 'Enforces HTTPS' must 'Support HTTPS' and default to
    HTTPS.  For websites (where Redirect is false) they are allowed to
    eventually redirect to an https:// URI. For "redirect domains"
    (domains where the Redirect value is true) they must immediately
    redirect clients to an https:// URI (even if that URI is on
    another domain) in order to be said to enforce HTTPS.
    """
    return is_domain_supports_https(domain) and is_strictly_forces_https(domain) and (
        is_defaults_to_https(domain) or is_http_redirect_domain(domain)
    )


def is_domain_strong_hsts(domain):
    if is_hsts(domain) and hsts_max_age(domain):
        return (
            is_hsts(domain) and
            hsts_max_age(domain) >= 31536000
        )
    else:
        return None


def get_domain_ip(domain):
    """
    Get the IP for the domain.  Any IP that responded is good enough.
    """
    if domain.canonical.ip is not None:
        return domain.canonical.ip
    if domain.https.ip is not None:
        return domain.https.ip
    if domain.httpswww.ip is not None:
        return domain.httpswww.ip
    if domain.httpwww.ip is not None:
        return domain.httpwww.ip
    if domain.http.ip is not None:
        return domain.http.ip
    return None


def get_domain_server_header(domain):
    """
    Get the Server header from the response for the domain.
    """
    if domain.canonical.server_header is not None:
        return domain.canonical.server_header.replace(',', ';')
    if domain.https.server_header is not None:
        return domain.https.server_header.replace(',', ';')
    if domain.httpswww.server_header is not None:
        return domain.httpswww.server_header.replace(',', ';')
    if domain.httpwww.server_header is not None:
        return domain.httpwww.server_header.replace(',', ';')
    if domain.http.server_header is not None:
        return domain.http.server_header.replace(',', ';')
    return None


def get_domain_server_version(domain):
    """
    Get the Server version based on the Server header for the web server.
    """
    if domain.canonical.server_version is not None:
        return domain.canonical.server_version
    if domain.https.server_version is not None:
        return domain.https.server_version
    if domain.httpswww.server_version is not None:
        return domain.httpswww.server_version
    if domain.httpwww.server_version is not None:
        return domain.httpwww.server_version
    if domain.http.server_version is not None:
        return domain.http.server_version
    return None


def get_domain_status_code(domain):
    """
    Get the status code for the response.
    """
    if domain.canonical.status is not None:
        return domain.canonical.status
    if domain.https.status is not None:
        return domain.https.status
    if domain.httpswww.status is not None:
        return domain.httpswww.status
    if domain.httpwww.status is not None:
        return domain.httpwww.status
    if domain.http.status is not None:
        return domain.http.status
    return None


def get_domain_notes(domain):
    """
    Combine all domain notes if there are any.
    """
    all_notes = domain.http.notes + "; " + domain.httpwww.notes + "; " + domain.https.notes + "; " + domain.httpswww.notes
    all_notes = all_notes.replace(',', ';')
    return all_notes


def did_domain_error(domain):
    """
    Checks if the domain had an Unknown error somewhere
    The main purpos of this is to flag any odd websites for
    further debugging with other tools.
    """
    http, httpwww, https, httpswww = domain.http, domain.httpwww, domain.https, domain.httpswww

    return (
        http.unknown_error or httpwww.unknown_error or
        https.unknown_error or httpswww.unknown_error
    )


def load_preload_pending():
    """
    Fetch the Chrome preload pending list.
    """

    utils.debug("Fetching hstspreload.org pending list...", divider=True)
    pending_url = "https://hstspreload.org/api/v2/pending"

    try:
        request = requests.get(pending_url)
    except (requests.exceptions.SSLError, requests.exceptions.ConnectionError) as err:
        logging.warning('Failed to fetch pending preload list: {}'.format(pending_url))
        logging.debug('{}'.format(err))
        return []

    # TODO: abstract Py 2/3 check out to utils
    if sys.version_info[0] < 3:
        raw = request.content
    else:
        raw = str(request.content, 'utf-8')

    pending_json = json.loads(raw)

    pending = []
    for entry in pending_json:
        if entry.get('include_subdomains', False) is True:
            pending.append(entry['name'])

    logging.debug('Finished loading pending preload list.')

    return pending


def load_preload_list():
    preload_json = None

    utils.debug("Fetching Chrome preload list from source...", divider=True)

    # Downloads the chromium preloaded domain list and sets it to a global set
    file_url = 'https://chromium.googlesource.com/chromium/src/+/main/net/http/transport_security_state_static.json?format=TEXT'

    try:
        request = requests.get(file_url)
    except (requests.exceptions.SSLError, requests.exceptions.ConnectionError) as err:
        logging.warning('Failed to fetch preload list: {}'.format(file_url))
        logging.debug('  {}'.format(err))
        return []

    raw = request.content

    # To avoid parsing the contents of the file out of the source tree viewer's
    # HTML, we download it as a raw file. googlesource.com Base64-encodes the
    # file to avoid potential content injection issues, so we need to decode it
    # before using it. https://code.google.com/p/gitiles/issues/detail?id=7
    raw = base64.b64decode(raw).decode('utf-8')

    # The .json file contains '//' comments, which are not actually valid JSON,
    # and confuse Python's JSON decoder. Begone, foul comments!
    raw = ''.join([re.sub(r'^\s*//.*$', '', line)
                   for line in raw.splitlines()])

    preload_json = json.loads(raw)

    # For our purposes, we only care about entries that includeSubDomains
    fully_preloaded = []
    for entry in preload_json['entries']:
        if entry.get('include_subdomains', False) is True:
            fully_preloaded.append(entry['name'])

    logging.debug('Finished loading preload list.')

    return fully_preloaded


# Returns an instantiated PublicSuffixList object, and the
# list of lines read from the file.
def load_suffix_list():
    # File does not exist, download current list and cache it at given location.
    utils.debug("Downloading the Public Suffix List...", divider=True)
    try:
        cache_file = fetch()
    except URLError as err:
        logging.warning("Unable to download the Public Suffix List...")
        utils.debug("  {}".format(err))
        return []
    content = cache_file.readlines()
    suffixes = PublicSuffixList(content)
    return suffixes, content


def initialize_external_data(
    init_preload_list=None,
    init_preload_pending=None,
    init_suffix_list=None
):
    """
    This function serves to load all of third party external data.

    This can be called explicitly by a library, as part of the setup needed
    before calling other library functions, or called as part of running
    inspect_domains() or CLI operation.

    If values are passed in to this function, they will be assigned to
    be the cached values. This allows a caller of the Python API to manage
    cached data in a customized way.

    It also potentially allows clients to pass in subsets of these lists,
    for testing or novel performance reasons.

    Otherwise, if the --cache-third-parties=[DIR] flag specifies a directory,
    all downloaded third party data will be cached in a directory, and
    used from cache on the next pshtt run instead of hitting the network.

    If no values are passed in, and no --cache-third-parties flag is used,
    then no cached third party data will be created or used, and pshtt will
    download the latest data from those third party sources.
    """
    global preload_list, preload_pending, suffix_list

    # The preload list should be sent in as a list of domains.
    if init_preload_list is not None:
        preload_list = init_preload_list

    # The preload_pending list should be sent in as a list of domains.
    if init_preload_pending is not None:
        preload_pending = init_preload_pending

    # The public suffix list should be sent in as a list of file lines.
    if init_suffix_list is not None:
        suffix_list = PublicSuffixList(init_suffix_list)

    # If there's a specified cache dir, prepare paths.
    # Only used when no data has been set yet for a source.
    if THIRD_PARTIES_CACHE:
        logging.debug('Third parties cache flag is set.')
        cache_preload_list = os.path.join(THIRD_PARTIES_CACHE, cache_preload_list_default)
        cache_preload_pending = os.path.join(THIRD_PARTIES_CACHE, cache_preload_pending_default)
        cache_suffix_list = os.path.join(THIRD_PARTIES_CACHE, cache_suffix_list_default)
    else:
        cache_preload_list, cache_preload_pending, cache_suffix_list = None, None, None

    # Load Chrome's latest versioned HSTS preload list.
    if preload_list is None:
        if cache_preload_list and os.path.exists(cache_preload_list):
            utils.debug("Using cached Chrome preload list.", divider=True)
            preload_list = json.loads(open(cache_preload_list).read())
        else:
            preload_list = load_preload_list()

            if cache_preload_list:
                utils.debug("Caching preload list at %s" % cache_preload_list, divider=True)
                utils.write(utils.json_for(preload_list), cache_preload_list)

    # Load Chrome's current HSTS pending preload list.
    if preload_pending is None:
        if cache_preload_pending and os.path.exists(cache_preload_pending):
            utils.debug("Using cached hstspreload.org pending list.", divider=True)
            preload_pending = json.loads(open(cache_preload_pending).read())
        else:
            preload_pending = load_preload_pending()

            if cache_preload_pending:
                utils.debug("Caching preload pending list at %s" % cache_preload_pending, divider=True)
                utils.write(utils.json_for(preload_pending), cache_preload_pending)

    # Load Mozilla's current Public Suffix list.
    if suffix_list is None:
        if cache_suffix_list and os.path.exists(cache_suffix_list):
            utils.debug("Using cached suffix list.", divider=True)
            cache_file = codecs.open(cache_suffix_list, encoding='utf-8')
            suffix_list = PublicSuffixList(cache_file)
        else:
            suffix_list, raw_content = load_suffix_list()

            if cache_suffix_list:
                utils.debug("Caching suffix list at %s" % cache_suffix_list, divider=True)
                utils.write(''.join(raw_content), cache_suffix_list)


def inspect_domains(domains, options):
    # Override timeout, user agent, preload cache, default CA bundle
    global TIMEOUT, USER_AGENT, THIRD_PARTIES_CACHE, CA_FILE, PT_INT_CA_FILE, STORE, DNS_RESOLVER, SCAN_ADFS

    if options.get('timeout'):
        TIMEOUT = int(options['timeout'])
    if options.get('user_agent'):
        USER_AGENT = options['user_agent']
    if options.get('adfs_hsts'):
        SCAN_ADFS = options['adfs_hsts']

    # Supported cache flag, a directory to store all third party requests.
    if options.get('cache-third-parties'):
        logging.debug("cache-third-parties is set.")
        THIRD_PARTIES_CACHE = options['cache-third-parties']

    if CA_FILE is None and options.get('ca_file'):
        CA_FILE = options['ca_file']
        # By default, the store that we want to check is the Mozilla store
        # However, if a user wants to use their own CA bundle, check the
        # "Custom" Option from the sslyze output.
        STORE = "Custom"

    if PT_INT_CA_FILE is None and options.get('pt_int_ca_file'):
        PT_INT_CA_FILE = options['pt_int_ca_file']

    if DNS_RESOLVER is None:
        initialize_dns_resolver(options)

    # If this has been run once already by a Python API client, it
    # can be safely run without hitting the network or disk again,
    # and without overriding the data the Python user set for them.
    initialize_external_data()

    # For every given domain, get inspect data.
    if domains:
        for domain in domains:
            yield inspect(domain, options)
