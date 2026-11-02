# Synapse model research — slib.shodan rework

Ground truth for `DESIGN.md`. Generated from a live `Cortex.getModelDict()` dump of
**synapse 2.256.0** (the version `uv sync` installs for `svcs/shodan` today), not from memory or docs
pages. The dump script is reproduced at the end. The package's declared `synapse_minversion` is
`[2, 137, 0]`; see "Version floor" below.

## Findings that drive the design

1. **`it:exec:query` exists** with `:text (it:query)`, `:language (str)`, `:opts (data)`,
   `:api:url (inet:url)`, `:offset (int)`, `:time (time)`, `:synuser (syn:user)`,
   `:service:platform (inet:service:platform)`. `:service:instance` is **deprecated** — don't use it.
2. **`it:exec:query -(found)> *`** is a declared edge: "The target node was returned as a result of
   running the query." This is the edge for query → result nodes.
3. **`* -(refs)> *`** is declared generically: "The source node contains a reference to the target node."
   Used for `meta:event -(refs)>` and `it:exec:query -(refs)> <inbound node>`.
4. **`meta:timeline`** (`:title`, `:summary`, `:type meta:timeline:taxonomy`) and **`meta:event`**
   (`:timeline`, `:title`, `:summary`, `:time`, `:index`, `:duration`, `:type meta:event:taxonomy`) exist.
   `meta:event:timeline` is **single-valued**: an event belongs to exactly one timeline. Both are
   documented as *curated* ("An analytically relevant event in a curated timeline").
5. **`meta:source -(seen)> *`** is declared — the service's existing provenance convention still applies
   to every new node (queries, timelines, events).
6. **`meta:rule`** is documented as "A generic rule linked to matches with -(matches)> edges"; its
   `:type` is `meta:rule:type:taxonomy` (the service already uses `svc.shodan.query.`).
7. **IP "whois"-style forms** (for the count command's facet modeling):
   - `inet:ipv4` / `inet:ipv6`: `:asn`, `:loc (loc)`, `:latlong`, `:place (geo:place)`, `:dns:rev`, `:type`.
   - `inet:asn`: `:name (str)`, `:owner (ou:org)`.
   - `inet:asnet4` / `inet:asnet6`: `(asn, net4/net6)` comp — ASN ↔ netblock.
   - `inet:whois:iprec`: `:net4`, `:net6`, `:asn`, `:country (str, ISO2)`, `:name`, `:registrant:name (ou:name)`
     (`:registrant` is **deprecated**), plus the edge **`inet:whois:iprec -(ipwhois)> inet:ipv4/6`**.
   - `pol:country`: `:iso2`, `:name` (use `$lib.gen.polCountryByIso2`, as `svcs/ip_api` does).
   - `ou:org`: `:names`, `:country`, `:country:code` (use `$lib.gen.orgByName`).
   - `geo:telem` (`:node`, `:place`, `:time`, `:desc`) — what `svcs/ip_api` uses for geolocation.
8. **`inet:server`**: `:ipv4`, `:ipv6`, `:port`, `:proto`, `:host`. **`inet:banner`**: `(server, text)` comp
   with `:server`, `:server:ipv4/6`, `:server:port`, `:text (it:dev:str)`. Both resolve their IP
   from their own props, so all three result classes are reachable from each other.
9. **Forms that do NOT exist** (checked, don't plan on them): `inet:ssh:hassh`, `inet:net4` (it's a
   type, not a form — `inet:cidr4` is the form), `inet:whois:iprecord`.

## Version floor

The dump is from 2.256.0. The design relies on `it:exec:query` (+ its `-(found)>` edge),
`meta:timeline`/`meta:event`, and `inet:whois:iprec -(ipwhois)>`. Whether all of these exist at the
declared floor (2.137.0) was **not verified** here. Resolution: add a StormPkgTest that loads the package
on the pinned test synapse and asserts these forms/edges exist, and bump `synapse_minversion` if needed
(DESIGN.md open question).

## Raw dump (relevant forms and edges)

```
synapse (2, 256, 0)

## it:exec:query type=None dep=False doc=An instance of an executed query.
  :api:url (inet:url) - The URL of the API endpoint the query was sent to.
  :exe (file:bytes) - The executable file which caused the activity.
  :host (it:host) - The host on which the activity occurred.
  :language (str) - The name of the language that the query is expressed in.
  :offset (int) - The offset of the last record consumed from the query.
  :opts (data) - An opaque JSON object containing query parameters and options.
  :proc (it:exec:proc) - The host process which caused the activity.
  :sandbox:file (file:bytes) - The initial sample given to a sandbox environment to analyze.
  :service:account (inet:service:account) - The service account which ran the query.
  :service:instance (inet:service:instance) DEPRECATED - Deprecated. Please use :service:platform.
  :service:platform (inet:service:platform) - The service platform which was queried.
  :synuser (syn:user) - The synapse user who executed the query.
  :text (it:query) - The query string that was executed.
  :thread (it:exec:thread) - The host thread which caused the activity.
  :time (time) - The time that the activity started.

## it:query type=None dep=False doc=A unique query string.

## meta:timeline type=None dep=False doc=A curated timeline of analytically relevant events.
  :summary (str) - A prose summary of the timeline.
  :title (str) - A title for the timeline.
  :type (meta:timeline:taxonomy) - The type of timeline.

## meta:timeline:taxonomy type=None dep=False doc=A taxonomy of timeline types for meta:timeline nodes.
  :base (taxon) - The base taxon.
  :depth (int) - The depth indexed from 0.
  :desc (str) - A definition of the taxonomy entry.
  :parent (meta:timeline:taxonomy) - The taxonomy parent.
  :sort (int) - A display sort order for siblings.
  :summary (str) DEPRECATED - Deprecated. Please use title/desc.
  :title (str) - A brief title of the definition.

## meta:event type=None dep=False doc=An analytically relevant event in a curated timeline.
  :duration (duration) - The duration of the event.
  :index (int) - The index of this event in a timeline without exact times.
  :summary (str) - A prose summary of the event.
  :time (time) - The time that the event occurred.
  :timeline (meta:timeline) - The timeline containing the event.
  :title (str) - A title for the event.
  :type (meta:event:taxonomy) - Type of event.

## meta:event:taxonomy type=None dep=False doc=A taxonomy of event types for meta:event nodes.
  :base (taxon) - The base taxon.
  :depth (int) - The depth indexed from 0.
  :desc (str) - A definition of the taxonomy entry.
  :parent (meta:event:taxonomy) - The taxonomy parent.
  :sort (int) - A display sort order for siblings.
  :summary (str) DEPRECATED - Deprecated. Please use title/desc.
  :title (str) - A brief title of the definition.

## inet:server type=None dep=False doc=A network server address.
  :host (it:host) - The it:host node for the server.
  :ipv4 (inet:ipv4) - The IPv4 of the server.
  :ipv6 (inet:ipv6) - The IPv6 of the server.
  :port (inet:port) - The server tcp/udp port.
  :proto (str) - The network protocol of the server.

## inet:banner type=None dep=False doc=A network protocol banner string presented by a server.
  :server (inet:server) - The server which presented the banner string.
  :server:ipv4 (inet:ipv4) - The IPv4 address of the server.
  :server:ipv6 (inet:ipv6) - The IPv6 address of the server.
  :server:port (inet:port) - The network port.
  :text (it:dev:str) - The banner text.

## inet:ipv4 type=None dep=False doc=An IPv4 address.
  :asn (inet:asn) - The ASN to which the IPv4 address is currently assigned.
  :dns:rev (inet:fqdn) - The most current DNS reverse lookup for the IPv4.
  :latlong (geo:latlong) - The best known latitude/longitude for the node.
  :loc (loc) - The geo-political location string for the IPv4.
  :place (geo:place) - The geo:place associated with the latlong property.
  :type (str) - The type of IP address (e.g., private, multicast, etc.).

## inet:ipv6 type=None dep=False doc=An IPv6 address.
  :asn (inet:asn) - The ASN to which the IPv6 address is currently assigned.
  :dns:rev (inet:fqdn) - The most current DNS reverse lookup for the IPv6.
  :ipv4 (inet:ipv4) - The mapped ipv4.
  :latlong (geo:latlong) - The last known latitude/longitude for the node.
  :loc (loc) - The geo-political location string for the IPv6.
  :place (geo:place) - The geo:place associated with the latlong property.
  :scope (str) - The IPv6 scope of the address (e.g., global, link-local, etc.).
  :type (str) - The type of IP address (e.g., private, multicast, etc.).

## inet:asn type=None dep=False doc=An Autonomous System Number (ASN).
  :name (str) - The name of the organization currently responsible for the ASN.
  :owner (ou:org) - The guid of the organization currently responsible for the ASN.

## inet:asnet4 type=None dep=False doc=An Autonomous System Number (ASN) and its associated IPv4 address range.
  :asn (inet:asn) - The Autonomous System Number (ASN) of the netblock.
  :net4 (inet:net4) - The IPv4 address range assigned to the ASN.
  :net4:max (inet:ipv4) - The last IPv4 in the range assigned to the ASN.
  :net4:min (inet:ipv4) - The first IPv4 in the range assigned to the ASN.

## inet:asnet6 type=None dep=False doc=An Autonomous System Number (ASN) and its associated IPv6 address range.
  :asn (inet:asn) - The Autonomous System Number (ASN) of the netblock.
  :net6 (inet:net6) - The IPv6 address range assigned to the ASN.
  :net6:max (inet:ipv6) - The last IPv6 in the range assigned to the ASN.
  :net6:min (inet:ipv6) - The first IPv6 in the range assigned to the ASN.

## pol:country type=None dep=False doc=A GUID for a country.
  :currencies (array) - The official currencies used in the country.
  :dissolved (time) - The date that the country was dissolved.
  :flag (file:bytes) - A thumbnail image of the flag of the country.
  :founded (time) - The date that the country was founded.
  :government (ou:org) - The ou:org node which represents the government of the country.
  :iso2 (pol:iso2) - 
  :iso3 (pol:iso3) - 
  :isonum (pol:isonum) - 
  :name (geo:name) - The name of the country.
  :names (array) - An array of alternate or localized names for the country.
  :place (geo:place) - A geo:place node representing the geospatial properties of the country.
  :pop (int) DEPRECATED - Deprecated. Please use :vitals::population.
  :tld (inet:fqdn) - 
  :vitals (pol:vitals) - The most recent known vitals for the country.

## ou:org type=None dep=False doc=A GUID for a human organization such as a company or military unit.
  :alias (ou:alias) DEPRECATED - Deprecated. Please use ou:org:names.
  :country (pol:country) - The organization's country of origin.
  :country:code (pol:iso2) - The 2 digit ISO 3166 country code for the organization's country of origin.
  :desc (str) - A description of the org.
  :dissolved (time) - The date on which the org was dissolved.
  :dns:mx (array) - An array of MX domains used by email addresses issued by the org.
  :ext:id (str) - An external identifier for the organization.
  :founded (time) - The date on which the org was founded.
  :goals (array) - The assessed goals of the organization.
  :hq (ps:contact) - A collection of contact information for the "main office" of an org.
  :industries (array) - The industries associated with the org.
  :loc (loc) - Location for an organization.
  :locations (array) - An array of contacts for facilities operated by the org.
  :logo (file:bytes) - An image file representing the logo for the organization.
  :motto (lang:phrase) - The motto used by the organization.
  :naics (ou:naics) DEPRECATED - The North American Industry Classification System code for the organization.
  :name (ou:name) - The localized name of an organization.
  :names (array) - A list of alternate names for the organization.
  :orgchart (ou:position) - The root node for an orgchart made up ou:position nodes.
  :orgtype (ou:orgtype) - The type of organization.
  :phone (tel:phone) - The primary phone number for the organization.
  :sic (ou:sic) DEPRECATED - The Standard Industrial Classification code for the organization.
  :subs (array) - An set of sub-organizations.
  :tag (syn:tag) - A base tag used to encode assessments made by the organization.
  :techniques (array) DEPRECATED - Deprecated for scalability. Please use -(uses)> ou:technique.
  :type (str) DEPRECATED - The type of organization.
  :url (inet:url) - The primary url for the organization.
  :us:cage (gov:us:cage) - The Commercial and Government Entity (CAGE) code for the organization.
  :vitals (ou:vitals) - The most recent/accurate ou:vitals for the org.

## ou:name type=None dep=False doc=The name of an organization. This may be a formal name or informal name of the organization.

## inet:whois:iprec type=None dep=False doc=An IPv4/IPv6 block registration record.
  :asn (inet:asn) - The associated Autonomous System Number (ASN).
  :asof (time) - The date of the record.
  :contacts (array) - Additional contacts from the record.
  :country (str) - The two-letter ISO 3166 country code.
  :created (time) - The "created" time from the record.
  :desc (str) - Notes concerning the record.
  :id (inet:whois:regid) - The registry unique identifier (e.g. NET-74-0-0-0-1).
  :links (array) - URLs provided with the record.
  :name (str) - The name assigned to the network by the registrant.
  :net4 (inet:net4) - The IPv4 address range assigned.
  :net4:max (inet:ipv4) - The last IPv4 in the range assigned.
  :net4:min (inet:ipv4) - The first IPv4 in the range assigned.
  :net6 (inet:net6) - The IPv6 address range assigned.
  :net6:max (inet:ipv6) - The last IPv6 in the range assigned.
  :net6:min (inet:ipv6) - The first IPv6 in the range assigned.
  :parentid (inet:whois:regid) - The registry unique identifier of the parent whois record (e.g. NET-74-0-0-0-0).
  :registrant (inet:whois:ipcontact) DEPRECATED - Deprecated. Please use :registrant:name.
  :registrant:name (ou:name) - The name assigned to the network by the registrant.
  :status (str) - The state of the registered network.
  :text (str) - The full text of the record.
  :type (str) - The classification of the registered network (e.g. direct allocation).
  :updated (time) - The "last updated" time from the record.

## inet:whois:ipcontact type=None dep=False doc=An individual contact from an IP block record.
  :asn (inet:asn) - The associated Autonomous System Number (ASN).
  :asof (time) - The date of the record.
  :contact (ps:contact) - Contact information associated with a registration.
  :contacts (array) - Additional contacts referenced by this contact.
  :created (time) - The "created" time from the record.
  :id (inet:whois:regid) - The registry unique identifier (e.g. NET-74-0-0-0-1).
  :links (array) - URLs provided with the record.
  :role (str) - The primary role for the contact.
  :roles (array) - Additional roles assigned to the contact.
  :status (str) - The state of the registered contact (e.g. validated, obscured).
  :updated (time) - The "last updated" time from the record.

## inet:whois:iprecord: DOES NOT EXIST

## inet:fqdn type=None dep=False doc=A Fully Qualified Domain Name (FQDN).
  :domain (inet:fqdn) - The parent domain for the FQDN.
  :host (str) - The host part of the FQDN.
  :issuffix (bool) - True if the FQDN is considered a suffix.
  :iszone (bool) - True if the FQDN is considered a zone.
  :zone (inet:fqdn) - The zone level parent for this FQDN.

## it:prod:soft type=None dep=False doc=A software product.
  :author (ps:contact) - The contact information of the org or person who authored the software.
  :author:acct (inet:web:acct) DEPRECATED - Deprecated. Please use :author to link to a ps:contact.
  :author:email (inet:email) DEPRECATED - Deprecated. Please use :author to link to a ps:contact.
  :author:org (ou:org) DEPRECATED - Deprecated. Please use :author to link to a ps:contact.
  :author:person (ps:person) DEPRECATED - Deprecated. Please use :author to link to a ps:contact.
  :cpe (it:sec:cpe) - The NIST CPE 2.3 string specifying this software.
  :desc (str) - A description of the software.
  :desc:short (str) - A short description of the software.
  :id (str) - An ID for the software.
  :islib (bool) - Set to True if the software is a library.
  :isos (bool) - Set to True if the software is an operating system.
  :name (it:prod:softname) - Name of the software.
  :names (array) - Observed/variant names for this software.
  :tag (syn:tag) - The tag used to annotate nodes that are associated with the software.
  :techniques (array) DEPRECATED - Deprecated for scalability. Please use -(uses)> ou:technique.
  :type (it:prod:soft:taxonomy) - The software type.
  :url (inet:url) - URL relevant for the software.

## it:prod:softver type=None dep=False doc=A specific version of a software product.
  :arch (it:dev:str) - Software architecture.
  :cpe (it:sec:cpe) - The NIST CPE 2.3 string specifying this software version.
  :cves (array) - A list of CVEs that apply to this software version.
  :desc (str) - A description of the software.
  :name (it:prod:softname) - Name of the software version.
  :names (array) - Observed/variant names for this software version.
  :released (time) - Timestamp for when this version of the software was released.
  :semver (it:semver) - System normalized semantic version number.
  :semver:build (str) DEPRECATED - Deprecated.
  :semver:major (int) DEPRECATED - Deprecated. Please use semver range queries.
  :semver:minor (int) DEPRECATED - Deprecated. Please use semver range queries.
  :semver:patch (int) DEPRECATED - Deprecated. Please use semver range queries.
  :semver:pre (str) DEPRECATED - Deprecated.
  :software (it:prod:soft) - Software associated with this version instance.
  :software:name (str) DEPRECATED - Deprecated. Please use it:prod:softver:name.
  :url (inet:url) - URL where a specific version of the software is available from.
  :vers (it:dev:str) - Version string associated with this version instance.
  :vers:norm (str) - Normalized version of the version string.

## risk:vuln type=None dep=False doc=A unique vulnerability.
  :cisa:kev:action (str) DEPRECATED - Deprecated. Please use it:sec:cve:cisa:kev:action.
  :cisa:kev:added (time) DEPRECATED - Deprecated. Please use it:sec:cve:cisa:kev:added.
  :cisa:kev:desc (str) DEPRECATED - Deprecated. Please use it:sec:cve:cisa:kev:desc.
  :cisa:kev:duedate (time) DEPRECATED - Deprecated. Please use it:sec:cve:cisa:kev:duedate.
  :cisa:kev:name (str) DEPRECATED - Deprecated. Please use it:sec:cve:cisa:kev:name.
  :cisa:kev:product (it:prod:softname) DEPRECATED - Deprecated. Please use it:sec:cve:cisa:kev:product.
  :cisa:kev:vendor (ou:name) DEPRECATED - Deprecated. Please use it:sec:cve:cisa:kev:vendor.
  :cve (it:sec:cve) - The CVE ID of the vulnerability.
  :cve:desc (str) - The description of the vulnerability according to the CVE database.
  :cve:references (array) - An array of documentation URLs provided by the CVE database.
  :cve:url (inet:url) - A URL linking this vulnerability to the CVE description.
  :cvss:a (str) DEPRECATED - Deprecated. Please use :cvss:v3.
  :cvss:ac (str) DEPRECATED - Deprecated. Please use :cvss:v3.
  :cvss:ar (str) DEPRECATED - Deprecated. Please use :cvss:v3.
  :cvss:av (str) DEPRECATED - Deprecated. Please use :cvss:v3.
  :cvss:c (str) DEPRECATED - Deprecated. Please use :cvss:v3.
  :cvss:cr (str) DEPRECATED - Deprecated. Please use :cvss:v3.
  :cvss:e (str) DEPRECATED - Deprecated. Please use :cvss:v3.
  :cvss:i (str) DEPRECATED - Deprecated. Please use :cvss:v3.
  :cvss:ir (str) DEPRECATED - Deprecated. Please use :cvss:v3.
  :cvss:ma (str) DEPRECATED - Deprecated. Please use :cvss:v3.
  :cvss:mac (str) DEPRECATED - Deprecated. Please use :cvss:v3.
  :cvss:mav (str) DEPRECATED - Deprecated. Please use :cvss:v3.
  :cvss:mc (str) DEPRECATED - Deprecated. Please use :cvss:v3.
  :cvss:mi (str) DEPRECATED - Deprecated. Please use :cvss:v3.
  :cvss:mpr (str) DEPRECATED - Deprecated. Please use :cvss:v3.
  :cvss:ms (str) DEPRECATED - Deprecated. Please use :cvss:v3.
  :cvss:mui (str) DEPRECATED - Deprecated. Please use :cvss:v3.
  :cvss:pr (str) DEPRECATED - Deprecated. Please use :cvss:v3.
  :cvss:rc (str) DEPRECATED - Deprecated. Please use :cvss:v3.
  :cvss:rl (str) DEPRECATED - Deprecated. Please use :cvss:v3.
  :cvss:s (str) DEPRECATED - Deprecated. Please use :cvss:v3.
  :cvss:score (float) DEPRECATED - Deprecated. Please use version specific score properties.
  :cvss:score:base (float) DEPRECATED - Deprecated. Please use version specific score properties.
  :cvss:score:environmental (float) DEPRECATED - Deprecated. Please use version specific score properties.
  :cvss:score:temporal (float) DEPRECATED - Deprecated. Please use version specific score properties.
  :cvss:ui (str) DEPRECATED - Deprecated. Please use :cvss:v3.
  :cvss:v2 (cvss:v2) - The CVSS v2 vector for the vulnerability.
  :cvss:v2_0:score (float) - The CVSS v2.0 overall score for the vulnerability.
  :cvss:v2_0:score:base (float) - The CVSS v2.0 base score for the vulnerability.
  :cvss:v2_0:score:environmental (float) - The CVSS v2.0 environmental score for the vulnerability.
  :cvss:v2_0:score:temporal (float) - The CVSS v2.0 temporal score for the vulnerability.
  :cvss:v3 (cvss:v3) - The CVSS v3 vector for the vulnerability.
  :cvss:v3_0:score (float) - The CVSS v3.0 overall score for the vulnerability.
  :cvss:v3_0:score:base (float) - The CVSS v3.0 base score for the vulnerability.
  :cvss:v3_0:score:environmental (float) - The CVSS v3.0 environmental score for the vulnerability.
  :cvss:v3_0:score:temporal (float) - The CVSS v3.0 temporal score for the vulnerability.
  :cvss:v3_1:score (float) - The CVSS v3.1 overall score for the vulnerability.
  :cvss:v3_1:score:base (float) - The CVSS v3.1 base score for the vulnerability.
  :cvss:v3_1:score:environmental (float) - The CVSS v3.1 environmental score for the vulnerability.
  :cvss:v3_1:score:temporal (float) - The CVSS v3.1 temporal score for the vulnerability.
  :cwes (array) - An array of MITRE CWE values that apply to the vulnerability.
  :desc (str) - A description of the vulnerability.
  :exploited (bool) - Set to true if the vulnerability has been exploited in the wild.
  :id (str) - An identifier for the vulnerability.
  :mitigated (bool) - Set to true if a mitigation/fix is available for the vulnerability.
  :name (risk:vulnname) - A user specified name for the vulnerability.
  :names (array) - An array of alternate names for the vulnerability.
  :nist:nvd:modified (time) DEPRECATED - Deprecated. Please use it:sec:cve:nist:nvd:modified.
  :nist:nvd:published (time) DEPRECATED - Deprecated. Please use it:sec:cve:nist:nvd:published.
  :nist:nvd:source (ou:name) DEPRECATED - Deprecated. Please use it:sec:cve:nist:nvd:source.
  :priority (meta:priority) - The priority of the vulnerability.
  :reporter (ou:org) - The organization reporting on the vulnerability.
  :reporter:name (ou:name) - The name of the organization reporting on the vulnerability.
  :reporter:url (inet:url) - The URL for the vulnerability provided by the reporter.
  :severity (meta:severity) - The severity of the vulnerability.
  :tag (syn:tag) - A tag used to annotate the presence or use of the vulnerability.
  :timeline:discovered (time) - The earliest known discovery time for the vulnerability.
  :timeline:exploited (time) - The earliest known time when the vulnerability was exploited in the wild.
  :timeline:published (time) - The earliest known time the vulnerability was published.
  :timeline:vendor:fixed (time) - The earliest known time the vendor issued a fix for the vulnerability.
  :timeline:vendor:notified (time) - The earliest known vendor notification time for the vulnerability.
  :type (risk:vuln:type:taxonomy) - A taxonomy type entry for the vulnerability.

## inet:ssl:jarmhash type=None dep=False doc=A TLS JARM fingerprint hash.
  :ciphers (str) - The encoded cipher and TLS version of the server.
  :extensions (str) - The truncated SHA256 of the TLS server extensions.

## crypto:x509:cert type=None dep=False doc=A unique X.509 certificate.
  :algo (iso:oid) - The X.509 signature algorithm OID.
  :crl:urls (array) - The extracted URL values from the CRLs extension.
  :ext:crls (array) - A list of Subject Alternate Names (SANs) for Distribution Points.
  :ext:sans (array) - The Subject Alternate Names (SANs) listed in the certificate.
  :file (file:bytes) - The file that the certificate metadata was parsed from.
  :identities:emails (array) - The fused list of e-mail addresses identified by the cert CN and SANs.
  :identities:fqdns (array) - The fused list of FQDNs identified by the cert CN and SANs.
  :identities:ipv4s (array) - The fused list of IPv4 addresses identified by the cert CN and SANs.
  :identities:ipv6s (array) - The fused list of IPv6 addresses identified by the cert CN and SANs.
  :identities:urls (array) - The fused list of URLs identified by the cert CN and SANs.
  :issuer (str) - The Distinguished Name (DN) of the Certificate Authority (CA) which issued the certificate.
  :issuer:cert (crypto:x509:cert) - The certificate used by the issuer to sign this certificate.
  :md5 (hash:md5) - The MD5 fingerprint for the certificate.
  :rsa:key (rsa:key) - The optional RSA public key associated with the certificate.
  :selfsigned (bool) - Whether this is a self-signed certificate.
  :serial (hex) - The certificate serial number as a big endian hex value.
  :sha1 (hash:sha1) - The SHA1 fingerprint for the certificate.
  :sha256 (hash:sha256) - The SHA256 fingerprint for the certificate.
  :signature (hex) - The hexadecimal representation of the digital signature.
  :subject (str) - The subject identifier, commonly in X.500/LDAP format, to which the certificate was issued.
  :validity:notafter (time) - The timestamp for the end of the certificate validity period.
  :validity:notbefore (time) - The timestamp for the beginning of the certificate validity period.
  :version (int) - The version integer in the certificate. (ex. 2 == v3 ).

## inet:net4: DOES NOT EXIST

## inet:cidr4 type=None dep=False doc=An IPv4 address block in Classless Inter-Domain Routing (CIDR) notation.
  :broadcast (inet:ipv4) - The broadcast IP address from the CIDR notation.
  :mask (int) - The mask from the CIDR notation.
  :network (inet:ipv4) - The network IP address from the CIDR notation.

## meta:source type=None dep=False doc=A data source unique identifier.
  :ingest:cursor (str) - Used by ingest logic to capture the current ingest cursor within a feed.
  :ingest:latest (time) - Used by ingest logic to capture the last time a feed ingest ran.
  :ingest:offset (int) - Used by ingest logic to capture the current ingest offset within a feed.
  :name (str) - A human friendly name for the source.
  :type (str) - An optional type field used to group sources.
  :url (inet:url) - A URL which documents the meta source.

## meta:rule type=None dep=False doc=A generic rule linked to matches with -(matches)> edges.
  :author (ps:contact) - The contact information of the rule author.
  :created (time) - The time the rule was initially created.
  :desc (str) - A description of the rule.
  :ext:id (str) - An external identifier for the rule.
  :name (str) - A name for the rule.
  :status (meta:rule:status:taxonomy) - The status of the rule.
  :text (str) - The text of the rule logic.
  :type (meta:rule:type:taxonomy) - The rule type.
  :updated (time) - The time the rule was most recently modified.
  :url (inet:url) - A URL which documents the rule.

## inet:http:response:header type=None dep=False doc=An HTTP response header.
  :name (inet:http:header:name) - The name of the HTTP response header.
  :value (str) - The value of the HTTP response header.

## inet:ssh:hassh: DOES NOT EXIST

## inet:service:platform type=None dep=False doc=A network platform which provides services.
  :creator (inet:service:account) - The service account which created the platform.
  :desc (str) - A description of the service platform.
  :family (str) - A family designation for use with instanced platforms such as Slack, Discord, or Mastodon.
  :id (str) - An ID which identifies the platform.
  :name (str) - A friendly name for the platform.
  :names (array) - An array of alternate names for the platform.
  :parent (inet:service:platform) - A parent platform which owns this platform.
  :period (ival) - The period when the platform existed.
  :provider (ou:org) - The organization which operates the platform.
  :provider:name (ou:name) - The name of the organization which operates the platform.
  :remover (inet:service:account) - The service account which removed or decommissioned the platform.
  :software (it:prod:softver) - The latest known software version that the platform is running.
  :status (inet:service:object:status) - The status of the platform.
  :tenant (inet:service:tenant) - The tenant which owns the platform.
  :type (inet:service:platform:type:taxonomy) - The type of service platform.
  :url (inet:url) - The primary URL of the platform.
  :urls (array) - An array of alternate URLs for the platform.
  :zone (inet:fqdn) - The primary zone for the platform.
  :zones (array) - An array of alternate zones for the platform.

## geo:telem type=None dep=False doc=The geospatial position and physical characteristics of a node at a given time.
  :accuracy (geo:dist) DEPRECATED - Deprecated. Please use :place:latlong:accuracy.
  :desc (str) - A description of the telemetry sample.
  :latlong (geo:latlong) DEPRECATED - Deprecated. Please use :place:latlong.
  :node (ndef) - The node that was observed at the associated time and place.
  :phys:height (geo:dist) - The height of the object.
  :phys:length (geo:dist) - The length of the object.
  :phys:mass (mass) - The mass of the object.
  :phys:volume (geo:dist) - The cubed volume of the object.
  :phys:width (geo:dist) - The width of the object.
  :place (geo:place) - The place where the object was located.
  :place:address (geo:address) - The postal address of the place where the object was located.
  :place:country (pol:country) - The country where the object was located.
  :place:country:code (pol:iso2) - The country code where the object was located.
  :place:latlong (geo:latlong) - The latlong where the object was located.
  :place:latlong:accuracy (geo:dist) - The accuracy of the latlong where the object was located.
  :place:loc (loc) - The geopolitical location of the object.
  :place:name (geo:name) - The name of the place where the object was located.
  :time (time) - The time that the telemetry measurements were taken.

## inet:servfile type=None dep=False doc=A file hosted on a server for access over a network protocol.
  :file (file:bytes) - The file hosted by the server.
  :server (inet:server) - The inet:addr of the server.
  :server:host (it:host) - The it:host node for the server.
  :server:ipv4 (inet:ipv4) - The IPv4 of the server.
  :server:ipv6 (inet:ipv6) - The IPv6 of the server.
  :server:port (inet:port) - The server tcp/udp port.
  :server:proto (str) - The network protocol of the server.

## edges
  ou:campaign -(uses)> ou:technique: The campaign used the technique.
  ou:org -(uses)> ou:technique: The org uses the technique.
  risk:vuln -(uses)> ou:technique: The vulnerability uses the technique.
  ou:org -(uses)> None: The ou:org makes use of the target node.
  ou:org -(targets)> None: The organization targets the target node.
  ou:campaign -(uses)> None: The campaign made use of the target node.
  ou:org -(has)> None: The organization is or was in possession of the target node.
  ou:org -(owns)> None: The organization owns or owned the target node.
  None -(refs)> None: The source node contains a reference to the target node.
  meta:source -(seen)> None: The meta:source observed the target node.
  meta:feed -(found)> None: The meta:feed produced the target node.
  meta:note -(about)> None: The meta:note is about the target node.
  meta:ruleset -(has)> meta:rule: The meta:ruleset includes the meta:rule.
  meta:ruleset -(has)> inet:service:rule: The meta:ruleset includes the inet:service:rule.
  meta:ruleset -(has)> it:app:snort:rule: The meta:ruleset includes the it:app:snort:rule.
  meta:ruleset -(has)> it:app:yara:rule: The meta:ruleset includes the it:app:yara:rule.
  meta:rule -(matches)> None: The meta:rule has matched on target node.
  meta:rule -(detects)> None: The meta:rule is designed to detect instances of the target node.
  meta:rule -(generated)> risk:alert: The meta:rule generated the risk:alert node.
  meta:rule -(generated)> it:log:event: The meta:rule generated the it:log:event node.
  risk:tool:software -(uses)> math:algorithm: The tool uses the algorithm.
  it:prod:softver -(uses)> math:algorithm: The software uses the algorithm.
  file:bytes -(uses)> math:algorithm: The file uses the algorithm.
  risk:attack -(uses)> ou:technique: The attacker used the technique in the attack.
  risk:threat -(uses)> ou:technique: The threat cluster uses the technique.
  risk:tool:software -(uses)> ou:technique: The tool uses the technique.
  risk:compromise -(uses)> ou:technique: The attacker used the technique in the compromise.
  risk:extortion -(uses)> ou:technique: The attacker used the technique to extort the victim.
  risk:attack -(uses)> risk:vuln: The attack used the vulnerability.
  risk:threat -(uses)> risk:vuln: The threat cluster uses the vulnerability.
  risk:tool:software -(uses)> risk:vuln: The tool uses the vulnerability.
  ou:technique -(uses)> risk:vuln: The technique uses the vulnerability.
  risk:threat -(uses)> None: The threat cluster uses the target node.
  risk:threat -(uses)> inet:service:platform: The threat cluster uses the service platform.
  risk:threat -(uses)> inet:service:app: Deprecated. Please use the inet:service:platform form instead.
  risk:attack -(uses)> None: The attack used the target node to facilitate the attack.
  risk:tool:software -(uses)> None: The tool uses the target node.
  risk:mitigation -(uses)> meta:rule: The mitigation uses the rule.
  risk:mitigation -(uses)> it:app:yara:rule: The mitigation uses the YARA rule.
  risk:mitigation -(uses)> it:app:snort:rule: The mitigation uses the Snort rule.
  risk:mitigation -(uses)> inet:service:rule: The mitigation uses the service rule.
  risk:mitigation -(uses)> it:prod:softver: The mitigation uses the software version.
  risk:mitigation -(uses)> it:prod:hardware: The mitigation uses the hardware.
  meta:event -(caused)> risk:outage: The event caused the outage.
  risk:alert -(about)> None: The alert is about the target node.
  ps:contact -(has)> None: The contact is or was in possession of the target node.
  ps:person -(has)> None: The person is or was in possession of the target node.
  file:bytes -(refs)> it:dev:str: The source file contains the target string.
  it:prod:soft -(uses)> ou:technique: The software uses the technique.
  it:prod:soft -(uses)> risk:vuln: The software uses the vulnerability.
  it:exec:query -(found)> None: The target node was returned as a result of running the query.
  it:dev:repo -(has)> inet:url: The repo has content hosted at the URL.
  it:dev:repo:commit -(has)> it:dev:repo:entry: The file entry is present in the commit version of the repository.
  it:log:event -(about)> None: The it:log:event is about the target node.
  None -(seenat)> geo:telem: Deprecated. Please use geo:telem:node.
  inet:whois:iprec -(ipwhois)> inet:ipv4: The source IP whois record describes the target IPv4 address.
  inet:whois:iprec -(ipwhois)> inet:ipv6: The source IP whois record describes the target IPv6 address.
  econ:bank:statement -(has)> econ:acct:payment: The bank statement includes the payment.
  belief:system -(has)> belief:tenet: The belief system includes the tenet.
  sci:experiment -(uses)> None: The experiment used the target nodes when it was run.
  sci:observation -(has)> None: The observations are summarized from the target nodes.
  sci:evidence -(has)> None: The evidence includes observations from the target nodes.
  plan:procedure:step -(uses)> None: The step in the procedure makes use of the target node.
```

## Dump script

```python
import asyncio, json, sys
import synapse, synapse.cortex as s_cortex, synapse.common as s_common
FORMS = ["it:exec:query","it:query","meta:timeline","meta:timeline:taxonomy","meta:event","meta:event:taxonomy",
 "inet:server","inet:banner","inet:ipv4","inet:ipv6","inet:asn","inet:asnet4","inet:asnet6","pol:country","ou:org","ou:name",
 "inet:whois:iprec","inet:whois:ipcontact","inet:whois:iprecord","inet:fqdn","it:prod:soft","it:prod:softver","risk:vuln",
 "inet:ssl:jarmhash","crypto:x509:cert","inet:net4","inet:cidr4","meta:source","meta:rule","inet:http:response:header","inet:ssh:hassh","inet:service:platform","geo:telem","inet:servfile"]
async def main():
    with s_common.getTempDir() as d:
        async with await s_cortex.Cortex.anit(d) as core:
            md = await core.getModelDict()
            print("synapse", synapse.version)
            for f in FORMS:
                fd = md['forms'].get(f)
                if fd is None:
                    print(f"\n## {f}: DOES NOT EXIST"); continue
                t = md['types'].get(f,{})
                print(f"\n## {f} type={fd.get('type')} dep={t.get('info',{}).get('deprecated', False)} doc={t.get('info',{}).get('doc','')[:150]}")
                for pn, pd in sorted(fd['props'].items()):
                    if pn.startswith('.'): continue
                    dep = ' DEPRECATED' if pd.get('deprecated') else ''
                    print(f"  :{pn} ({pd['type'][0]}){dep} - {pd.get('doc','')[:110]}")
            print("\n## edges")
            for (n1, verb, n2), info in md['edges']:
                if verb in ('refs','found','seen','uses','about','has') or (n1 in FORMS or n2 in FORMS):
                    print(f"  {n1} -({verb})> {n2}: {info.get('doc','')[:100]}")
if __name__ == "__main__":
    asyncio.run(main())
```
