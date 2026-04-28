# Brisbane

Project Brisbane delivers a Java [Cryptographic Service Provider](https://docs.oracle.com/en/java/javase/26/security/java-cryptography-architecture-jca-reference-guide.html#GUID-3E0744CE-6AC7-4A6D-A1F6-6C01199E6920) (CSP)
for Java's [JCA](https://docs.oracle.com/en/java/javase/26/security/java-cryptography-architecture-jca-reference-guide.html#GUID-2BCFDD85-D533-4E6C-8CE9-29990DEB0190) framework,
enabling Java applications to use FIPS-validated cryptography in regulated environments.
Internally, the CSP delegates cryptographic operations to the [OpenSSL FIPS provider](https://docs.openssl.org/master/man7/OSSL_PROVIDER-FIPS/).
The OpenSSL FIPS Provider, in turn, uses a [cryptographic module](https://csrc.nist.gov/glossary/term/cryptographicmodule)
that conforms to the Federal Information Processing Standard (FIPS) requirements specified in [FIPS 140-3](https://csrc.nist.gov/pubs/fips/140-3/final).

In short, Brisbane bridges Java's standard cryptography interfaces and FIPS-regulated deployment requirements,
making it easier to build and run Java systems that must meet government and industry security mandates
while continuing to use familiar JCA patterns.

Project Brisbane is an open source project, released under the
[Universal Permissive License (UPL), Version 1.0](LICENSE).
Contributions are welcome - please help improve the project, port it to additional platforms or devices,
and reuse or modify the code as permitted by the license.

Brisbane is a project under the charter of the OpenJDK.
The [OpenJDK Bylaws](https://openjdk.org/bylaws) and [License](LICENSE) govern our work.
The Brisbane project membership can be found on the [OpenJDK Census](https://openjdk.org/census#brisbane).
We welcome patches and involvement from individual contributors or companies.
If this is your first time contributing to an OpenJDK project,
you will need to review the rules on becoming a Contributor,
and sign the Oracle Contributor Agreement (OCA).

## Issue Tracking

If you are reporting a possible security vulnerability, **DO NOT** use the issue tracking system documented below.
Please follow the process outlined in the [OpenJDK Vulnerability Policy](https://openjdk.org/groups/vulnerability/report).

If you think you have found a bug, first make sure that you are testing against
the latest version - your issue may already have been fixed.
If not, search our [issues list](https://bugs.openjdk.org/projects/BRISBANE/issues/?filter=allopenissues)
in case a similar issue has already been opened.

## Getting Started

For instructions on building and testing the project, see [doc/build-and-test.md](doc/build-and-test.md).

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct, and the process for submitting pull
requests to us.

## Common Tasks

 * Build and test the project: see [doc/build-and-test.md](doc/build-and-test.md)
 * Integrate the security provider in an application: see [doc/usage.md](doc/usage.md)
 * Configuring the security provider through Java System Properties: see [doc/configuration.md](doc/configuration.md)
