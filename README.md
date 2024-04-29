# azure-sc-900

## MS Microsoft Certified: Security, Compliance, and Identity Fundamentals

https://learn.microsoft.com/en-us/credentials/certifications/security-compliance-and-identity-fundamentals/?practice-assessment-type=certification

### Describe security and compliance concepts

#### Describe the shared responsibility model

In summary, responsibilities always retained by the customer organization include:

* Information and data
* Devices (mobile and PCs)
* Accounts and identities

![shared responsibility model](https://github.com/spawnmarvel/azure-sc-900/blob/main/images/shared_model.jpg)

#### Describe defense in depth

Defense in depth uses a layered approach to security, rather than relying on a single perimeter.

A defense in-depth strategy uses a series of mechanisms to slow the advance of an attack.

* Physical security such as limiting access to a datacenter
* Identity and access security controls
* Perimeter security of network, DDos protection to filter large-scale attacks before they can cause a denial of service for users.
* Network security, network segmentation and limit communication.
* Compute layer security, closing ports.
* Application layer security to ensure applications are secure and free of security vulnerabilities.
* Data layer security, encryption

![layers](https://github.com/spawnmarvel/azure-sc-900/blob/main/images/layers.jpg)

Confidentiality, Integrity, Availability (CIA)**

As described above, a defense in-depth strategy uses a series of mechanisms to slow the advance of an attack.
All mechanisms are elements of cyber security, were the goal is:

* Condidentiality
* * Sensitive data, passwords, financial, can encrypt, but then need to decrypt.
* integity
* * Keeping data correct, send data = recieved data, no tampering.
* availability
* * making data available to thosse who need it, when they need it.

#### Describe the Zero Trust model

"trust no one, verify everything".

Zero Trust guiding principles

* Verify explicitly. Always authenticate and authorize based on the available data points, including user identity, location, device, service or workload, data classification, and anomalies.
* Least privileged access., JIT, policys, data protection
* Assume breach, segment access by nytwork, users, device, application. Encrypt, etc.

***Six foundational pillars***

In the Zero Trust model, all elements work together to provide end-to-end security.

* Identities may be users, services, or devices, verify it, strong auth, and least priv.
* Devices create a large attack surface, monitor everything.
* Applications are the way that data is consumed. This includes discovering all applications being used, shadow IT.
* Data should be classified, labeled, and encrypted based on its attributes.
* Infrastructure represents a threat factor. assess for version, configuration, JIT and telemetry monitor for attacks.
* Networks should be segmented, including depper in-network micros segmentation, real-time threat protection, end-2-end encryption, monitor/analytics.

![zero_trust](https://github.com/spawnmarvel/azure-sc-900/blob/main/images/zero_trust.jpg)

#### Describe encryption and hashing

One way to mitigate against threats = encryption.

There are two top-level types of encryption: symmetric and asymmetric.

* Symmetric = same key to encrypt and decrypt the data.
* Asymmetric = uses a public key and private key pair.
* * To decrypt, you need a paired key. For example, if the public key is used to encrypt, then only the corresponding private key can be used to decrypt.
* * HTTPS, AMQPS, mtls, etc.

Encryption for data at rest

* Data on server, db or storage that is encrypted and need keys/secrets to decrypt.

Encryption for data in transit

* Data in transit is the data moving from one location to another.
* HTTPS is an example of encryption in transit.

Encryption for data in use
* A common use case for encryption of data in use involves securing data in nonpersistent storage, such as RAM or CPU caches
* Tech process enclave (secured lockbox) that protects HW while processing

Hashing
* Hashing uses an algorithm to convert text to a unique fixed-length value called a hash.
* Each time the same text is hashed using the same algorithm, the same hash value is produced. 
* That hash can then be used as a unique identifier of its associated data.
* Hashing is different to encryption in that it doesn't use keys, and the hashed value isn't subsequently decrypted back to the original.
* Hashing is often used to store passwords.
* Because hash functions are deterministic (the same input produces the same output), hackers can use brute-force dictionary attacks by hashing the passwords.
* To mitigate this risk, passwords are often “salted”. This refers to adding a fixed-length random value to the input of hash functions to create unique hashes for same input.

#### Describe governance, risk, and compliance (GRC) concepts

Organizations face increasing complexity and change in regulatory environments, calling for a more structured approach for managing governance, risk, and compliance (GRC).

As organizations establish GRC competency they can establish a framework that includes implementing specific policies, operational processes, and technologies.

Governance
* Governance is the system of rules, practices, and processes an organization uses to direct and control its activities.
* Many governance activities arise from external standards, obligations and expectations.

Risk
* Risk management is the process of identifying, assessing, and responding to threats or events that can impact company or customer objectives.

Compliance
* Compliance refers to the country/region, state or federal laws or even multi-national regulations that an organization must follow. 
* ... what types of data must be protected, what processes are required under the legislation, and what penalties are issued to organizations that fail to comply.

Some compliance-related concepts include:
* Data residency - When it comes to compliance, data residency regulations govern the physical locations where data can be stored, transferd..
* Data sovereignty - Another important consideration is data sovereignty, the concept that data, particularly personal data, is subject to the laws and regulations of the country/region in which it's physically collected, held, or processed.
* Data privacy - Providing notice and being transparent about the collection, processing, use, and sharing of personal data are fundamental principles of privacy laws and regulations. 


### Describe identity concepts

#### Define authentication and authorization

Authentication

* ... proving that a person is who they say they are. (ID card)
*  The username and password, together, are a form of authentication. Authentication is sometimes shortened to AuthN.

Authorization

* ... you'll need to decide where they can go, and what they're allowed to see and touch. (Key card)
*  Level of access or the permissions an authenticated person has to your data and resources. Authorization is sometimes shortened to AuthZ.

#### Define identity as the primary security perimeter



### TBD

## J.S Youtube

https://www.youtube.com/watch?v=Bz-8jM3jg-8

## Practice Assessment for Exam SC-900: Microsoft Security, Compliance, and Identity Fundamentals

| #  | Sum | Comment
| --- | --- | -------------
| 1   | 74  | No reading
| 2   | 54  | In a hurry
| x   | x   | xxxx
