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


### Describe identity concepts

### TBD

## J.S Youtube

https://www.youtube.com/watch?v=Bz-8jM3jg-8

## Practice Assessment for Exam SC-900: Microsoft Security, Compliance, and Identity Fundamentals

| #  | Sum | Comment
| --- | --- | -------------
| 1   | 74  | No reading
| 2   | 54  | In a hurry
| x   | x   | xxxx
