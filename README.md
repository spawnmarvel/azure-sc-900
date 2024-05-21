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

Digital collaboration has changed. Your employees and partners now need to collaborate and access organizational resources from anywhere, on any device, and without affecting their productivity. There has also been an acceleration in the number of people working from home.

The security perimeter can no longer be viewed as the on-premises network. It now extends to:

* SaaS applications, hosted outside the corporate network.
* The personal devices, BYOD.
* The unmanaged devices used by partners or customers.
* Internet of things, referred to as IoT devices.

The traditional perimeter-based security model is no longer enough. 
***Identity has become the new security perimeter that enables organizations to secure their assets.***

An identity is the set of things that define or characterize someone or something.

* a person’s identity, username and password and their level of authorization.
* An identity may be associated with a user, an application, a device, or something else.

Four pillars of an identity infrastructure

* Administration. Administration is about the creation and management/governance of identities for users, devices, and services.
* Authentication. The authentication pillar tells the story of how much an IT system needs to know about an identity to have sufficient proof that they really are who they say they are.
* Authorization. The authorization pillar is about processing the incoming identity data to determine the level of access an authenticated person or service has within the application or service that it wants to access.
* Auditing. The auditing pillar is about tracking who does what, when, where, and how.

#### Describe the role of the identity provider

An identity provider creates, maintains, and manages identity information while offering authentication, authorization, and auditing services.

Modern autentication:
* C get security token from Idp
* S validates with Idp via trust relation
* Token = signed document
* Claims = info about identity calling the server (person,BYOD, process)
* * Subject = immutable, non reusable identifier for identity
* * Issued at = when was issued
* * Expiration = When expire
* * Audience = Token is for C1, non other. S1 can not use it for S2.


![Identity Provider](https://github.com/spawnmarvel/azure-sc-900/blob/main/images/idp.jpg)

Microsoft Entra ID is an example of a cloud-based identity provider. Other examples include Google, Amazon, LinkedIn, and GitHub.

Single sign-on

Another fundamental capability of an identity provider and “modern authentication” is the support for single sign-on (SSO). 

* With SSO, the user logs in once and that credential is used to access multiple applications or resources.


#### Describe the concept of directory services and Active Directory

In the context of a computer network, a directory is a hierarchical structure that stores information about objects on the network.

* Active Directory (AD) is a set of directory services developed by Microsoft as part of Windows 2000 for on-premises domain-based networks.
* The best-known service of this kind is Active Directory Domain Services (AD DS).
* A server running AD DS is a domain controller (DC).
* AD DS is a central component in organizations with on-premises IT infrastructure.

AD DS doesn't, however, natively support mobile devices, SaaS applications, or line of business apps that require modern authentication methods.

The growth of cloud services, SaaS applications, and personal devices being used at work, has resulted in the need for modern authentication, and an evolution of Active Directory-based identity solutions.

* Microsoft Entra ID (previously referred to as Azure Active Directory) and part of the Microsoft Entra family of multicloud identity and access solutions, dentity as a Service, IDaaS. 


#### Describe the concept of federation

Federation enables the access of services across organizational or domain boundaries by establishing trust relationships between the respective domain’s identity provider.

* With federation, there's no need for a user to maintain a different username and password when accessing resources in other domains.

![Federation](https://github.com/spawnmarvel/azure-sc-900/blob/main/images/federation.jpg)

With federation, trust isn't always bidirectional.

Although IdP-A may trust IdP-B and allow the user in domain B to access the website in domain A, the opposite isn't true, unless that trust relationship is configured.

A common example of federation in practice is when a user logs in to a third-party site with their social media account, such as Twitter. In this scenario, Twitter is an identity provider, and the third-party site might be using a different identity provider, such as Microsoft Entra ID. There's a trust relationship between Microsoft Entra ID and Twitter.


### Describe the function and identity types of Microsoft Entra ID

When it comes to security, your organization can no longer rely on its network boundary. To allow employees, partners, and customers to collaborate securely, organizations need to shift to an approach whereby identity becomes the new security perimeter.

#### Describe Microsoft Entra ID

Microsoft Entra ID, formerly Azure Active Directory, is Microsoft’s cloud-based identity and access management service.

Microsoft Entra ID includes an identity secure score, which is a percentage that functions as an indicator for how aligned you are with Microsoft's best practice recommendations for security.


Tenant

* - A Microsoft Entra tenant is an instance of Microsoft Entra ID in which information about a single organization resides including organizational objects such as users, groups, devices, and application registrations.

Directory 

* - The terms Microsoft Entra directory and Microsoft Entra tenant are often used interchangeably. The directory is a logical container within a Microsoft Entra tenant that holds and organizes the various resources and objects related to identity and access management including users, groups, applications, devices, and other directory objects.

Multi-tenant 

* - A multi-tenant organization is an organization that has more than one instance of Microsoft Entra ID.


#### Describe types of identities

In Microsoft Entra ID, there are different types of identities that are supported. 

* You can assign identities to people (humans).
* You can assign identities to physical devices, such as mobile phones, desktop computers, and IoT devices.
* Lastly, you can assign identities to software-based objects, such as applications, virtual machines, services, and containers. These identities are referred to as workload identities.

Workload identities

* A workload identity is an identity you assign to a software workload.

Applications and service principals

* A service principal is essentially, an identity for an application. 
* For an application to delegate its identity and access functions to Microsoft Entra ID, the application must first be registered with Microsoft Entra ID to enable its integration.
* Once an application is registered, a service principal is created in each Microsoft Entra tenant where the application is used. The service principal enables core features such as authentication and authorization of the application to resources that are secured by the Microsoft Entra tenant.

Managed identities

* Managed identities are a type of service principal that are automatically managed in Microsoft Entra ID and eliminate the need for developers to manage credentials.
* System-assigned. Some Azure resources, such as virtual machines, allow you to enable a managed identity directly on the resource.
* User-assigned. You may also create a managed identity as a standalone Azure resource. Once you create a user-assigned managed identity, you can assign it to one or more instances of an Azure service


Device

* Microsoft Entra registered devices. The goal of Microsoft Entra registered devices is to provide users with support for bring your own device (BYOD) or mobile device scenarios.
* Microsoft Entra joined. A Microsoft Entra joined device is a device joined to Microsoft Entra ID through an organizational account, which is then used to sign in to the device.
* Microsoft Entra hybrid joined devices. Organizations with existing on-premises Active Directory implementations can benefit from the functionality provided by Microsoft Entra ID by implementing Microsoft Entra hybrid joined devices.

Groups

* Security: A security group is the most common type of group and it's used to manage user and device access to shared resources. (creating securitu groups requires MS entra administrator role)
* Microsoft 365: A Microsoft 365 group, which is also often referred to as a distribution group, is used for grouping users according to collaboration needs. (shared mailbox, calender, etc)


***Groups can be configured to allow members to be assigned, that is manually selected, or they can be configured for dynamic membership. Dynamic membership uses rules to automatically add and remove identities.***

#### Describe hybrid identity

Microsoft’s identity solutions span on-premises and cloud-based capabilities. These solutions create a common identity for authentication and authorization to all resources, regardless of location. We call this hybrid identity.

* Inter-directory provisioning is provisioning an identity between two different directory services systems. For a hybrid environment, the most common scenario for inter-directory provisioning is when a user already in Active Directory is provisioned into Microsoft Entra ID.
* Synchronization is responsible for making sure identity information for your on-premises users and groups is matching the cloud

One of the available methods for accomplishing inter-directory provisioning and synchronization is through Microsoft Entra Cloud Sync

The Microsoft Entra Cloud Sync provisioning agent uses the System for Cross-domain Identity Management (SCIM) specification with Microsoft Entra ID to provision and deprovision users and groups.

#### Describe external identities

B2B collaboration
* typically as guest users.

B2B direct connect
* new way to collaborate with other Microsoft Entra organizations using Microsoft Teams shared channels.
* you create two-way trust relationships with other Microsoft Entra organizations to allow users to seamlessly sign in to your shared resources and vice versa.
* users aren't represented in your Microsoft Entra directory (they aren't added as guests), but they're visible from within the Teams shared channel and can be monitored in Teams admin center reports.

Microsoft Entra External ID for customers (preview)
* new customer identity and access management (CIAM) solution.
* This solution is intended for businesses that want to make applications available to their customers using the Microsoft Entra platform for identity and access.
* sso, sign up and sign in pages for apps, branding to sign in pages, self service account management

Microsoft Entra multi-tenant organization
* Multi-tenant organizations use a one-way synchronization service in Microsoft Entra ID, called cross-tenant synchronization. Cross-tenant synchronization enables seamless collaboration for a multi-tenant organization.


### Describe the authentication capabilities of Microsoft Entra ID

Authentication is the process of verifying an identity to be legitimate. Passwords are commonly used to authenticate users, but there are better and more secure ways to authenticate.

#### Describe authentication methods

Passwords are the most common form of authentication, but they have many problems, especially if used in single-factor authentication, where only one form of authentication is used.

![Federation](https://github.com/spawnmarvel/azure-sc-900/blob/main/images/passwords.jpg)

Phone
Microsoft Entra ID supports two options for phone-based authentication.

* SMS-based authentication.
* 


## J.S Youtube

https://www.youtube.com/watch?v=Bz-8jM3jg-8

## Practice Assessment for Exam SC-900: Microsoft Security, Compliance, and Identity Fundamentals

| #  | Sum | Comment
| --- | --- | -------------
| 1   | 74  | No reading
| 2   | 54  | In a hurry
| 3   | 72   | Read a bit
| 4   | x   | 
