# azure-sc-900

## MS Microsoft Certified: Security, Compliance, and Identity Fundamentals


https://learn.microsoft.com/en-us/training/courses/sc-900t00#course-syllabus

## Exam practice

https://learn.microsoft.com/en-us/credentials/certifications/security-compliance-and-identity-fundamentals/?practice-assessment-type=certification

## 1 Describe the concepts of security, compliance, and identity

https://learn.microsoft.com/en-us/training/paths/describe-concepts-of-security-compliance-identity/

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

## 2 Describe the capabilities of Microsoft Entra

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

* SMS-based authentication, The user instead enters their registered mobile phone number, receives a text message with a verification code, and enters that in the sign-in interface.
* Voice call verification, To complete the sign-in process, the user is prompted to press # on their keypad. Voice calls are not supported as a primary form of authentication, in Microsoft Entra ID.

OATH (Open Authentication) is an open standard that specifies how time-based, one-time password (TOTP) codes are generated.

* Software OATH tokens are typically applications. 
* OATH TOTP hardware tokens (supported in public preview) are small hardware devices that look like a key fob that displays a code that refreshes every 30 or 60 seconds. 

Passwordless authentication

* Windows Hello for Business, This two-factor authentication is a combination of a key or certificate tied to a device and something that the person knows (a PIN) or something that the person is (biometrics).
* Fast Identity Online (FIDO) is an open standard for passwordless authentication. FIDO allows users and organizations to leverage the standard to sign in to their resources using an external security key or a platform key built into a device, eliminating the need for a username and password. (With FIDO2 security keys, users can sign in to Microsoft Entra ID or Microsoft Entra hybrid joined Windows 10 devices and get single-sign on to their cloud and on-premises resources. )
* Microsoft Authenticator app
* Certificate-based authentication

Some authentication methods can be used as the primary factor when you sign in to an application or device. Other authentication methods are only available as a secondary factor when you use Microsoft Entra multifactor authentication or SSPR.

#### Describe multifactor authentication

Multifactor authentication is a process in which users are prompted during the sign-in process for an additional form of identification, such as a code on their cellphone or a fingerprint scan.

MFA
* Something you know – typically a password or PIN and
* Something you have – such as a trusted device that's not easily duplicated, like a phone or hardware key or
* Something you are – biometrics like a fingerprint or face scan.

Security defaults and multifactor authentication

* Security defaults are a set of basic identity security mechanisms recommended by Microsoft.
* When enabled, these recommendations are automatically enforced in your organization.


#### Describe self-service password reset


Self-service password reset (SSPR) is a feature of Microsoft Entra ID that allows users to change or reset their password, without administrator or help desk involvement. SSPR has several key benefits for organizations and users.


To use self-service password reset, users must be:

* Assigned a Microsoft Entra ID license. Refer to the Learn More section of the summary and resources unit for a link to the Licensing requirements for Microsoft Entra self-service password reset.
* Enabled for SSPR by an administrator.
* Registered, with the authentication methods they want to use. Two or more authentication methods are recommended in case one is unavailable.

Either with mobile app notification, mobile app code, email, mobile phone, office phone, security question.

#### Describe password protection and management capabilities

* reduces the risk of users setting weak passwords.
* default global banned password lists are automatically applied to all users in a Microsoft Entra tenant. 

Examples of passwords that might be blocked are P@$$w0rd or Passw0rd1 and all variations.

Custom banned password lists

* Brand names
* Product names
* Locations, such as company headquarters
* Company-specific internal terms

Banned password lists are a feature of Microsoft Entra ID P1 or P2 licensing.

Protecting against password spray

Hybrid security, A component installed in the on-premises environment receives the global banned password list and custom password protection policies from Microsoft Entra ID.


### Describe access management capabilities of Microsoft Entra ID

Conditional access and how Microsoft Entra roles and role-based access control (RBAC) helps organizations manage and control access.

#### Describe Conditional Access

* Conditional Access is implemented through policies that are created and managed in Microsoft Entra ID. 
* A Conditional Access policy analyses signals including user, location, device, application, and risk to automate decisions for authorizing access to resources (apps and data).

Assignments

* Users and groups assign who the policy will include or exclude. 
* Cloud apps or actions can include or exclude cloud applications, user actions, or authentication contexts that are subjected to the policy. 
* Conditions define where and when the policy will apply.
* * Sign-in risk and user risk.
* * Devices platform
* * IP location information
* * Client apps
* * Filter for devices

Access controls

* Block access 
* Grant access
* Session, block download, cut, copy etc.


#### Describe Microsoft Entra roles and role-based access control (RBAC)

Managing access using roles is known as role-based access control (RBAC).

Built in

* Global administrator: users with this role have access to all administrative features in Microsoft Entra.
* User administrator: users with this role can create and manage all aspects of users and groups.
* Billing administrator: users with this role make purchases, manage subscriptions and support tickets, and monitor service health.

Custom roles

* Although there are many built-in admin roles in Microsoft Entra, custom roles give flexibility when granting access. A custom role definition is a collection of permissions that you choose from a preset list.

Only grant the access users need

Categories of Microsoft Entra roles


Microsoft Entra ID is an available service if you subscribe to any Microsoft Online business offer, such as Microsoft 365 and Azure.

Available Microsoft 365 services include Microsoft Entra ID, Exchange, SharePoint, Microsoft Defender, Teams, Intune, and many more.

* Microsoft Entra specific roles: These roles grant permissions to manage resources within Microsoft Entra-only. 
* Service-specific roles: For major Microsoft 365 services, Microsoft Entra ID includes built-in, service-specific roles that grant permissions to manage features within the service. (exchange admin, intune admin, sp admin, teams admin)
* Cross-service roles: There are some roles within Microsoft Entra ID that span services. ()

Difference between Microsoft Entra RBAC and Azure RBAC

* Microsoft Entra RBAC - Microsoft Entra roles control access to Microsoft Entra resources such as users, groups, and applications.
* Azure RBAC - Azure roles control access to Azure resources such as virtual machines or storage using Azure Resource Management.



### Describe the identity protection and governance capabilities of Microsoft Entra


Identity governance is about balancing identity security with user productivity in a way that can be justified and audited.

#### Describe Microsoft Entra ID Governance

Microsoft Entra ID Governance allows you to balance your organization's need for security and employee productivity with the right processes and visibility.

ID Governance gives organizations the ability to do the following tasks:

* Govern the identity lifecycle.
* Govern access lifecycle.
* Secure privileged access for administration.

It's intended to help organizations address these four key questions:

* Which users should have access to which resources?
* What are those users doing with that access?
* Are there effective organizational controls for managing access?
* Can auditors verify that the controls are working?

Identity lifecycle

* When planning identity lifecycle management for employees, for example, many organizations model the "join, move, and leave" process.
* Microsoft Entra ID P1 or P2 offers integration with cloud-based HR systems. When a new employee is added to an HR system, Microsoft Entra ID can create a corresponding user account.

Access lifecycle is the process of managing access throughout the user’s organizational life. Users require different levels of access from the point at which they join an organization to when they leave it. 

* Organizations can automate the access lifecycle process through technologies such as dynamic groups. Dynamic groups enable admins to create attribute-based rules to determine membership of groups.

Privileged access lifecycle

* Monitoring privileged access is a key part of identity governance.
* Microsoft Entra Privileged Identity Management (PIM) provides extra controls tailored to securing access rights. 

#### Describe access reviews

Microsoft Entra access reviews enable organizations to efficiently manage group memberships, access to enterprise applications, and role assignment.

There are many use cases in which access reviews should be used, here are just a few examples.

* Too many users in privileged roles:
* Business critical data access
* To maintain a policy's exception list
* Ask group owners to confirm they still need guests in their groups
* Have reviews recur periodically

Manage user and guest user access with access reviews

* With access reviews, you can easily ensure that users or guests have appropriate access.

Multi-stage access reviews

* Microsoft Entra access reviews support up to three review stages, in which multiple types of reviewers engage in determining who still needs access to company resources.

#### Describe entitlement management

Entitlement management is an identity governance feature that enables organizations to manage the identity and access lifecycle at scale.

Entitlement management automates access request workflows, access assignments, reviews, and expiration.

* Users may not know what access they should have, and even if they do, they might have difficulty locating the right individuals to approve it.
* When users find and receive access to a resource, they may hold on to access longer than is required for business purposes.
* Managing access for external users.

Entitlement management includes the following capabilities to address these challenges:

* Delegate the creation of access packages to non-administrators.
* Managing external users.

Microsoft Entra terms of use

* Microsoft Entra terms of use allow information to be presented to users, before they access data or an application. 
* Terms of use ensure users read relevant disclaimers for legal or compliance requirements.

Example use cases where employees or guests may be required to accept terms of use include:

* Before they access sensitive data or an application.
* On a recurring schedule, so they're reminded of regulations.
* Based on user attributes, such as terms applicable to certain roles.
* Presenting terms for all users in your organization.

#### Describe the capabilities of Privileged identity Management

Privileged Identity Management (PIM) is a service of Microsoft Entra ID that enables you to manage, control, and monitor access to important resources in your organization.

PIM is:

* Just in time, providing privileged access only when needed, and not before.
* Time-bound, by assigning start and end dates that indicate when a user can access resources.
* Approval-based, requiring specific approval to activate privileges.
* Visible, sending notifications when privileged roles are activated.
* Auditable, allowing a full access history to be downloaded.

General workflow

These steps are: assign, activate, approve/deny, and extend/renew.

* Assign - The assignment process starts by assigning roles to members.
* Activate - If users have been made eligible for a role, then they must activate the role assignment before using the role.
* Approve or deny - Delegated approvers receive email notifications when a role request is pending their approval.
* Extend and renew - When a role assignment nears expiration, the user can use PIM to request an extension for the role assignment.


Audit

* Privileged Identity Management (PIM) audit history to see all role assignments and activations within the past 30 days for all privileged roles.

#### Describe Microsoft Entra ID Protection

Identity Protection is a tool that allows organizations to accomplish three key tasks:

* Automate the detection and remediation of identity-based risks.
* Investigate risks using data in the portal.
* Export risk detection data to third-party utilities for further analysis.


Detect risks

With Identity Protection, risk can be detected at the user and sign-in level, can be categorized as low, medium, or high, and may be calculated in real-time or offline.

* Anonymous IP address
* Atypical travel
* Unfamiliar sign-in properties
* Microsoft Entra threat intelligence

Here are just a few examples of some of the user risks that Identity Protection in Microsoft Entra ID is able to identify:

* Anomalous user activity
* User reported suspicious activity
* Leaked credentials
* Microsoft Entra threat intelligence

Investigate risks

Identity Protection provides organizations with three reports that they can use to investigate identity risks in their environment. 

These reports are the risky users, risky sign-ins, and risk detections. 


* Risk detections: Each risk detected is reported as a risk detection.
* Risky sign-ins: A risky sign-in is reported when there are one or more risk detections reported for that sign-in.
* Risky users: A Risky user is reported when either or both of the following are true:
* * The user has one or more Risky sign-ins.
* * One or more risk detections have been reported.

![security report](https://github.com/spawnmarvel/azure-sc-900/blob/main/images/securityreport.jpg)

Remediate

After completing an investigation, admins will want to take action to remediate the risk or unblock users. 

Organizations can enable automated remediation using their risk policies.

Export

Data from Identity Protection can be exported to other tools for archive, further investigation, and correlation. 

The Microsoft Graph based APIs allow organizations to collect this data for further processing in tools such as a SIEM. 

The data can also be sent to a Log Analytics workspace, archived data to a storage account, streamed to Event Hubs, or solutions.


Workload identity

* now extending these capabilities to workload identities to protect applications and service principals.

#### Describe Microsoft Entra Permissions Management


Microsoft Entra Permissions Management is a cloud infrastructure entitlement management (CIEM) product that provides comprehensive visibility and control over permissions for any identity and any resource in Microsoft Azure, Amazon Web Services (AWS) and Google Cloud Platform (GCP).


This functionality helps organizations address the Zero Trust principle of least privilege access. 

Some of the key reasons include:

* Organizations are increasingly adopting multicloud strategy
* With the proliferation of identities and cloud services, the number of high-risk cloud permissions is exploding, expanding the attack surface for organizations.
* IT security teams are under increased pressure to ensure access to their expanding cloud estate is secure and compliant.
* The inconsistency of cloud providers' native access management models makes it even more complex for Security and Identity to manage permissions and enforce least privilege access policies across their entire environment.

Permissions Management detects, automatically right-sizes (remediates), and continuously monitors unused and excessive permissions.


Discover

Customers can assess permission risks by evaluating the gap between permissions granted and permissions used.

Remediate

Customers can right-size permissions based on usage, grant new permissions on-demand, and automate just-in-time access for cloud resources.

Monitor

Customers can detect anomalous activities with machine learning-powered (ML-powered) alerts and generate detailed forensic reports.

#### Describe Microsoft Entra Verified ID

Microsoft Entra Verified ID is a managed verifiable credentials service based on open standards. Verified ID automates verification of identity credentials and enables privacy-protected interactions between organizations and users.


Why do we need it?

* ...transactions are increasingly done over the web and often require individuals to make claims or assertions that organizations can digitally verify.
* A digital credential serves as a digital identity. 
* ...it’s hard to retain control of your identity once you've shared it in exchange for access to a service.
* Individuals and businesses need a way to express their qualifications and/or personal information, that is, our digital identities, over the web in a manner that is cryptographically secure, compliant to privacy requirements, and machine readable for verification.

Verifiable credentials help address these challenges.


## 3 Describe the capabilities of Microsoft security solutions

### Describe core infrastructure security services in Azure

https://learn.microsoft.com/en-us/training/paths/describe-capabilities-of-microsoft-security-solutions/


#### Describe Azure DDoS protection

The aim of a Distributed Denial of Service (DDoS) attack is to overwhelm the resources on your applications and servers, making them unresponsive or slow for genuine users.

* Volume attaks
* Protocol attacks
* Resource (application) layer attacks


What is Azure DDoS Protection?

* Analyze traffic = looks like DDoS?
* Layer 3 (network), 4 (transport)
* Always on traffic monitoring
* Adaptive real time tuning, learning the trffic
* DDoS protection telemetry, monitoring and alerting

Two tiers

* DDoS network protection, as sku, DDos mitigation, automatically tuned to help in vnet
* DDoS ip protection, pay per protected ip model. Same as above but differ, does not include DDoS rapid response support, cost protection and disciunt on WAF.

A common question that is often raised is why consider adding DDos Protection services if services running on Azure are inherently protected by the default infrastructure-level DDoS protection? 

* Infrastructure has higher treshold than most apps can handle.
* and does not have telemetry and alerting



#### Describe Azure Firewall

* Any vnet, but best to use on centralized vnet
* Can scale

Key features

* Built in HA and availability zones
* Network and application level filtering
* Outbund SNAT and inbound DNAT
* Multiple public ip addresses
* Threat intelligence
* Integration with Azure monitor

#### Describe Web Application Firewall

Web Application Firewall (WAF) provides centralized protection of your web applications from common exploits and vulnerabilities at application layer.

While Azure DDoS Protection services protect customers against DDoS attacks that can occur at the network and transport layers, Azure WAF protects web applications against application-layer DDoS attacks, such as HTTP Floods.

#### Describe network segmentation in Azure

Segmentation is about dividing something into smaller pieces.

* The ability to group related assets that are a part of (or support) workload operations.
* Isolation of resources.
* Governance policies set by the organization.

Network segmentation also supports the Zero Trust model and a layered approach to security that is part of a defense in depth strategy.


Network segmentation can secure interactions between perimeters.


#### Describe Azure Network Security Groups

Network security groups (NSGs) let you filter network traffic to and from Azure resources in an Azure virtual network; for example, a virtual machine. 

An NSG consists of rules that define how the traffic is filtered. 

You can associate only one network security group to each virtual network subnet and network interface in a virtual machine. 

The same network security group, however, can be associated to as many different subnets and network interfaces as you choose.

Inbound and outbound security rules

* Name
* Prioroty
* Source or destination
* Protocol
* Direction
* Port range
* Action

Some default AllowVnetInBound (65000), AllowAzureLoadBalancerInBound(65001), DenyAllInBound(65500)


***What is the difference between Network Security Groups (NSGs) and Azure Firewall?***

The Azure Firewall service complements network security group functionality. Together, they provide better "defense-in-depth" network security.

NSG = within virtual networks in each subscription
AFW = across different subscriptions and virtual networks.


#### Describe Azure Bastion


Azure Bastion is a service you deploy that lets you connect to a virtual machine using your browser and the Azure portal. The Azure Bastion service is a fully platform-managed PaaS service that you provision inside your virtual network.


Key benefits of Azure Bastion

* RDP / SSH directly in azure portal
* Remote session over tls and fw traversal RDP/SSH
* No public IP
* No hassel managing NSG
* Protect against port scanning
* Hardening in one place to protect against zero-day exploits

Azure Bastion has two available SKUs, Basic and Standard. 


#### Describe Azure Key Vault

* Secrets management.
* Key management. 
* Certificate management



### Describe the security management capabilities in Azure


#### Describe Microsoft Defender for Cloud

Microsoft Defender for Cloud is a cloud-native application protection platform (CNAPP) with a set of security measures and practices designed to protect cloud-based applications from various cyber threats and vulnerabilities. 

* A development security operations (DevSecOps) solution that unifies security management at the code level across multicloud and multiple-pipeline environments.
* A cloud security posture management (CSPM) solution that surfaces actions that you can take to prevent breaches.
* A cloud workload protection platform (CWPP) with specific protections for servers, containers, storage, databases, and other workloads.

DevSecOps. Defender for Cloud helps you to incorporate good security practices early during the software development process, or DevSecOps.

CSPM. The security of your cloud and on-premises resources depends on proper configuration and deployment. Cloud security posture management (CSPM) assesses your systems and automatically alerts security staff in your IT department when a vulnerability is found.

CWPP. Proactive security principles require that you implement security practices that protect your workloads from threats. Cloud workload protections (CWP) surface workload-specific recommendations that lead you to the right security controls to protect your workloads. 


#### Describe how security policies and initiatives improve cloud security posture

Microsoft Defender for Cloud enables organizations to manage the security with It does this by using policy definitions and security initiatives.

* An Azure Policy definition, is a rule about specific security conditions that you want controlled
* A security initiative is a collection of Azure Policy definitions, or rules, grouped together towards a specific goal or purpose. 
* To implement policy definitions or initiatives, you assign them to any scope of resources that are supported, such as management groups, subscriptions, resource groups, or individual resources.

Microsoft Defender for Cloud applies security initiatives to your subscriptions.


***Microsoft cloud security benchmark***

The Microsoft cloud security benchmark (MCSB) is a Microsoft-authored set of guidelines for security and compliance that provides best practices and recommendations to help improve the security of workloads, data, and services on Azure and your multicloud environment. 

Excel sheet

https://github.com/MicrosoftDocs/SecurityBenchmarks/blob/master/Microsoft%20Cloud%20Security%20Benchmark/Microsoft_cloud_security_benchmark_v1.xlsx


![Mcsb](https://github.com/spawnmarvel/azure-sc-900/blob/main/images/mcsb.jpg)

Microsoft cloud security benchmark in Defender for Cloud

Microsoft Defender for Cloud continuously assesses an organization's hybrid cloud environment to analyze the risk factors according to the controls and best practices in the Microsoft cloud security benchmark. 


The regulatory compliance dashboard in Microsoft Defender for Cloud reflects the status of your compliance with the MCSB and any other standards that you've applied to your subscriptions.

![Defender](https://github.com/spawnmarvel/azure-sc-900/blob/main/images/defender.jpg)

Recommendations are the result of assessing your resources against the relevant policies and identifying resources that aren't meeting your defined requirements.

Defender for Cloud periodically analyzes the compliance status of your resources to identify potential security misconfigurations and weaknesses.


***Calculate my cost***

![My Cost](https://github.com/spawnmarvel/azure-sc-900/blob/main/images/mycost.jpg)

#### Describe Cloud security posture management

One of Microsoft Defender for Cloud's main pillars for cloud security is Cloud Security Posture Management (CSPM).

* CSPM provides you with hardening guidance that helps you efficiently and effectively improve your security. 
* CSPM also gives you visibility into your current security situation.
* Secure score
* Hardening recommendations

![CSPM](https://github.com/spawnmarvel/azure-sc-900/blob/main/images/cspm.jpg)


#### Describe the enhanced security of Microsoft Defender for Cloud

A pillar of cloud security is cloud workload protection.

Microsoft Defender for Cloud includes a range of advanced intelligent protections for your workloads.

Defender plans:

* Microsoft Defender for servers
* Microsoft Defender for App Service
* Microsoft Defender for Storage
* etc

Enhanced security features

* Comprehensive endpoint detection and response 
* Vulnerability scanning for virtual machines, container registries, and SQL resources
* Multicloud security
* Hybrid security
* Threat protection alerts
* Track compliance with a range of standards
* Access and application controls

#### Describe DevOps security management

DevOps combines development (Dev) and operations (Ops) to unite people, process, and technology in application planning, development, delivery, and operations. 

Defender for DevOps uses a central console to empower security teams with the ability to protect applications and resources from code to cloud across multi-pipeline environments, such as GitHub and Azure DevOps.

* Unified visibility into DevOps security posture: Security administrators now have full visibility into DevOps inventory and the security posture of preproduction application code.
* Strengthen cloud resource configurations throughout the development lifecycle: You can enable security of Infrastructure as Code (IaC) templates
* Prioritize remediation of critical issues in code: Apply comprehensive code to cloud contextual insights within Defender for Cloud.

### Describe security capabilities of Microsoft Sentinel

Microsoft Sentinel provides a single solution for alert detection, threat visibility, proactive hunting, and threat response.

#### Define the concepts of SIEM and SOAR

Security information event management (SIEM)

* A SIEM system is a tool that an organization uses to collect data from across the whole estate, including infrastructure, software, and resources. It does analysis, looks for correlations or anomalies, and generates alerts and incidents.

security orchestration automated response (SOAR)

* A SOAR system takes alerts from many sources, such as a SIEM system. The SOAR system then triggers action-driven automated workflows and processes to run security tasks that mitigate the issue.


#### Describe threat detection and mitigation capabilities in Microsoft Sentinel

Microsoft Sentinel is a scalable, cloud-native SIEM/SOAR solution that delivers intelligent security analytics and threat intelligence across the enterprise.

It provides a single solution for alert detection, threat visibility, proactive hunting, and threat response.

![Sentinel](https://github.com/spawnmarvel/azure-sc-900/blob/main/images/sentinel.jpg)

* Collect data
* Detect
* Investigate
* Respond

Microsoft Sentinel helps enable end-to-end security operations, in a modern Security Operations Center (SOC). Listed below are some of the key features of Microsoft Sentinel.

* Connect Sentinel to your data
* Workbooks, monitor
* Analytics
* Incident management
* Security automation and orchestration with playbooks
* Investigation
* Hunting (based on the MITRE framework (a global database of adversary tactics and techniques))
* Notebooks
* Community and Content Hub

#### Describe Microsoft Security Copilot

Organizations need to work at machine speed.

Microsoft Security Copilot is the first and only generative AI security product to help defend organizations at machine speed and scale. 

It's an AI-powered security analysis tool that enables analysts to respond to threats quickly, process signals at machine speed, and assess risk exposure in minutes.


### Describe threat protection with Microsoft Defender XDR

Security threat prevention isn't limited to just network security. It also covers applications, email, collaborations, endpoints, cross SaaS solutions, identity, and more.

#### Describe Microsoft Defender XDR (extended detection and response) services

Microsoft Defender XDR is an enterprise defense suite that protects against sophisticated cyberattacks. With Microsoft Defender XDR, you can natively coordinate the detection, prevention, investigation, and response to threats across endpoints, identities, email, and applications.

Microsoft Defender XDR suite protects:

* Endpoints with Microsoft Defender for Endpoint
* Assets with Defender Vulnerability Management
* Email and collaboration with Microsoft Defender for Office 365
* Identities with Microsoft Defender for Identity
* Applications with Microsoft Defender for Cloud Apps


#### Describe Microsoft Defender for Office 365

Microsoft Defender for Office 365 is a seamless integration into your Office 365 subscription that provides protection against threats, like phishing and malware that arrive in email links (URLs), attachments, or collaboration tools like SharePoint, Teams, and Outlook.

Microsoft Defender for Office 365 safeguards organizations against malicious threats by providing admins and security operations (sec ops) teams a wide range of capabilities.

* Preset security policies: Preset security policies allow you to apply protection features to users based on Microsoft recommended settings.
* Threat protection policies: Define threat protection policies to set the appropriate level of protection for your organization.
* Reports
* Threat investigation and response capabilities: Use leading-edge tools to investigate, understand, simulate, and prevent threats.
* Automated investigation and response capabilities


#### Describe Microsoft Defender for Endpoint


Microsoft Defender for Endpoint is a platform designed to help enterprise networks protect 

* endpoints including laptops, phones, tablets, PCs, access points, routers, and firewalls. 

It does so by preventing, detecting, investigating, and responding to advanced threats.


#### Describe Microsoft Defender for Cloud Apps

Software as a service (SaaS) apps are ubiquitous across hybrid work environments. Protecting SaaS apps and the important data they store is a significant challenge for organizations. 

Microsoft Defender for Cloud Apps delivers full protection for SaaS applications

* Fundamental cloud access security broker (CASB) functionality. A CASB acts as a gatekeeper to broker real-time access between your enterprise users and the cloud resources they use.
* SaaS Security Posture Management (SSPM) features, enabling security teams to improve the organization’s security posture
* Advanced threat protection, as part of Microsoft's extended detection and response (XDR) solution, enabling powerful correlation of signal and visibility across the full kill chain of advanced attacks
* App-to-app protection, extending the core threat scenarios to OAuth-enabled apps that have permissions and privileges to critical data and resources.


Information protection

Defender for Cloud Apps connects to SaaS apps to scan for files containing sensitive data uncovering which data is stored where and who is accessing it.

* Apply a sensitivity label
* Block downloads to an unmanaged device
* Remove external collaborators on confidential files

SaaS Security Posture Management (SSPM)

Defender for Cloud Apps automatically provides SSPM data in Microsoft Secure Score, for any supported and connected app.

#### Describe Microsoft Defender for Identity

Microsoft Defender for Identity is a cloud-based security solution. It uses your on-premises Active Directory data (called signals) to identify, detect, and investigate advanced threats, compromised identities, and malicious insider actions directed at your organization.

* Monitor users, entity behavior, and activities with learning-based analytics.
* Protect user identities and credentials stored in Active Directory
* Identify and investigate suspicious activities and advanced attacks across the * cyberattack kill-chain.
* Provide clear incident information on a simple timeline for fast triage


#### Describe Microsoft Defender Vulnerability Management

Defender Vulnerability Management delivers asset visibility, intelligent assessments, and built-in remediation tools for Windows, macOS, Linux, Android, iOS, and network devices.

* Continuous asset discovery and monitoring
* Risk-based intelligent prioritization.
* * focuses on emerging threats to align the prioritization of security recommendations with vulnerabilities currently being exploited in the wild and emerging threats that pose the highest risk.
* Remediation and tracking
* Dashboard insights


#### Describe Microsoft Defender Threat Intelligence

Microsoft Defender Threat Intelligence (Defender TI) helps 

* Streamline security analyst triage
* Incident response
* Threat hunting 
* Vulnerability management workflows. 
* Defender TI aggregates and enriches critical threat information in an easy-to-use interface.
* From TI home page analysts can quickly scan new featured articles and begin their intelligence gathering, triage, incident response, and hunting efforts by performing a keyword, artifact or Common Vulnerabilities
* and Exposure ID (CVE-ID) search.

Defender TI articles

* Articles are narratives by Microsoft that provide insight into threat actors, tooling, attacks, and vulnerabilities. 
* they also link to actionable content and key indicators of compromise to help users take action.

Vulnerability articles

* Defender TI offers CVE-ID searches to help users identify critical information about the CVE. 
* CVE-ID searches result in Vulnerability Articles.

Data sets

* Microsoft centralizes numerous data sets into a single platform, Defender TI.
* Making it easier for Microsoft’s community and customers to conduct infrastructure analysis. 
* Microsoft’s primary focus is to provide as much data as possible about Internet infrastructure to support a variety of security use cases.

This internet data is categorized into two distinct groups

* Traditional data sets include Resolutions, WHOIS, SSL Certificates, Subdomains, DNS, Reverse DNS, and Services.
* Advanced data sets include Trackers, Components, Host Pairs, and Cookies. Trackers, Components, Host Pairs, and Cookies data sets are collected from observing the Document Object Model (DOM) of web pages crawled.


#### Describe the Microsoft Defender portal

The Microsoft Defender portal combines protection, detection, investigation, and response to devices, identities, endpoints, email & collaboration, and cloud apps, in a central place.

* The Microsoft Defender portal home page shows many of the common cards that security teams need.
* Microsoft Defender portal uses role-based access control
*  Customization is specific to the individual admin, so other admins won’t see these changes.
* The left navigation pane provides security professionals easy access to the suite of Microsoft Defender XDR services, including Defender for Identity, Defender for Office 365, Defender for Endpoints, and Defender for Cloud Apps, which were described in the previous units. 
* Incidents and alerts
* Hunting, You can build custom detection rules and hunt for specific threats in your environment. 


Threat Intelligence

* Threat Analytics, Threat analytics is our in-product threat intelligence solution from expert Microsoft security researchers.
* Intel Profiles, Intel profiles is a new feature that introduces curated content organized by threat actors, their tools and known vulnerabilities
* Intel Explorer - Through Intel Explorer you access the existing Defender Threat Intelligence content described in the previous unit.

## 4 Microsoft Security, Compliance, and Identity Fundamentals: Describe the capabilities of Microsoft compliance solutions


### Describe Microsoft’s Service Trust portal and privacy capabilities

The Microsoft Service Trust Portal provides a variety of content, tools, and other resources about Microsoft security, privacy, and compliance practices.

Describe the offerings of the Service Trust portal

The Service Trust Portal (STP) is Microsoft's public site for publishing audit reports and other compliance-related information associated with Microsoft’s cloud services.

https://servicetrust.microsoft.com/

Service Trust Portal Content Categories

* Certifications, Regulations, and Standards
* * ... information with the goal of making it easier for you to meet regulatory compliance objectives by understanding how Microsoft Cloud services keep your data secure.
* Reports, Whitepapers, and Artifacts
* * ... BCP and DR - Business Continuity and Disaster Recovery, Pen Test and Security Assessments, privacy, data protection, faq and whitepapers.
* Industry and Regional Resources
* * Financial services, health and life science, media, USA government, regional.
* Resources for your Organization
* * This section lists documents applying to your organization (restricted by tenant) based on your organization’s subscription and permissions.


#### Describe Microsoft's privacy principles


Microsoft's approach to privacy is built on the following six principles:

* Control, Your data is your business.
* Transparency, We only process your data based on your agreement and in accordance with the strict policies and procedures that we've contractually agreed to.
* Security, Microsoft protects your data both at rest and in transit.
* Strong legal protections, Respecting local privacy laws and fighting for legal protection of privacy as a fundamental human right.
* No content-based targeting, Not using email, chat, files, or other personal content to target advertising.
* Benefits to you, Troubleshooting, Feature improvement, Personalized customer experience.


#### Describe Microsoft Priva

... privacy by default

Priva's capabilities are available through two solutions: 
 
Priva Privacy Risk Management
* which provides visibility into your organization's data and policy templates for reducing risks.
* understand the data your organization stores by automating discovery of personal data assets and providing visualizations of essential information.
* These visualizations can be found on the overview and data profile pages, currently accessible through the Microsoft Purview compliance portal.

![Purview](https://github.com/spawnmarvel/azure-sc-900/blob/main/images/purview.jpg)

The overview dashboard provides an overall view into your organization’s data in Microsoft 365. Privacy administrators can monitor trends and activities, identify and investigate potential risks involving personal data, and springboard into key activities like policy management or subject rights request actions.

Priva Subject Rights Requests

* which provides automation and workflow tools for fulfilling data requests.
* In accordance with certain privacy regulations around the world, individuals (or data subjects) may make requests to review or manage the personal data about themselves that companies have collected.
* These requests are sometimes also referred to as data subject requests (DSRs), data subject access requests (DSARs), or consumer rights requests. 
* For companies that store large amounts of information, finding the relevant data can be a formidable task.


#### Describe the compliance management capabilities in Microsoft Purview

The Microsoft Purview compliance portal is the portal for organizations to manage their compliance needs using integrated solutions for information protection, data lifecycle management, insider risk management, auditing, and more.

The Microsoft Purview compliance portal brings together all of the tools and data that are needed to help understand and manage an organization’s compliance needs.

The compliance portal is available to customers with a Microsoft 365 SKU with one of the following roles:

* Global administrator
* Compliance administrator
* Compliance data administrator

The Compliance Manager card. This card leads you to the Microsoft Purview Compliance Manager solution. Compliance Manager helps simplify the way you manage compliance. 

It calculates a risk-based compliance score that measures progress toward completing recommended actions to reduce risks associated with data protection and regulatory standards. 

The Active alerts card includes a summary of the most active alerts and a link where admins can view more detailed information, such as alert severity, status, category, and more.

Navigation

* Compliance Manager
* Data Classification

#### Describe Compliance Manager

Compliance Manager helps simplify compliance and reduce risk by providing:

* Prebuilt assessments based on common regional and industry regulations and standards. Admins can also use custom assessment to help with compliance needs unique to the organization.
* Workflow capabilities that enable admins to efficiently complete risk assessments for the organization.
* Step-by-step improvement actions that admins can take to help meet regulations and standards relevant to the organization.
* Compliance score

Controls

A control is a requirement of a regulation, standard, or policy.

Compliance Manager tracks the following types of controls:

* Microsoft-managed controls: controls for Microsoft cloud services, which Microsoft is responsible for implementing.
* Your controls: sometimes referred to as customer-managed controls, these are implemented and managed by the organization.
* Shared controls: responsibility for implementing these controls is shared by the organization and Microsoft.

Assessments

An assessment is a grouping of controls from a specific regulation, standard, or policy.

Templates

Compliance Manager provides templates to help admins to quickly create assessments. 

Improvement actions

Improvement actions help centralize compliance activities. Each improvement action provides recommended guidance that's intended to help organizations to align with data protection regulations and standards. 

Benefits of Compliance Manager
Compliance Manager provides many benefits, including:

* Translating complicated regulations, standards, company policies, or other control frameworks into a simple language.
* Providing access to a large variety of out-of-the-box assessments and custom assessments to help organizations with their unique compliance needs.
* Mapping regulatory controls against recommended improvement actions.
* Providing step-by-step guidance on how to implement the solutions to meet regulatory requirements.
* Helping admins and users to prioritize actions that will have the highest impact on their organizational compliance by associating a score with each action.


#### Describe use and benefits of compliance score

Compliance score measures progress in completing recommended improvement actions within controls.

What is the difference between Compliance Manager and compliance score?

Compliance Manager is an end-to-end solution in the Microsoft Purview compliance portal to enable admins to manage and track compliance activities. 

Compliance score is a calculation of the overall compliance posture across the organization. 

The compliance score is available through Compliance Manager.

### Describe information protection, data lifecycle management, and data governance capabilities in Microsoft Purview

Microsoft Purview is a comprehensive set of solutions that help you govern, protect, and manage your entire data estate, providing unified data governance and risk management for your organization.


Organizations need to find, classify, and protect all types of information, including financial and personal data. This must be done to ensure customers, employees, and the organization are protected from risks, while still being able to find and access the data they need.

#### Know your data, protect your data, and govern your data

* Microsoft Purview, It provides the tools to know your data, protect your data, and prevent data loss.
* It gives organizations the capabilities to govern their data, for compliance or regulatory requirements.

* Know your data, Capabilities and tools such as trainable classifiers, activity explorer, and content explorer allow organizations to know their data.
* Protect your data, encryption, access restrictions, and visual markings.
* Prevent data loss, detect risky behavior and prevent accidental oversharing of sensitive information.
* Govern your data, automatically keep, delete, and store data and records in a compliant manner.

#### Describe the data classification capabilities of the compliance portal

![Data classification](https://github.com/spawnmarvel/azure-sc-900/blob/main/images/data_classification.jpg)


Microsoft Purview provides three ways of identifying items so that they can be classified:

* manually by users
* automated pattern recognition, like sensitive information types
* machine learning


Sensitive information types

* Sensitive information types (SIT) are pattern-based classifiers.
* example, 123-456-789-ABC

Microsoft Purview includes many built-in sensitive information types based on patterns that are defined by a regular expression (regex) or a function.

Examples include:

* Credit card numbers
* Passport or identification numbers
* Bank account numbers
* Health service numbers
* Microsoft Purview also supports the ability to create custom sensitive information types


Trainable classifiers

* Trainable classifiers use artificial intelligence and machine learning to intelligently classify your data. 
* They're most useful classifying data unique to an organization like specific kinds of contracts, invoices, or customer records.

Pre-trained classifiers - Microsoft has created and pretrained many classifiers that you can start using without training them

Custom trainable classifiers - Microsoft supports the ability to create and train custom classifiers. 

Understand and explore the data

Data classification can involve large numbers of documents and emails.

... the overview section of the data classification pane in compliance portal provides many details at a glance, including:

* The number of items classified as sensitive information and which classifications they are.
* Details on the locations of data based on sensitivity.
* Summary of actions that users are taking on sensitive content across the organization.

What is the content explorer?

*  It enables administrators to gain visibility into the content that has been summarized in the overview pane.


What is the activity explorer?

* Activity explorer provides visibility into what content has been discovered and labeled, and where that content is. It makes it possible to monitor what's being done with labeled content across the organization.

Example

* File copied to removable media
* File copied to network share
* Label applied
* Label changed


#### Describe sensitivity labels and policies


Admins can enable their organization to protect its data, through capabilities and tools such as sensitivity labels and policies in Microsoft Purview.

Sensitivity labels

* Customizable: Admins can create different categories specific to the organization, such as Personal, Public, Confidential, and Highly Confidential.
* Clear text: Because each label is stored in clear text in the content's metadata, third-party apps and services can read it and then apply their own protective actions, if necessary.
* Persistent. After you apply a sensitivity label to content, the label is stored in the metadata of that email or document. The label then moves with the content, including the protection settings, and this data becomes the basis for applying and enforcing policies.

Each item that supports sensitivity labels can only have one label applied to it, at any given time.

Sensitivity labels can be configured to:

* Encrypt email only or both email and documents.
* Mark the content when Office apps are used.
* Apply the label automatically in Office apps or recommend a label. 
* Protect content in containers such as sites and groups. 
* Extend sensitivity labels to third-party apps and services. 
* Classify content without using any protection settings.

A classification can be assigned to content (just like a sticker) that persists and roams with the content as it's used and shared. The classification can be used to generate usage reports and view activity data for sensitive content.


Label policies

After sensitivity labels are created, they need to be published to make them available to people and services in the organization. Sensitivity labels are published to users or groups through label policies

*  Choose the users and groups that can see labels.
* Apply a default label to all new emails and documents that the specified users and groups create. 
* Require justifications for label changes. If a user wants to remove a label or replace it, admins can require the user to provide a valid justification to complete the action.
* Require users to apply a label (mandatory labeling).
* Link users to custom help pages.


#### Describe data loss prevention


In Microsoft Purview, you implement data loss prevention by defining and applying DLP policies. With a DLP policy, you can identify, monitor, and automatically protect sensitive items across:

* 365 (Teams, Exchange, SP, Onedrive)
* Word, Excel, PP
* Win 10, 11 and macos
* Cloud apps
* On premise fs and SP
* Power BI

Protective actions of DLP policies

DLP policies are how you monitor the activities that users take on sensitive items at rest, sensitive items in transit, or sensitive items in use and take protective actions.

Protective actions that DLP policies can take include:

* Pop up warnings
* Block sharing, via policy
* Data at rest, sensitive items can be locked and moved to secure location/ quarantine
* For Teams chat, the sensitive information won't be displayed.

All DLP monitored activities are recorded to the Microsoft 365 Audit log by default and routed to Activity explorer.


DLP Policy information

DLP policies can be created from predefined templates, or you can create a custom policy. No matter which you choose, all DLP policies require the same information.

* Type of data, scope, location, conditions, protective action


What is endpoint data loss prevention?

Endpoint DLP enables you to audit and manage the many activities users take on sensitive items that are physically stored Windows 10, Windows 11, or macOS devices. 

* Create, rename, copy, print, access an item


Data loss prevention in Microsoft Teams

... administrators can use DLP policy tips that will be displayed to the user to show them why a policy has been triggered.


#### Describe retention policies and retention labels

Retention labels and policies help organizations to manage and govern information by ensuring content is kept only for a required time, and then permanently deleted.

Use a retention policy to assign the same retention settings for content at a site or mailbox level, and use a retention label to assign retention settings at an item level (folder, document, email).

For example, if all documents in a SharePoint site should be retained for 5 years, it's more efficient to do this with a retention policy than apply the same retention label to all documents in that site.

* Apply a single policy to multiple locations, or to specific locations or users.

Retention labels, Use retention labels for different types of content that require different retention settings.

* Tax forms that need to be retained for a minimum period of time.
* Press materials that need to be permanently deleted when they reach a specific age.


#### Describe records management

Organizations of all types require a management solution to manage regulatory, legal, and business-critical records across their corporate data. Microsoft Purview Records Management helps an organization look after their legal obligations.


* Labeling content as a record.
* Establishing retention and deletion policies within the record label.
* Triggering event-based retention.
* Reviewing and validating disposition.
* Proof of records deletion.
* Exporting information about disposed items.

When content is labeled as a record, the following happens:

* Restrictions are put in place to block certain activities.
* Activities are logged.
* Proof of disposition is kept at the end of the retention period.

To enable items to be marked as records, an administrator sets up retention labels.

Common use cases for records management

* Enabling administrators and users to manually apply retention and deletion actions for documents and emails.
* 

#### Describe the Microsoft Purview unified data governance solution

... address the challenges associated with the rapid growth of data and to help enterprises get the most value from their information assets.

The Microsoft Purview governance portal provides a unified data governance service that helps you manage your on-premises, multicloud, and software-as-a-service (SaaS) data. 

* Create a holistic, up-to-date map of your data landscape with automated data discovery, sensitive data classification, and end-to-end data lineage.
* Enable data curators to manage and secure your data estate.
* Empower data consumers to find valuable, trustworthy data.


### Describe the insider risk capabilities in Microsoft Purview

#### Describe insider risk management

Learn how Microsoft Purview enables organizations to identify, analyze, and remediate internal risks before they cause harm.

...  minimizing risk in an organization 

* Leaks of sensitive data and data spillage
* Confidentiality violations
* Intellectual property (IP) theft
* Fraud
* Insider trading

Insider risk management workflow

* Policies - Insider risk management policies are created using predefined templates and policy conditions that define what risk indicators are examined in Microsoft 365 feature areas.
* Alerts - Alerts are automatically generated by risk indicators that match policy conditions and are displayed in the Alerts dashboard. 
* Triage - New activities that need investigation automatically generate alerts that are assigned a Needs review status.
* Investigate - Cases are created for alerts that require deeper review and investigation of the details and circumstances around the policy match.
* Action - After cases are investigated, reviewers can quickly act to resolve the case or collaborate with other risk stakeholders in the organization.

#### Describe communication compliance

... is an insider risk solution that helps you detect, capture, and act on inappropriate messages that can lead to potential data security or compliance incidents within your organization.

* Communication compliance evaluates text and image-based messages in Microsoft and third-party apps (Teams, Viva Engage, Outlook, WhatsApp, etc.)
* for potential business policy violations including inappropriate sharing of sensitive information, threatening or harassing language as well as potential regulatory violations.

Workflow

* Configure
* Investigate
* Investigate
* Monitor 


### Describe the eDiscovery and Audit capabilities in Microsoft Purview

Organizations may need to identify, collect, and/or audit information for legal, regulatory, or business reasons. With today's volume and variety of data, it’s vital that an organization can do this in an efficient and timely manner.

Learn how the eDiscovery and audit capabilities of Microsoft Purview help organizations find relevant data quickly.


#### Describe the eDiscovery solutions in Microsoft Purview

Electronic discovery, or eDiscovery, is the process of identifying and delivering electronic information that can be used as evidence in legal cases.

eDiscovery tools in Microsoft Purview to search for content in Exchange Online, OneDrive for Business, SharePoint Online, Microsoft Teams, Microsoft 365 Groups, and Yammer teams.

* Content Search
* eDiscovery (Standard). The eDiscovery (Standard) solution builds on the basic search and export functionality of Content search by enabling you to create eDiscovery cases and assign eDiscovery managers to specific cases.
* eDiscovery (Premium). The eDiscovery (Premium) solution builds on the existing capabilities in eDiscovery (Standard). In addition, eDiscovery (Premium) provides an end-to-end workflow to identify, preserve, collect, review, analyze, and export content that's responsive to your organization's internal and external investigations.


#### Describe the audit solutions in Microsoft Purview

Auditing solutions in Microsoft Purview help organizations effectively respond to security events, forensic investigations, internal investigations, and compliance obligations

Thousands of user and admin operations performed in dozens of Microsoft 365 services and solutions are captured, recorded, and retained in your organization's unified audit log.

Microsoft Purview provides two auditing solutions: Audit (Standard) and Audit (Premium).


![Audit](https://github.com/spawnmarvel/azure-sc-900/blob/main/images/audit.jpg)




![Done](https://github.com/spawnmarvel/azure-sc-900/blob/main/images/done.jpg)




## Practice Assessment for Exam SC-900: Microsoft Security, Compliance, and Identity Fundamentals 80 % or more

| #  | Sum | Comment
| --- | --- | -------------
| 1   | 74  | No reading
| 2   | 54  | In a hurry
| 3   | 72  | Read a bit, a bit course
| 4   | 60  | Read a bit 2, a bit course
| 5   | 70  | Tired
| 6   | 80  | Cool, getting there.
| 7   |     | 



## J.S Youtube

https://www.youtube.com/watch?v=Bz-8jM3jg-8

## Repeat the readme.md




