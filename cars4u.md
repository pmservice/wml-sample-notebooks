<?xml version="1.0" encoding="UTF-8"?>
<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:ns1="http://schemas.xmlsoap.org/encoding/" targetNamespace="http://schemas.xmlsoap.org/encoding/" elementFormDefault="qualified" attributeFormDefault="unqualified">
  <xs:annotation>
    <xs:documentation>pwd</xs:documentation>
  </xs:annotation>
  <xs:complexType name="HostEntry">
    <xs:annotation>
      <xs:documentation>This is the data needed to attempt a connection to a specific host.</xs:documentation>
    </xs:annotation>
    <xs:sequence>
      <xs:element name="HostEntry" maxOccurs="unbounded">
        <xs:annotation>
          <xs:documentation>A HostEntry comprises the data needed to identify and connect to a specific host.</xs:documentation>
        </xs:annotation>
        <xs:complexType>
          <xs:sequence>
            <xs:element name="HostName">
              <xs:annotation>
                <xs:documentation>Can be an alias used to refer to the host or an  FQDN or IP address.  If an FQDN or IP address is used, a HostAddress is not required.</xs:documentation>
              </xs:annotation>
            </xs:element>
            <xs:element name="HostAddress" minOccurs="0">
              <xs:annotation>
                <xs:documentation>Can be a FQDN or IP address.</xs:documentation>
              </xs:annotation>
            </xs:element>
            <xs:element name="UserGroup" minOccurs="0">
              <xs:annotation>
                <xs:documentation>The tunnel group to use when connecting to the specified host.  This field is used in conjunction with the HostAddress value to form a Group based URL.  NOTE: Group based URL support requires ASA version 8.0.3 or later.</xs:documentation>
              </xs:annotation>
            </xs:element>
            <xs:element name="BackupServerList" type="ns1:BackupServerList" minOccurs="0">
              <xs:annotation>
                <xs:documentation>Collection of one or more backup servers to be used in case the user selected one fails.</xs:documentation>
              </xs:annotation>
            </xs:element>
            <xs:element name="LoadBalancingServerList" type="ns1:LoadBalancingServerList" minOccurs="0">
              <xs:annotation>
                <xs:documentation>Collection of one or more load balancing servers.</xs:documentation>
              </xs:annotation>
            </xs:element>
            <xs:element name="AutomaticSCEPHost" type="xs:string" minOccurs="0" />
            <xs:element name="CAURL" type="ns1:CAURL" minOccurs="0" />
            <xs:element name="MobileHostEntryInfo" minOccurs="0" maxOccurs="1">
              <xs:complexType>
                <xs:sequence>
                  <xs:element name="NetworkRoaming" type="ns1:simpleBinary" default="true" minOccurs="0" maxOccurs="1">
                    <xs:annotation>
                      <xs:documentation>Controls whether the client will reconnect across network transitions.</xs:documentation>
                    </xs:annotation>
                  </xs:element>
                  <xs:element name="CertificatePolicy" type="ns1:CertificatePolicyRule" default="Auto" minOccurs="0" maxOccurs="1">
                    <xs:annotation>
                      <xs:documentation>
                                  When Auto is specified, AnyConnect will enumerate all the certificates on the client against the CertificateMatch rules in the profile.
                                  If Manual is specified, AnyConnect will try to find a certificate to associate with the connection by applying the CertificateMatch rules.
                                  </xs:documentation>
                    </xs:annotation>
                  </xs:element>
                  <xs:element name="ConnectOnDemand" type="ns1:simpleBinary" default="false" minOccurs="0" maxOccurs="1">
                    <xs:annotation>
                      <xs:documentation>Initiates a VPN connection when accessing domains in the domain list.</xs:documentation>
                    </xs:annotation>
                  </xs:element>
                  <xs:element name="AlwaysConnectDomainList" minOccurs="0" maxOccurs="1">
                    <xs:complexType>
                      <xs:sequence>
                        <xs:element name="OnDemandDNSMatch" type="xs:string" minOccurs="0" maxOccurs="unbounded">
                          <xs:annotation>
                            <xs:documentation>Attempt to initiate a VPN connection when rules in this list are matched.</xs:documentation>
                          </xs:annotation>
                        </xs:element>
                      </xs:sequence>
                    </xs:complexType>
                  </xs:element>
                  <xs:element name="NeverConnectDomainList" minOccurs="0" maxOccurs="1">
                    <xs:complexType>
                      <xs:sequence>
                        <xs:element name="OnDemandDNSMatch" type="xs:string" minOccurs="0" maxOccurs="unbounded">
                          <xs:annotation>
                            <xs:documentation>Never attempt to initiate a VPN connection when rules in this list are matched.</xs:documentation>
                          </xs:annotation>
                        </xs:element>
                      </xs:sequence>
                    </xs:complexType>
                  </xs:element>
                  <xs:element name="ConnectIfNeededDomainList" minOccurs="0" maxOccurs="1">
                    <xs:complexType>
                      <xs:sequence>
                        <xs:element name="OnDemandDNSMatch" type="xs:string" minOccurs="0" maxOccurs="unbounded">
                          <xs:annotation>
                            <xs:documentation>Attempt to initiate a VPN connection when rules in this list are matched only if the system could not resolve the address using DNS.</xs:documentation>
                          </xs:annotation>
                        </xs:element>
                      </xs:sequence>
                    </xs:complexType>
                  </xs:element>
                  <xs:element name="ActivateOnImport" type="ns1:simpleBinary" default="false" minOccurs="0" maxOccurs="1">
                    <xs:annotation>
                      <xs:documentation>If defined true this will become the active connection when the import is completed. This may result in the user being disconnected on Apple IOS platforms when a profile is imported.</xs:documentation>
                    </xs:annotation>
                  </xs:element>
                </xs:sequence>
              </xs:complexType>
            </xs:element>
            <xs:element name="PrimaryProtocol" default="SSL" minOccurs="0">
              <xs:annotation>
                <xs:documentation>This setting specifies the protocol that the client will first use when attempting to connect to the gateway.</xs:documentation>
              </xs:annotation>
              <xs:complexType mixed="true">
                <xs:all>
                  <xs:element name="StandardAuthenticationOnly" default="false" minOccurs="0">
                    <xs:annotation>
                      <xs:documentation>This setting denotes IOS gateways that support only standards-based authentication methods.</xs:documentation>
                    </xs:annotation>
                    <xs:complexType mixed="true">
                      <xs:all>
                        <xs:element name="AuthMethodDuringIKENegotiation" type="ns1:AuthMethodValues" default="EAP-GTC" minOccurs="0">
                          <xs:annotation>
                            <xs:documentation>This specifies the specific authentication method that the client will use during IKE negotiations.</xs:documentation>
                          </xs:annotation>
                        </xs:element>
                        <xs:element name="IKEIdentity" type="xs:string" minOccurs="0">
                          <xs:annotation>
                            <xs:documentation>This specifies the IKE identity, used as the IKE IDi payload.</xs:documentation>
                          </xs:annotation>
                        </xs:element>
                      </xs:all>
                    </xs:complexType>
                  </xs:element>
                </xs:all>
              </xs:complexType>
            </xs:element>
            <xs:element name="CertificatePinList" minOccurs="0">
              <xs:annotation>
                <xs:documentation>Pinned certificates to be used for verification by AnyConnect for server certificate chain.</xs:documentation>
              </xs:annotation>
              <xs:complexType>
                <xs:sequence>
                  <xs:element name="Pin" maxOccurs="unbounded" minOccurs="0">
                    <xs:complexType>
                      <xs:simpleContent>
                        <xs:annotation>
                          <xs:documentation>Pinned certificate SHA-512 hash of the public key. Info attribute has the Subject field value of pinned certificate by default.</xs:documentation>
                        </xs:annotation>
                        <xs:extension base="xs:string">
                          <xs:attribute type="xs:string" name="Subject"/>
                          <xs:attribute type="xs:string" name="Issuer"/>
                        </xs:extension>
                      </xs:simpleContent>
                    </xs:complexType>
                  </xs:element>
                </xs:sequence>
              </xs:complexType>
            </xs:element>
          </xs:sequence>
        </xs:complexType>
      </xs:element>
    </xs:sequence>
  </xs:complexType>
  <xs:complexType name="AnyConnectClientProfile">
    <xs:annotation>
      <xs:documentation>This is the XML schema definition for the Cisco AnyConnect VPN Client Profile XML file.  The VPN Client Initialization is a repository of information used to manage the Cisco VPN client software.  This file is intended to be maintained by a Secure Gateway administrator and then distributed with the client software.  The xml file based on this schema can be distributed to clients at any time.  The distribution mechanisms supported are as a bundled file with the software distribution or as part of the automatic download mechanism.  The automatic download mechanism only available with certain Cisco Secure Gateway products.</xs:documentation>
    </xs:annotation>
    <xs:sequence>
      <xs:element name="ClientInitialization" minOccurs="0">
        <xs:annotation>
          <xs:documentation>The ClientInitialization section represents global settings for the client.  In some cases (e.g. BackupServerList) host specific overrides are possible.</xs:documentation>
        </xs:annotation>
        <xs:complexType>
          <xs:all>
            <xs:element name="UseStartBeforeLogon" default="false" minOccurs="0">
              <xs:annotation>
                <xs:documentation>The Start Before Logon feature can be used to activate the VPN as part of the logon sequence.</xs:documentation>
              </xs:annotation>
              <xs:complexType>
                <xs:simpleContent>
                  <xs:extension base="ns1:simpleBinary">
                    <xs:attribute name="UserControllable" type="ns1:UserControllableValues" default="true">
                      <xs:annotation>
                        <xs:documentation>Does the administrator of this profile allow the user to control this attribute for their own use.  Any user setting associated with this attribute will be stored elsewhere.</xs:documentation>
                      </xs:annotation>
                    </xs:attribute>
                  </xs:extension>
                </xs:simpleContent>
              </xs:complexType>
            </xs:element>
            <xs:element name="AutomaticCertSelection" default="true" minOccurs="0">
              <xs:annotation>
                <xs:documentation>Controls AnyConnect client behavior for certificate selection. By default, the user certificate will be matched internally. If disabled, a user certificate selection dialog will be displayed.</xs:documentation>
              </xs:annotation>
              <xs:complexType>
                <xs:simpleContent>
                  <xs:extension base="ns1:simpleBinary">
                    <xs:attribute name="UserControllable" type="ns1:UserControllableValues" default="true">
                      <xs:annotation>
                        <xs:documentation>Does the administrator of this profile allow the user to control this attribute for their own use.  Any user setting associated with this attribute will be stored elsewhere.</xs:documentation>
                      </xs:annotation>
                    </xs:attribute>
                  </xs:extension>
                </xs:simpleContent>
              </xs:complexType>
            </xs:element>
            <xs:element name="ShowPreConnectMessage" default="false" minOccurs="0">
              <xs:annotation>
                <xs:documentation>
                  This control enables an administrator to have a one time message displayed prior to a users first connection attempt.  As an example, the message could be used to remind a user to insert their smart card into it's reader.

                  The message to be used with this control is localizable and can be found in the AnyConnect message catalog (default: "This is a pre-connect reminder message.").
                </xs:documentation>
              </xs:annotation>
              <xs:simpleType>
                <xs:restriction base="xs:string">
                  <xs:enumeration value="true">
                    <xs:annotation>
                      <xs:documentation>Show a pre-connect message prior to users first connect attempt.</xs:documentation>
                    </xs:annotation>
                  </xs:enumeration>
                  <xs:enumeration value="false">
                    <xs:annotation>
                      <xs:documentation>Do not show a pre-connect message prior to users first connect attempt.</xs:documentation>
                    </xs:annotation>
                  </xs:enumeration>
                </xs:restriction>
              </xs:simpleType>
            </xs:element>
            <xs:element name="CertificateStore" type="ns1:CertificateStores" default="All" minOccurs="0">
              <xs:annotation>
                <xs:documentation>
                    This setting allows an administrator to specify which certificate store AnyConnect will use for locating certificates.
                    This setting only applies to the Microsoft Windows version of AnyConnect and has no effect on other platforms.
                </xs:documentation>
              </xs:annotation>
            </xs:element>
              <xs:element name="CertificateStoreMac" type="ns1:CertificateStoresMac" default="All" minOccurs="0">
                <xs:annotation>
                  <xs:documentation>
                      This setting allows an administrator to specify which certificate store AnyConnect will use for locating certificates.
                      This setting only applies to the macOS version of AnyConnect and has no effect on other platforms.
                  </xs:documentation>
                </xs:annotation>
              </xs:element>
              <xs:element name="CertificateStoreOverride" type="ns1:simpleBinary" default="false" minOccurs="0">
              <xs:annotation>
                <xs:documentation>This setting allows an administrator to direct AnyConnect to search for certificates in the Windows machine certificate store.  This is useful in cases where certificates are located in this store and users do not have administrator privileges on their machine.</xs:documentation>
              </xs:annotation>
            </xs:element>
            <xs:element name="ProxySettings" default="Native" minOccurs="0">
              <xs:annotation>
                <xs:documentation>This setting allows an administrator to control the user proxy settings.</xs:documentation>
              </xs:annotation>
              <xs:complexType mixed="true">
                <xs:sequence>
                  <xs:element name="PublicProxyServerAddress" default="" minOccurs="0" maxOccurs="1">
                    <xs:annotation>
                      <xs:documentation>This attribute provides the public proxy address and port number. Can be a FQDN or IP address.</xs:documentation>
                    </xs:annotation>
                    <xs:complexType>
                      <xs:simpleContent>
                        <xs:extension base="xs:string">
                          <xs:attribute name="UserControllable" type="ns1:UserControllableValues" default="true">
                            <xs:annotation>
                              <xs:documentation>Does the administrator of this profile allow the user to control this attribute for their own use.  Any user setting associated with this attribute will be stored elsewhere.</xs:documentation>
                            </xs:annotation>
                          </xs:attribute>
                        </xs:extension>
                      </xs:simpleContent>
                    </xs:complexType>
                  </xs:element>
                </xs:sequence>
                <xs:attribute name="UserControllable" type="ns1:UserControllableValues" default="true">
                  <xs:annotation>
                    <xs:documentation>Does the administrator of this profile allow the user to control this attribute for their own use.  Any user setting associated with this attribute will be stored elsewhere.</xs:documentation>
                  </xs:annotation>
                </xs:attribute>
              </xs:complexType>
            </xs:element>
            <xs:element name="AllowLocalProxyConnections" type="ns1:simpleBinary" default="true" minOccurs="0">
              <xs:annotation>
                <xs:documentation>This preference gives the network administrator the ability to allow users to connect through a local proxy.</xs:documentation>
              </xs:annotation>
            </xs:element>
            <xs:element name="AutoConnectOnStart" default="false" minOccurs="0">
              <xs:annotation>
                <xs:documentation>Controls AnyConnect client behavior when started.  By default, the client will attempt to contact the last Gateway a user connected to or the first one in the list from the AnyConnect profile.  In the case of certificate-only authentication, this will result in the establishment of a VPN tunnel when the client is started.</xs:documentation>
              </xs:annotation>
              <xs:complexType>
                <xs:simpleContent>
                  <xs:extension base="ns1:simpleBinary">
                    <xs:attribute name="UserControllable" type="ns1:UserControllableValues" default="true">
                      <xs:annotation>
                        <xs:documentation>Does the administrator of this profile allow the user to control this attribute for their own use.  Any user setting associated with this attribute will be stored elsewhere.</xs:documentation>
                      </xs:annotation>
                    </xs:attribute>
                  </xs:extension>
                </xs:simpleContent>
              </xs:complexType>
            </xs:element>
            <xs:element name="MinimizeOnConnect" default="true" minOccurs="0">
              <xs:annotation>
                <xs:documentation>Controls AnyConnect GUI behavior when a VPN tunnel is established.  By default, the GUI will minimize when the VPN tunnel is established.</xs:documentation>
              </xs:annotation>
              <xs:complexType>
                <xs:simpleContent>
                  <xs:extension base="ns1:simpleBinary">
                    <xs:attribute name="UserControllable" type="ns1:UserControllableValues" default="true">
                      <xs:annotation>
                        <xs:documentation>Does the administrator of this profile allow the user to control this attribute for their own use.  Any user setting associated with this attribute will be stored elsewhere.</xs:documentation>
                      </xs:annotation>
                    </xs:attribute>
                  </xs:extension>
                </xs:simpleContent>
              </xs:complexType>
            </xs:element>
            <xs:element name="LocalLanAccess" default="false" minOccurs="0">
              <xs:annotation>
                <xs:documentation>If Local LAN access is enabled for remote clients on the Secure Gateway, this setting can be used to allow the user to accept or reject this access.</xs:documentation>
              </xs:annotation>
              <xs:complexType>
                <xs:simpleContent>
                  <xs:extension base="ns1:simpleBinary">
                    <xs:attribute name="UserControllable" type="ns1:UserControllableValues" default="true">
                      <xs:annotation>
                        <xs:documentation>Does the administrator of this profile allow the user to control this attribute for their own use.  Any user setting associated with this attribute will be stored elsewhere.</xs:documentation>
                      </xs:annotation>
                    </xs:attribute>
                  </xs:extension>
                </xs:simpleContent>
              </xs:complexType>
            </xs:element>
            <xs:element name="DisableCaptivePortalDetection" default="false" minOccurs="0">
              <xs:annotation>
                <xs:documentation>If Disable captive portal is enabled for remote clients on the Secure Gateway, this setting can be used to allow the user to enable or disable captive portal detection.</xs:documentation>
              </xs:annotation>
              <xs:complexType>
                <xs:simpleContent>
                  <xs:extension base="ns1:simpleBinary">
                    <xs:attribute name="UserControllable" type="ns1:UserControllableValues" default="true">
                      <xs:annotation>
                        <xs:documentation>Does the administrator of this profile allow the user to control this attribute for their own use.  Any user setting associated with this attribute will be stored elsewhere.</xs:documentation>
                      </xs:annotation>
                    </xs:attribute>
                  </xs:extension>
                </xs:simpleContent>
              </xs:complexType>
            </xs:element>
            <xs:element name="AutoReconnect" default="true" minOccurs="0">
              <xs:annotation>
                <xs:documentation>This setting allows an administrator to control how a client will behave when the VPN tunnel is interrupted.  Control can optionally be given to the user.</xs:documentation>
              </xs:annotation>
              <xs:complexType mixed="true">
                <xs:sequence>
                  <xs:element name="AutoReconnectBehavior" default="DisconnectOnSuspend" minOccurs="0">
                    <xs:complexType>
                      <xs:simpleContent>
                        <xs:extension base="ns1:AutoConnectValues">
                          <xs:attribute name="UserControllable" type="ns1:UserControllableValues" default="false">
                            <xs:annotation>
                              <xs:documentation>Does the administrator of this profile allow the user to control this attribute for their own use.  Any user setting associated with this attribute will be stored elsewhere.</xs:documentation>
                            </xs:annotation>
                          </xs:attribute>
                        </xs:extension>
                      </xs:simpleContent>
                    </xs:complexType>
                  </xs:element>
                </xs:sequence>
                <xs:attribute name="UserControllable" type="ns1:UserControllableValues" default="false">
                  <xs:annotation>
                    <xs:documentation>Does the administrator of this profile allow the user to control this attribute for their own use.  Any user setting associated with this attribute will be stored elsewhere.</xs:documentation>
                  </xs:annotation>
                </xs:attribute>
              </xs:complexType>
            </xs:element>
            <xs:element name="AutoUpdate" default="true" minOccurs="0">
              <xs:annotation>
                <xs:documentation>This setting allows the adminstrator to turn off the dynamic update functionality of AnyConnect.  Control of this can also be given to the user.</xs:documentation>
              </xs:annotation>
              <xs:complexType>
                <xs:simpleContent>
                  <xs:extension base="ns1:simpleBinary">
                    <xs:attribute name="UserControllable" type="ns1:UserControllableValues" default="false">
                      <xs:annotation>
                        <xs:documentation>Does the administrator of this profile allow the user to control this attribute for their own use.  Any user setting associated with this attribute will be stored elsewhere.</xs:documentation>
                      </xs:annotation>
                    </xs:attribute>
                  </xs:extension>
                </xs:simpleContent>
              </xs:complexType>
            </xs:element>
            <xs:element name="RSASecurIDIntegration" default="Automatic" minOccurs="0">
              <xs:annotation>
                <xs:documentation>This setting allows the adminstrator to control how the user will interact with RSA.  By default, AnyConnect will determine the correct method of RSA interaction.  The desired setting can be locked down by the administrator or control can be given to the user.</xs:documentation>
              </xs:annotation>
              <xs:complexType>
                <xs:simpleContent>
                  <xs:extension base="ns1:RSAIntegrationValues">
                    <xs:attribute name="UserControllable" type="ns1:UserControllableValues" default="false">
                      <xs:annotation>
                        <xs:documentation>Does the administrator of this profile allow the user to control this attribute for their own use.  Any user setting associated with this attribute will be stored elsewhere.</xs:documentation>
                      </xs:annotation>
                    </xs:attribute>
                  </xs:extension>
                </xs:simpleContent>
              </xs:complexType>
            </xs:element>
            <xs:element name="WindowsLogonEnforcement" default="SingleLocalLogon" minOccurs="0">
              <xs:annotation>
                <xs:documentation>This preference allows an administrator to control if more than one user may be logged into the client PC during the VPN connection (Windows only).</xs:documentation>
              </xs:annotation>
              <xs:complexType>
                <xs:simpleContent>
                  <xs:extension base="ns1:WindowsLogonEnforcementValues" />
                </xs:simpleContent>
              </xs:complexType>
            </xs:element>
            <xs:element name="WindowsVPNEstablishment" default="LocalUsersOnly" minOccurs="0">
              <xs:annotation>
                <xs:documentation>This preference allows an administrator to control whether or not remote users may initiate a VPN connection (Windows only).</xs:documentation>
              </xs:annotation>
              <xs:complexType>
                <xs:simpleContent>
                  <xs:extension base="ns1:WindowsVPNEstablishmentValues" />
                </xs:simpleContent>
              </xs:complexType>
            </xs:element>
            <xs:element name="RetainVpnOnLogoff" default="false" minOccurs="0">
              <xs:annotation>
                <xs:documentation>Determines whether to keep the VPN session when the user logs off a Windows OS or macOS.</xs:documentation>
              </xs:annotation>
              <xs:complexType mixed="true">
                <xs:sequence>
                  <xs:element name="UserEnforcement" default="SameUserOnly" type="ns1:UserEnforcementValues" minOccurs="0">
                    <xs:annotation>
                      <xs:documentation>Specifies whether to end the VPN session if a different user logs on. This value applies only if the RetainVpnOnLogoff is True and the original user logged off Windows or macOS when the VPN session was up.</xs:documentation>
                    </xs:annotation>
                  </xs:element>
                </xs:sequence>
              </xs:complexType>
            </xs:element>
            <xs:element name="AutomaticVPNPolicy" default="false" minOccurs="0">
              <xs:annotation>
                <xs:documentation>This preference allows the administrator to define a policy to automatically manage when a VPN connection should be started or stopped.</xs:documentation>
              </xs:annotation>
              <xs:complexType mixed="true">
                <xs:all>
                  <xs:element name="TrustedDNSDomains" default="" type="xs:string" minOccurs="0">
                    <xs:annotation>
                      <xs:documentation>This setting defines the list of possible DNS domain name(s) that an interface is assigned when in a trusted network</xs:documentation>
                    </xs:annotation>
                  </xs:element>
                  <xs:element name="TrustedDNSServers" default="" type="xs:string" minOccurs="0">
                    <xs:annotation>
                      <xs:documentation>This setting defines the list of DNS server(s) that an interface is assigned when in a trusted network</xs:documentation>
                    </xs:annotation>
                  </xs:element>
                  <xs:element name="TrustedHttpsServerList" minOccurs="0">
                    <xs:annotation>
                      <xs:documentation>This setting defines the list of HTTPS servers reachable only via a trusted network.</xs:documentation>
                    </xs:annotation>
                    <xs:complexType>
                      <xs:sequence>
                        <xs:element name="TrustedHttpsServer" maxOccurs="unbounded" minOccurs="0">
                          <xs:complexType>
                            <xs:sequence>
                              <xs:element type="xs:string" name="Address"/>
                              <xs:element type="xs:string" name="Port"/>
                              <xs:element type="xs:string" name="CertificateHash"/>
                            </xs:sequence>
                          </xs:complexType>
                        </xs:element>
                      </xs:sequence>
                    </xs:complexType>
                  </xs:element>
                  <xs:element name="TrustedNetworkPolicy" default="Disconnect" type="ns1:TrustedNetworkPolicyValues" minOccurs="0">
                    <xs:annotation>
                      <xs:documentation>This preference allows an administrator to define a policy to automatically manage the VPN connection for users in trusted networks.</xs:documentation>
                    </xs:annotation>
                  </xs:element>
                  <xs:element name="UntrustedNetworkPolicy" default="Connect" type="ns1:UntrustedNetworkPolicyValues" minOccurs="0">
                    <xs:annotation>
                      <xs:documentation>This preference allows an administrator to define a policy to automatically manage the VPN connection for users in untrusted networks.</xs:documentation>
                    </xs:annotation>
                  </xs:element>
                  <xs:element name="AlwaysOn" default="false" minOccurs="0">
                    <xs:annotation>
                      <xs:documentation>This preference governs VPN reestablishment after interruptions</xs:documentation>
                    </xs:annotation>
                    <xs:complexType mixed="true">
                      <xs:all>
                        <xs:element name="ConnectFailurePolicy" default="Closed" minOccurs="0">
                          <xs:annotation>
                            <xs:documentation>This preference gives the network administrator the ability to dictate the network access allowed by the client endpoint device following a VPN connection establishment failure. Possible values are Open and Closed</xs:documentation>
                          </xs:annotation>
                          <xs:complexType mixed="true">
                            <xs:all>
                              <xs:element name="AllowCaptivePortalRemediation" default="false" minOccurs="0">
                                <xs:annotation>
                                  <xs:documentation>This preference gives the network administrator the ability to dictate the network access allowed by the client endpoint device following a VPN connection establishment failure</xs:documentation>
                                </xs:annotation>
                                <xs:complexType mixed="true">
                                  <xs:all>
                                    <xs:element name="CaptivePortalRemediationTimeout" default="5" type="ns1:CaptivePortalRemediationTimeoutValues" minOccurs="0">
                                      <xs:annotation>
                                        <xs:documentation>This preference allows the network administrator the ability to impose a time limit (in minutes) for captive portal remediation when the ConnectFailurePolicy value is Closed</xs:documentation>
                                      </xs:annotation>
                                    </xs:element>
                                  </xs:all>
                                </xs:complexType>
                              </xs:element>
                              <xs:element name="ApplyLastVPNLocalResourceRules" type="ns1:simpleBinary" default="false" minOccurs="0">
                                <xs:annotation>
                                  <xs:documentation>This preference gives the network administrator the ability to allow split routes and firewall rules to be applied following a VPN connection establishment failure when the ConnectFailurePolicy value is Closed</xs:documentation>
                                </xs:annotation>
                              </xs:element>
                            </xs:all>
                          </xs:complexType>
                        </xs:element>
                        <xs:element name="AllowVPNDisconnect" type="ns1:simpleBinary" default="true" minOccurs="0">
                          <xs:annotation>
                            <xs:documentation>This preference gives the network administrator the ability to allow users to disconnect the VPN session during Always On</xs:documentation>
                          </xs:annotation>
                        </xs:element>
                      </xs:all>
                    </xs:complexType>
                  </xs:element>
                </xs:all>
              </xs:complexType>
            </xs:element>
            <xs:element name="PPPExclusion" default="Automatic" minOccurs="0">
              <xs:annotation>
                <xs:documentation>This preference allows an administrator to control the policy used to exclude routes to PPP servers when connecting over L2TP or PPTP. Options are Automatic (default), Disable, and Override.</xs:documentation>
              </xs:annotation>
              <xs:complexType mixed="true">
                <xs:sequence>
                  <xs:element name="PPPExclusionServerIP" default="" minOccurs="0">
                    <xs:annotation>
                      <xs:documentation>When PPPExclusion is set to Override, the value of this preference allows an end user to specify the address of a PPP server that should be excluded from tunnel traffic.</xs:documentation>
                    </xs:annotation>
                    <xs:complexType>
                      <xs:simpleContent>
                        <xs:extension base="xs:string">
                          <xs:attribute name="UserControllable" type="ns1:UserControllableValues" default="false">
                            <xs:annotation>
                              <xs:documentation>Does the administrator of this profile allow the user to control this attribute for their own use.  Any user setting associated with this attribute will be stored elsewhere.</xs:documentation>
                            </xs:annotation>
                          </xs:attribute>
                        </xs:extension>
                      </xs:simpleContent>
                    </xs:complexType>
                  </xs:element>
                </xs:sequence>
                <xs:attribute name="UserControllable" type="ns1:UserControllableValues" default="false">
                  <xs:annotation>
                    <xs:documentation>Does the administrator of this profile allow the user to control this attribute for their own use.  Any user setting associated with this attribute will be stored elsewhere.</xs:documentation>
                  </xs:annotation>
                </xs:attribute>
              </xs:complexType>
            </xs:element>
            <xs:element minOccurs="0" default="false" name="EnableScripting">
              <xs:annotation>
                <xs:documentation>This preference allows an administrator to enable scripting which executes OnConnect and OnDisconnect scripts (if found).</xs:documentation>
              </xs:annotation>
              <xs:complexType mixed="true">
                <xs:sequence>
                  <xs:element minOccurs="0" default="false" name="TerminateScriptOnNextEvent">
                    <xs:annotation>
                      <xs:documentation>This setting dictates whether or not AnyConnect will terminate a running script process if a transition to another scriptable event occurs.</xs:documentation>
                    </xs:annotation>
                    <xs:complexType>
                      <xs:simpleContent>
                        <xs:extension base="ns1:simpleBinary" />
                      </xs:simpleContent>
                    </xs:complexType>
                  </xs:element>
                  <xs:element minOccurs="0" default="true" name="EnablePostSBLOnConnectScript">
                    <xs:annotation>
                      <xs:documentation>This setting dictates whether or not the OnConnect script will be launched from the desktop GUI when a tunnel has been established via Start Before Logon.</xs:documentation>
                    </xs:annotation>
                    <xs:complexType>
                      <xs:simpleContent>
                        <xs:extension base="ns1:simpleBinary" />
                      </xs:simpleContent>
                    </xs:complexType>
                  </xs:element>
                </xs:sequence>
                <xs:attribute default="false" name="UserControllable" type="ns1:UserControllableValues">
                  <xs:annotation>
                    <xs:documentation>Does the administrator of this profile allow the user to control this attribute for their own use.  Any user setting associated with this attribute will be stored elsewhere.</xs:documentation>
                  </xs:annotation>
                </xs:attribute>
              </xs:complexType>
            </xs:element>
            <xs:element name="CertificatePinning" default="false" minOccurs="0">
              <xs:annotation>
                <xs:documentation>The setting dictates whether or not AnyConnect should perform certificate pinning checks for server certificate chain.</xs:documentation>
              </xs:annotation>
              <xs:complexType mixed="true">
                <xs:sequence>
                  <xs:element name="CertificatePinList" minOccurs="0">
                    <xs:annotation>
                      <xs:documentation>Pinned certificates to be used for verification by AnyConnect for server certificate chain.</xs:documentation>
                    </xs:annotation>
                    <xs:complexType>
                      <xs:sequence>
                        <xs:element name="Pin" maxOccurs="unbounded" minOccurs="0">
                          <xs:annotation>
                            <xs:documentation>Pinned certificate SHA-512 hash of the public key. Info attribute has the Subject field value of pinned certificate by default.</xs:documentation>
                          </xs:annotation>
                          <xs:complexType>
                            <xs:simpleContent>
                              <xs:extension base="xs:string">
                                <xs:attribute type="xs:string" name="Subject"/>
                                <xs:attribute type="xs:string" name="Issuer"/>
                              </xs:extension>
                            </xs:simpleContent>
                          </xs:complexType>
                        </xs:element>
                      </xs:sequence>
                    </xs:complexType>
                  </xs:element>
                </xs:sequence>
              </xs:complexType>
            </xs:element>
            <xs:element name="CertificateMatch" minOccurs="0">
              <xs:annotation>
                <xs:documentation>This section enables the definition of various attributes that can be used to refine client certificate selection.</xs:documentation>
              </xs:annotation>
              <xs:complexType>
                <xs:sequence>
                  <xs:element name="MatchOnlyCertsWithEKU" type="xs:string" minOccurs="0">
                    <xs:annotation>
                      <xs:documentation>This section disables certificate with no EKU from matching.</xs:documentation>
                    </xs:annotation>
                  </xs:element>
                  <xs:element name="MatchOnlyCertsWithKU" type="xs:string" minOccurs="0">
                    <xs:annotation>
                      <xs:documentation>This section disables certificate with no KU from matching.</xs:documentation>
                    </xs:annotation>
                  </xs:element>
                  <xs:element name="KeyUsage" type="ns1:KeyUsage" minOccurs="0">
                    <xs:annotation>
                      <xs:documentation>Certificate Key attributes that can be used for choosing acceptable client certificates.</xs:documentation>
                    </xs:annotation>
                  </xs:element>
                  <xs:element name="ExtendedKeyUsage" type="ns1:ExtendedKeyUsage" minOccurs="0">
                    <xs:annotation>
                      <xs:documentation>Certificate Extended Key attributes that can be used for choosing acceptable client certificates.</xs:documentation>
                    </xs:annotation>
                  </xs:element>
                  <xs:element name="DistinguishedName" type="ns1:DistinguishedName" minOccurs="0">
                    <xs:annotation>
                      <xs:documentation>Certificate Distinguished Name matching allows for exact match criteria in the choosing of acceptable client certificates.</xs:documentation>
                    </xs:annotation>
                  </xs:element>
                </xs:sequence>
              </xs:complexType>
            </xs:element>
            <xs:element name="BackupServerList" type="ns1:BackupServerList" minOccurs="0">
              <xs:annotation>
                <xs:documentation>Collection of one or more backup servers to be used in case the user selected one fails.</xs:documentation>
              </xs:annotation>
            </xs:element>
            <xs:element name="MobilePolicy" minOccurs="0">
              <xs:annotation>
                <xs:documentation>Collection of policy settings specific to the Windows Mobile version of AnyConnect that have no effect on other platforms.</xs:documentation>
              </xs:annotation>
              <xs:complexType>
                <xs:sequence>
                  <xs:element name="DeviceLockRequired" minOccurs="0">
                    <xs:annotation>
                      <xs:documentation>Indicates that a Windows Mobile device must be configured with a password or PIN prior to establishing a VPN connection.  This configuration is only valid on Windows Mobile devices that use the Microsoft Default Local ation Provider (LAP).</xs:documentation>
                    </xs:annotation>
                    <xs:complexType>
                      <xs:attribute name="MaximumTimeoutMinutes" type="xs:unsignedInt">
                        <xs:annotation>
                          <xs:documentation>When set to non-negative number, specifies the maximum number of minutes that must be configured before device lock takes effect.  (WM5/WM5AKU2+)  </xs:documentation>
                        </xs:annotation>
                      </xs:attribute>
                      <xs:attribute name="MinimumPasswordLength" type="xs:unsignedInt">
                        <xs:annotation>
                          <xs:documentation>When set to a non-negative number,  specifies that any PIN/password used for device lock must be equal to or longer than the specified value, in characters. (WM5AKU2+)</xs:documentation>
                        </xs:annotation>
                      </xs:attribute>
                      <xs:attribute name="PasswordComplexity" type="ns1:PasswordComplexityValues">
                        <xs:annotation>
                          <xs:documentation>When present checks for the following password subtypes:  "alpha"  - Requires an alphanumeric password,  "pin"    - Numeric PIN required, "strong" - Strong alphanumeric password defined by Microsoft as containing at least 7 characters, including a minimum of 3 from the set of uppercase, lowercase,  numerals, and punctuation characters. (WM5AKU2+)</xs:documentation>
                        </xs:annotation>
                      </xs:attribute>
                    </xs:complexType>
                  </xs:element>
                </xs:sequence>
              </xs:complexType>
            </xs:element>
            <xs:element name="CertificateEnrollment" minOccurs="0">
              <xs:annotation>
                <xs:documentation>This section enables the definition of various .</xs:documentation>
              </xs:annotation>
              <xs:complexType>
                <xs:sequence>
                  <xs:element name="CertificateExpirationThreshold" type="xs:unsignedInt" minOccurs="0">
                    <xs:annotation>
                      <xs:documentation>This attribute will enable a notice to be shown to the user when their certificate is about to expire.</xs:documentation>
                    </xs:annotation>
                  </xs:element>
                  <xs:element name="AutomaticSCEPHost" type="xs:string" minOccurs="0">
                    <xs:annotation>
                      <xs:documentation>If the group-url can be identified (FQDN/group or IP/group) by this value will trigger the automatic SCEP process.</xs:documentation>
                    </xs:annotation>
                  </xs:element>
                  <xs:element name="CAURL" type="ns1:CAURL" minOccurs="0">
                    <xs:annotation>
                      <xs:documentation>The SCEP CA server.</xs:documentation>
                    </xs:annotation>
                  </xs:element>
                  <xs:element name="CertificateImportStore" type="ns1:CertificateStores" default="All" minOccurs="0">
                    <xs:annotation>
                      <xs:documentation>
                                                This setting allows an administrator to specify which certificate store AnyConnect will use for locating certificates.
                                                This setting only applies to the Microsoft Windows version of AnyConnect and has no effect on other platforms.
                                            </xs:documentation>
                    </xs:annotation>
                  </xs:element>
                  <xs:element name="CertificateSCEP" minOccurs="0">
                    <xs:complexType>
                      <xs:sequence>
                        <xs:element name="CADomain" type="xs:string" minOccurs="0">
                          <xs:annotation>
                            <xs:documentation>Domain of the CA</xs:documentation>
                          </xs:annotation>
                        </xs:element>
                        <xs:element name="Name_CN" type="xs:string" minOccurs="0">
                          <xs:annotation>
                            <xs:documentation>Common Name</xs:documentation>
                          </xs:annotation>
                        </xs:element>
                        <xs:element name="Department_OU" type="xs:string" minOccurs="0">
                          <xs:annotation>
                            <xs:documentation>Org Unit</xs:documentation>
                          </xs:annotation>
                        </xs:element>
                        <xs:element name="Company_O" type="xs:string" minOccurs="0">
                          <xs:annotation>
                            <xs:documentation>Org</xs:documentation>
                          </xs:annotation>
                        </xs:element>
                        <xs:element name="State_ST" type="xs:string" minOccurs="0">
                          <xs:annotation>
                            <xs:documentation>State</xs:documentation>
                          </xs:annotation>
                        </xs:element>
                        <xs:element name="State_SP" type="xs:string" minOccurs="0">
                          <xs:annotation>
                            <xs:documentation>State</xs:documentation>
                          </xs:annotation>
                        </xs:element>
                        <xs:element name="Country_C" type="xs:string" minOccurs="0">
                          <xs:annotation>
                            <xs:documentation>Country</xs:documentation>
                          </xs:annotation>
                        </xs:element>
                        <xs:element name="Email_EA" type="xs:string" minOccurs="0">
                          <xs:annotation>
                            <xs:documentation>Email</xs:documentation>
                          </xs:annotation>
                        </xs:element>
                        <xs:element name="Domain_DC" type="xs:string" minOccurs="0" maxOccurs="10">
                          <xs:annotation>
                            <xs:documentation>Domain Component</xs:documentation>
                          </xs:annotation>
                        </xs:element>
                        <xs:element name="SurName_SN" type="xs:string" minOccurs="0">
                          <xs:annotation>
                            <xs:documentation>Sur Name</xs:documentation>
                          </xs:annotation>
                        </xs:element>
                        <xs:element name="GivenName_GN" type="xs:string" minOccurs="0">
                          <xs:annotation>
                            <xs:documentation>Given Name</xs:documentation>
                          </xs:annotation>
                        </xs:element>
                        <xs:element name="UnstructName_N" type="xs:string" minOccurs="0">
                          <xs:annotation>
                            <xs:documentation>Unstructured Name</xs:documentation>
                          </xs:annotation>
                        </xs:element>
                        <xs:element name="Initials_I" type="xs:string" minOccurs="0">
                          <xs:annotation>
                            <xs:documentation>Initials</xs:documentation>
                          </xs:annotation>
                        </xs:element>
                        <xs:element name="Qualifier_GEN" type="xs:string" minOccurs="0">
                          <xs:annotation>
                            <xs:documentation>Gen Qualifier</xs:documentation>
                          </xs:annotation>
                        </xs:element>
                        <xs:element name="Qualifier_DN" type="xs:string" minOccurs="0">
                          <xs:annotation>
                            <xs:documentation>DN Qualifier</xs:documentation>
                          </xs:annotation>
                        </xs:element>
                        <xs:element name="City_L" type="xs:string" minOccurs="0">
                          <xs:annotation>
                            <xs:documentation>City</xs:documentation>
                          </xs:annotation>
                        </xs:element>
                        <xs:element name="Title_T" type="xs:string" minOccurs="0">
                          <xs:annotation>
                            <xs:documentation>Title</xs:documentation>
                          </xs:annotation>
                        </xs:element>
                        <xs:element name="KeySize" type="xs:unsignedInt" minOccurs="0">
                          <xs:annotation>
                            <xs:documentation>Key Size</xs:documentation>
                          </xs:annotation>
                        </xs:element>
                        <xs:element name="DisplayGetCertButton" type="ns1:simpleBinary" minOccurs="0">
                          <xs:annotation>
                            <xs:documentation>Turn on display of Get Certificate button if SCEP is configured and user encounters client certificate authentication failure.</xs:documentation>
                          </xs:annotation>
                        </xs:element>
                      </xs:sequence>
                    </xs:complexType>
                  </xs:element>
                </xs:sequence>
              </xs:complexType>
            </xs:element>
            <xs:element name="DeviceLockRequired" minOccurs="0">
              <xs:complexType mixed="true">
                <xs:sequence>
                  <xs:element name="DeviceLockMaximumTimeoutMinutes" type="xs:unsignedInt" minOccurs="0">
                    <xs:annotation>
                      <xs:documentation>When set to non-negative number, specifies the maximum number of minutes that must be configured before device lock takes effect.  (WM5/WM5AKU2+)  </xs:documentation>
                    </xs:annotation>
                  </xs:element>
                  <xs:element name="DeviceLockMinimumPasswordLength" type="xs:unsignedInt" minOccurs="0">
                    <xs:annotation>
                      <xs:documentation>When set to a non-negative number,  specifies that any PIN/password used for device lock must be equal to or longer than the specified value, in characters. (WM5AKU2+)</xs:documentation>
                    </xs:annotation>
                  </xs:element>
                  <xs:element name="DeviceLockPasswordComplexity" type="ns1:PasswordComplexityValues" minOccurs="0">
                    <xs:annotation>
                      <xs:documentation>When present checks for the following password subtypes:  "alpha"  - Requires an alphanumeic password,  "pin"    - Numeric PIN required, "strong" - Strong alphanumeric password defined by Microsoft as containing at least 7 characters, including a minimum of 3 from the set of uppercase, lowercase,  numerals, and punctuation characters. (WM5AKU2+)</xs:documentation>
                    </xs:annotation>
                  </xs:element>
                </xs:sequence>
              </xs:complexType>
            </xs:element>
            <xs:element name="EnableAutomaticServerSelection" default="false" minOccurs="0">
              <xs:annotation>
                <xs:documentation>Automatic server selection will automatically select the optimal secure gateway for the endpoint. Possible values are true or false.
                                </xs:documentation>
              </xs:annotation>
              <xs:complexType mixed="true">
                <xs:sequence>
                  <xs:element name="AutoServerSelectionImprovement" default="20" type="ns1:AutoServerSelectionImprovement" minOccurs="0">
                    <xs:annotation>
                      <xs:documentation>During a reconnection attempt after a system resume, this setting specifies the minimum  estimated performance improvement required to justify transitioning a user to a new server. This value represents a percentage in 0..100</xs:documentation>
                    </xs:annotation>
                  </xs:element>
                  <xs:element name="AutoServerSelectionSuspendTime" default="4" type="ns1:AutoServerSelectionSuspendTime" minOccurs="0">
                    <xs:annotation>
                      <xs:documentation>During a reconnection attempt after a system resume, this specifies the minimum time a user must have been suspended in order to justify a new server selection calculation. It is measured in hours</xs:documentation>
                    </xs:annotation>
                  </xs:element>
                </xs:sequence>
                <xs:attribute name="UserControllable" type="ns1:UserControllableValues" default="true">
                  <xs:annotation>
                    <xs:documentation>Does the administrator of this profile allow the user to control this attribute for their own use.  Any user setting associated with this attribute will be stored elsewhere.</xs:documentation>
                  </xs:annotation>
                </xs:attribute>
              </xs:complexType>
            </xs:element>
            <xs:element name="AuthenticationTimeout" default="12" type="ns1:AuthenticationTimeoutValues" minOccurs="0">
              <xs:annotation>
                <xs:documentation>Amount of time, in seconds, that the client waits for authentication to be completed.</xs:documentation>
              </xs:annotation>
            </xs:element>
            <xs:element name="SafeWordSofTokenIntegration" default="false" minOccurs="0">
              <xs:annotation>
                <xs:documentation>If SafeWord SofToken software is installed on the endpoint device, this setting can be used to enable the client to directly interface with the SofToken software.</xs:documentation>
              </xs:annotation>
              <xs:complexType>
                <xs:simpleContent>
                  <xs:extension base="ns1:simpleBinary">
                    <xs:attribute name="UserControllable" type="ns1:UserControllableValues" default="false">
                      <xs:annotation>
                        <xs:documentation>Does the administrator of this profile allow the user to control this attribute for their own use.  Any user setting associated with this attribute will be stored elsewhere.</xs:documentation>
                      </xs:annotation>
                    </xs:attribute>
                  </xs:extension>
                </xs:simpleContent>
              </xs:complexType>
            </xs:element>
            <xs:element name="AllowIPsecOverSSL" default="false" type="ns1:simpleBinary" minOccurs="0">
              <xs:annotation>
                <xs:documentation>AllowIPsecOverSSL is an unsupported and unadvertised preference that makes IPsec tunnels possible over SSL tunnels. It must not be visible in the Profile Editor.</xs:documentation>
              </xs:annotation>
            </xs:element>
            <xs:element name="ClearSmartcardPin" default="true" minOccurs="0">
              <xs:annotation>
                <xs:documentation>This preference controls whether the smartcard pin will be cleared on a successful connection
                                  This setting only applies to the Microsoft Windows version of AnyConnect and has no effect on other platforms.</xs:documentation>
              </xs:annotation>
              <xs:complexType>
                <xs:simpleContent>
                  <xs:extension base="ns1:simpleBinary">
                    <xs:attribute name="UserControllable" type="ns1:UserControllableValues" default="true">
                      <xs:annotation>
                        <xs:documentation>Does the administrator of this profile allow the user to control this attribute for their own use.  Any user setting associated with this attribute will be stored elsewhere.</xs:documentation>
                      </xs:annotation>
                    </xs:attribute>
                  </xs:extension>
                </xs:simpleContent>
              </xs:complexType>
            </xs:element>
            <xs:element name="ServiceDisable" type="ns1:simpleBinary" default="false" minOccurs="0">
              <xs:annotation>
                <xs:documentation>This attribute will indicate that the VPN service should not be used on the endpoint.</xs:documentation>
              </xs:annotation>
            </xs:element>
            <xs:element name="IPProtocolSupport" type="ns1:IPProtocolSupportValues" default="IPv4,IPv6" minOccurs="0">
              <xs:annotation>
                <xs:documentation>This attribute will indicate the supported IP protocols (IPv4 and IPv6) and in what order they should be used to attempt a VPN connection.</xs:documentation>
              </xs:annotation>
            </xs:element>
            <xs:element name="AllowManualHostInput" type="ns1:simpleBinary" default="true" minOccurs="0">
              <xs:annotation>
                <xs:documentation>This attribute will indicate whether the end-user may manually specify a new headend.</xs:documentation>
              </xs:annotation>
            </xs:element>
          </xs:all>
        </xs:complexType>
      </xs:element>
      <xs:element name="ServerList" type="ns1:HostEntry" minOccurs="0">
        <xs:annotation>
          <xs:documentation>This section contains the list of hosts the user will be able to select from.</xs:documentation>
        </xs:annotation>
      </xs:element>
    </xs:sequence>
  </xs:complexType>
  <xs:complexType name="BackupServerList">
    <xs:annotation>
      <xs:documentation>Collection of one or more backup servers to be used in case the user selected one fails.</xs:documentation>
    </xs:annotation>
    <xs:sequence>
      <xs:element name="HostAddress" maxOccurs="unbounded">
        <xs:annotation>
          <xs:documentation>Can be a FQDN or IP address.</xs:documentation>
        </xs:annotation>
      </xs:element>
    </xs:sequence>
  </xs:complexType>
  <xs:complexType name="LoadBalancingServerList">
    <xs:annotation>
      <xs:documentation>Collection of one or more load balancing servers.</xs:documentation>
    </xs:annotation>
    <xs:sequence>
      <xs:element name="HostAddress" maxOccurs="unbounded">
        <xs:annotation>
          <xs:documentation>Can be a FQDN or IP address.</xs:documentation>
        </xs:annotation>
      </xs:element>
    </xs:sequence>
  </xs:complexType>
  <xs:complexType name="KeyUsage">
    <xs:annotation>
      <xs:documentation>Certificate Key attributes that can be used for choosing acceptable client certificates.</xs:documentation>
    </xs:annotation>
    <xs:sequence>
      <xs:element name="MatchKey" maxOccurs="9">
        <xs:annotation>
          <xs:documentation>One or more match key may be specified.  A certificate must match at least one of the specified key to be selected.</xs:documentation>
        </xs:annotation>
        <xs:simpleType>
          <xs:restriction base="xs:string">
            <xs:enumeration value="Decipher_Only" />
            <xs:enumeration value="Encipher_Only" />
            <xs:enumeration value="CRL_Sign" />
            <xs:enumeration value="Key_Cert_Sign" />
            <xs:enumeration value="Key_Agreement" />
            <xs:enumeration value="Data_Encipherment" />
            <xs:enumeration value="Key_Encipherment" />
            <xs:enumeration value="Non_Repudiation" />
            <xs:enumeration value="Digital_Signature" />
          </xs:restriction>
        </xs:simpleType>
      </xs:element>
    </xs:sequence>
  </xs:complexType>
  <xs:complexType name="ExtendedKeyUsage">
    <xs:annotation>
      <xs:documentation>Certificate Extended Key attributes that can be used for choosing acceptable client certificates.</xs:documentation>
    </xs:annotation>
    <xs:sequence>
      <xs:element name="ExtendedMatchKey" nillable="false" minOccurs="0" maxOccurs="unbounded">
        <xs:annotation>
          <xs:documentation>Zero or more extended match key may be specified.  A certificate must match all of the specified key(s) to be selected.</xs:documentation>
        </xs:annotation>
        <xs:simpleType>
          <xs:restriction base="xs:string">
            <xs:whiteSpace value="collapse" />
            <xs:enumeration value="ServerAuth">
              <xs:annotation>
                <xs:documentation>1.3.6.1.5.5.7.3.1</xs:documentation>
              </xs:annotation>
            </xs:enumeration>
            <xs:enumeration value="ClientAuth">
              <xs:annotation>
                <xs:documentation>1.3.6.1.5.5.7.3.2</xs:documentation>
              </xs:annotation>
            </xs:enumeration>
            <xs:enumeration value="CodeSign">
              <xs:annotation>
                <xs:documentation>1.3.6.1.5.5.7.3.3</xs:documentation>
              </xs:annotation>
            </xs:enumeration>
            <xs:enumeration value="EmailProtect">
              <xs:annotation>
                <xs:documentation>1.3.6.1.5.5.7.3.4</xs:documentation>
              </xs:annotation>
            </xs:enumeration>
            <xs:enumeration value="IPSecEndSystem">
              <xs:annotation>
                <xs:documentation>1.3.6.1.5.5.7.3.5</xs:documentation>
              </xs:annotation>
            </xs:enumeration>
            <xs:enumeration value="IPSecTunnel">
              <xs:annotation>
                <xs:documentation>1.3.6.1.5.5.7.3.6</xs:documentation>
              </xs:annotation>
            </xs:enumeration>
            <xs:enumeration value="IPSecUser">
              <xs:annotation>
                <xs:documentation>1.3.6.1.5.5.7.3.7</xs:documentation>
              </xs:annotation>
            </xs:enumeration>
            <xs:enumeration value="TimeStamp">
              <xs:annotation>
                <xs:documentation>1.3.6.1.5.5.7.3.8</xs:documentation>
              </xs:annotation>
            </xs:enumeration>
            <xs:enumeration value="OCSPSign">
              <xs:annotation>
                <xs:documentation>1.3.6.1.5.5.7.3.9</xs:documentation>
              </xs:annotation>
            </xs:enumeration>
            <xs:enumeration value="DVCS">
              <xs:annotation>
                <xs:documentation>1.3.6.1.5.5.7.3.10</xs:documentation>
              </xs:annotation>
            </xs:enumeration>
            <xs:enumeration value="IKEIntermediate">
              <xs:annotation>
                <xs:documentation>1.3.6.1.5.5.8.2.2</xs:documentation>
              </xs:annotation>
            </xs:enumeration>
          </xs:restriction>
        </xs:simpleType>
      </xs:element>
      <xs:element name="CustomExtendedMatchKey" minOccurs="0" maxOccurs="10">
        <xs:annotation>
          <xs:documentation>Zero or more custom extended match key may be specified.  A certificate must match all of the specified key(s) to be selected.  The key should be in OID form (e.g. 1.3.6.1.5.5.7.3.11)</xs:documentation>
        </xs:annotation>
        <xs:simpleType>
          <xs:restriction base="xs:string">
            <xs:whiteSpace value="collapse" />
            <xs:minLength value="1" />
            <xs:maxLength value="30" />
          </xs:restriction>
        </xs:simpleType>
      </xs:element>
    </xs:sequence>
  </xs:complexType>
  <xs:complexType name="DistinguishedName">
    <xs:annotation>
      <xs:documentation>Certificate Distinguished Name matching allows for exact match criteria in the choosing of acceptable client certificates.</xs:documentation>
    </xs:annotation>
    <xs:sequence>
      <xs:element name="DistinguishedNameDefinition" maxOccurs="10">
        <xs:annotation>
          <xs:documentation>This element represents the set of attributes to define a single Distinguished Name mathcing definition.</xs:documentation>
        </xs:annotation>
        <xs:complexType>
          <xs:sequence>
            <xs:element name="Name">
              <xs:annotation>
                <xs:documentation>Distinguished attribute name to be used in mathcing.</xs:documentation>
              </xs:annotation>
              <xs:simpleType>
                <xs:restriction base="xs:string">
                  <xs:enumeration value="CN">
                    <xs:annotation>
                      <xs:documentation>Subject Common Name</xs:documentation>
                    </xs:annotation>
                  </xs:enumeration>
                  <xs:enumeration value="DC">
                    <xs:annotation>
                      <xs:documentation>Domain Component</xs:documentation>
                    </xs:annotation>
                  </xs:enumeration>
                  <xs:enumeration value="SN">
                    <xs:annotation>
                      <xs:documentation>Subject Sur Name</xs:documentation>
                    </xs:annotation>
                  </xs:enumeration>
                  <xs:enumeration value="GN">
                    <xs:annotation>
                      <xs:documentation>Subject Given Name</xs:documentation>
                    </xs:annotation>
                  </xs:enumeration>
                  <xs:enumeration value="N">
                    <xs:annotation>
                      <xs:documentation>Subject Unstruct Name</xs:documentation>
                    </xs:annotation>
                  </xs:enumeration>
                  <xs:enumeration value="I">
                    <xs:annotation>
                      <xs:documentation>Subject Initials</xs:documentation>
                    </xs:annotation>
                  </xs:enumeration>
                  <xs:enumeration value="GENQ">
                    <xs:annotation>
                      <xs:documentation>Subject Gen Qualifier</xs:documentation>
                    </xs:annotation>
                  </xs:enumeration>
                  <xs:enumeration value="DNQ">
                    <xs:annotation>
                      <xs:documentation>Subject Dn Qualifier</xs:documentation>
                    </xs:annotation>
                  </xs:enumeration>
                  <xs:enumeration value="C">
                    <xs:annotation>
                      <xs:documentation>Subject Country</xs:documentation>
                    </xs:annotation>
                  </xs:enumeration>
                  <xs:enumeration value="L">
                    <xs:annotation>
                      <xs:documentation>Subject City</xs:documentation>
                    </xs:annotation>
                  </xs:enumeration>
                  <xs:enumeration value="SP">
                    <xs:annotation>
                      <xs:documentation>Subject State</xs:documentation>
                    </xs:annotation>
                  </xs:enumeration>
                  <xs:enumeration value="ST">
                    <xs:annotation>
                      <xs:documentation>Subject State</xs:documentation>
                    </xs:annotation>
                  </xs:enumeration>
                  <xs:enumeration value="O">
                    <xs:annotation>
                      <xs:documentation>Subject Company</xs:documentation>
                    </xs:annotation>
                  </xs:enumeration>
                  <xs:enumeration value="OU">
                    <xs:annotation>
                      <xs:documentation>Subject Department</xs:documentation>
                    </xs:annotation>
                  </xs:enumeration>
                  <xs:enumeration value="T">
                    <xs:annotation>
                      <xs:documentation>Subject Title</xs:documentation>
                    </xs:annotation>
                  </xs:enumeration>
                  <xs:enumeration value="EA">
                    <xs:annotation>
                      <xs:documentation>Subject Email Address</xs:documentation>
                    </xs:annotation>
                  </xs:enumeration>
                  <xs:enumeration value="ISSUER-CN">
                    <xs:annotation>
                      <xs:documentation>Issuer Common Name</xs:documentation>
                    </xs:annotation>
                  </xs:enumeration>
                  <xs:enumeration value="ISSUER-DC">
                    <xs:annotation>
                      <xs:documentation>Issuer Domain Component</xs:documentation>
                    </xs:annotation>
                  </xs:enumeration>
                  <xs:enumeration value="ISSUER-SN">
                    <xs:annotation>
                      <xs:documentation>Issuer Sur Name</xs:documentation>
                    </xs:annotation>
                  </xs:enumeration>
                  <xs:enumeration value="ISSUER-GN">
                    <xs:annotation>
                      <xs:documentation>Issuer Given Name</xs:documentation>
                    </xs:annotation>
                  </xs:enumeration>
                  <xs:enumeration value="ISSUER-N">
                    <xs:annotation>
                      <xs:documentation>Issuer Unstruct Name</xs:documentation>
                    </xs:annotation>
                  </xs:enumeration>
                  <xs:enumeration value="ISSUER-I">
                    <xs:annotation>
                      <xs:documentation>Issuer Initials</xs:documentation>
                    </xs:annotation>
                  </xs:enumeration>
                  <xs:enumeration value="ISSUER-GENQ">
                    <xs:annotation>
                      <xs:documentation>Issuer Gen Qualifier</xs:documentation>
                    </xs:annotation>
                  </xs:enumeration>
                  <xs:enumeration value="ISSUER-DNQ">
                    <xs:annotation>
                      <xs:documentation>Issuer Dn Qualifier</xs:documentation>
                    </xs:annotation>
                  </xs:enumeration>
                  <xs:enumeration value="ISSUER-C">
                    <xs:annotation>
                      <xs:documentation>Issuer Country</xs:documentation>
                    </xs:annotation>
                  </xs:enumeration>
                  <xs:enumeration value="ISSUER-L">
                    <xs:annotation>
                      <xs:documentation>Issuer City</xs:documentation>
                    </xs:annotation>
                  </xs:enumeration>
                  <xs:enumeration value="ISSUER-SP">
                    <xs:annotation>
                      <xs:documentation>Issuer State</xs:documentation>
                    </xs:annotation>
                  </xs:enumeration>
                  <xs:enumeration value="ISSUER-ST">
                    <xs:annotation>
                      <xs:documentation>Issuer State</xs:documentation>
                    </xs:annotation>
                  </xs:enumeration>
                  <xs:enumeration value="ISSUER-O">
                    <xs:annotation>
                      <xs:documentation>Issuer Company</xs:documentation>
                    </xs:annotation>
                  </xs:enumeration>
                  <xs:enumeration value="ISSUER-OU">
                    <xs:annotation>
                      <xs:documentation>Issuer Department</xs:documentation>
                    </xs:annotation>
                  </xs:enumeration>
                  <xs:enumeration value="ISSUER-T">
                    <xs:annotation>
                      <xs:documentation>Issuer Title</xs:documentation>
                    </xs:annotation>
                  </xs:enumeration>
                  <xs:enumeration value="ISSUER-EA">
                    <xs:annotation>
                      <xs:documentation>Issuer Email Address</xs:documentation>
                    </xs:annotation>
                  </xs:enumeration>
                </xs:restriction>
              </xs:simpleType>
            </xs:element>
            <xs:element name="Pattern" nillable="false">
              <xs:annotation>
                <xs:documentation>The string to use in the match.</xs:documentation>
              </xs:annotation>
              <xs:simpleType>
                <xs:restriction base="xs:string">
                  <xs:minLength value="1" />
                  <xs:maxLength value="30" />
                  <xs:whiteSpace value="collapse" />
                </xs:restriction>
              </xs:simpleType>
            </xs:element>
          </xs:sequence>
          <xs:attribute name="Wildcard" default="Disabled">
            <xs:annotation>
              <xs:documentation>Should the pattern include wildcard pattern matching.  With wildcarding enabled, the pattern can be anywhere in the string.</xs:documentation>
            </xs:annotation>
            <xs:simpleType>
              <xs:restriction base="xs:string">
                <xs:enumeration value="Disabled">
                  <xs:annotation>
                    <xs:documentation>wildcard pattern match is not enabled for this definition</xs:documentation>
                  </xs:annotation>
                </xs:enumeration>
                <xs:enumeration value="Enabled">
                  <xs:annotation>
                    <xs:documentation>wildcard pattern match is enabled for this definition</xs:documentation>
                  </xs:annotation>
                </xs:enumeration>
              </xs:restriction>
            </xs:simpleType>
          </xs:attribute>
          <xs:attribute name="Operator" default="Equal">
            <xs:annotation>
              <xs:documentation>The operator to be used in performing the match</xs:documentation>
            </xs:annotation>
            <xs:simpleType>
              <xs:restriction base="xs:string">
                <xs:enumeration value="Equal">
                  <xs:annotation>
                    <xs:documentation>equivalent to ==</xs:documentation>
                  </xs:annotation>
                </xs:enumeration>
                <xs:enumeration value="NotEqual">
                  <xs:annotation>
                    <xs:documentation>equivalent to !=</xs:documentation>
                  </xs:annotation>
                </xs:enumeration>
              </xs:restriction>
            </xs:simpleType>
          </xs:attribute>
          <xs:attribute name="MatchCase" default="Enabled">
            <xs:annotation>
              <xs:documentation>Should the pattern matching applied to "Pattern" be case sensitive?  Default is "Enabled" (case sensitive).</xs:documentation>
            </xs:annotation>
            <xs:simpleType>
              <xs:restriction base="xs:string">
                <xs:enumeration value="Enabled">
                  <xs:annotation>
                    <xs:documentation>perform case sensitive match with pattern</xs:documentation>
                  </xs:annotation>
                </xs:enumeration>
                <xs:enumeration value="Disabled">
                  <xs:annotation>
                    <xs:documentation>perform case in-sensitive match with pattern</xs:documentation>
                  </xs:annotation>
                </xs:enumeration>
              </xs:restriction>
            </xs:simpleType>
          </xs:attribute>
        </xs:complexType>
      </xs:element>
    </xs:sequence>
  </xs:complexType>
  <xs:element name="AnyConnectProfile" type="ns1:AnyConnectClientProfile">
    <xs:annotation>
      <xs:documentation>The root element representing the AnyConnect Client Profile</xs:documentation>
    </xs:annotation>
  </xs:element>
  <xs:simpleType name="simpleBinary">
    <xs:restriction base="xs:string">
      <xs:enumeration value="true">
        <xs:annotation>
          <xs:documentation>
          </xs:documentation>
        </xs:annotation>
      </xs:enumeration>
      <xs:enumeration value="false">
        <xs:annotation>
          <xs:documentation>
          </xs:documentation>
        </xs:annotation>
      </xs:enumeration>
    </xs:restriction>
  </xs:simpleType>
  <xs:simpleType name="AutoConnectValues">
    <xs:restriction base="xs:string">
      <xs:enumeration value="DisconnectOnSuspend" />
      <xs:enumeration value="ReconnectAfterResume" />
    </xs:restriction>
  </xs:simpleType>
  <xs:simpleType name="RSAIntegrationValues">
    <xs:restriction base="xs:string">
      <xs:enumeration value="Automatic" />
      <xs:enumeration value="SoftwareToken" />
      <xs:enumeration value="HardwareToken" />
    </xs:restriction>
  </xs:simpleType>
  <xs:simpleType name="UserControllableValues">
    <xs:restriction base="xs:string">
      <xs:enumeration value="true">
        <xs:annotation>
          <xs:documentation source="user is allowed to control this setting." />
        </xs:annotation>
      </xs:enumeration>
      <xs:enumeration value="false">
        <xs:annotation>
          <xs:documentation source="user is not allowed to control this setting." />
        </xs:annotation>
      </xs:enumeration>
    </xs:restriction>
  </xs:simpleType>
  <xs:simpleType name="WindowsLogonEnforcementValues">
    <xs:restriction base="xs:string">
      <xs:enumeration value="SingleLogon">
        <xs:annotation>
          <xs:documentation>Allows only one user during a VPN connection</xs:documentation>
        </xs:annotation>
      </xs:enumeration>
      <xs:enumeration value="SingleLocalLogon">
        <xs:annotation>
          <xs:documentation>Allows only one local user but many remote users during a VPN connection</xs:documentation>
        </xs:annotation>
      </xs:enumeration>
    </xs:restriction>
  </xs:simpleType>
  <xs:simpleType name="WindowsVPNEstablishmentValues">
    <xs:restriction base="xs:string">
      <xs:enumeration value="LocalUsersOnly">
        <xs:annotation>
          <xs:documentation>Only local users may establish a VPN connection</xs:documentation>
        </xs:annotation>
      </xs:enumeration>
      <xs:enumeration value="AllowRemoteUsers">
        <xs:annotation>
          <xs:documentation>Local and remote users may establish a VPN connection</xs:documentation>
        </xs:annotation>
      </xs:enumeration>
    </xs:restriction>
  </xs:simpleType>
  <xs:simpleType name="UserEnforcementValues">
    <xs:restriction base="xs:string">
      <xs:enumeration value="SameUserOnly" />
      <xs:enumeration value="AnyUser" />
    </xs:restriction>
  </xs:simpleType>
  <xs:simpleType name="PPPExclusionValues">
    <xs:restriction base="xs:string">
      <xs:enumeration value="Automatic">
        <xs:annotation>
          <xs:documentation>Automatically detect when a VPN connection is being established over a point-to-point connection.</xs:documentation>
        </xs:annotation>
      </xs:enumeration>
      <xs:enumeration value="Disable">
        <xs:annotation>
          <xs:documentation>Disable automatic detection of point-to-point connections.</xs:documentation>
        </xs:annotation>
      </xs:enumeration>
      <xs:enumeration value="Override">
        <xs:annotation>
          <xs:documentation>Override the address of the PPP server with the value of PPPExclusionServerIP.</xs:documentation>
        </xs:annotation>
      </xs:enumeration>
    </xs:restriction>
  </xs:simpleType>
  <xs:simpleType name="TrustedNetworkPolicyValues">
    <xs:restriction base="xs:string">
      <xs:enumeration value="Connect" />
      <xs:enumeration value="Pause" />
      <xs:enumeration value="Disconnect" />
      <xs:enumeration value="DoNothing" />
    </xs:restriction>
  </xs:simpleType>
  <xs:simpleType name="UntrustedNetworkPolicyValues">
    <xs:restriction base="xs:string">
      <xs:enumeration value="Connect" />
      <xs:enumeration value="DoNothing" />
    </xs:restriction>
  </xs:simpleType>
  <xs:simpleType name="CaptivePortalRemediationTimeoutValues">
    <xs:restriction base="xs:integer">
      <xs:minInclusive value="0" />
      <xs:maxInclusive value="100" />
    </xs:restriction>
  </xs:simpleType>
  <xs:simpleType name="AutoServerSelectionImprovement">
    <xs:restriction base="xs:integer">
      <xs:minInclusive value="10" />
      <xs:maxInclusive value="100" />
    </xs:restriction>
  </xs:simpleType>
  <xs:simpleType name="AutoServerSelectionSuspendTime">
    <xs:restriction base="xs:integer">
      <xs:minInclusive value="1" />
      <xs:maxInclusive value="100" />
    </xs:restriction>
  </xs:simpleType>
  <xs:simpleType name="AuthenticationTimeoutValues">
    <xs:restriction base="xs:integer">
      <xs:minInclusive value="10" />
      <xs:maxInclusive value="120" />
    </xs:restriction>
  </xs:simpleType>
  <xs:complexType name="CAURL">
    <xs:simpleContent>
      <xs:extension base="xs:string">
        <xs:attribute name="PromptForChallengePW" type="ns1:simpleBinary" />
        <xs:attribute name="Thumbprint" type="xs:string" />
      </xs:extension>
    </xs:simpleContent>
  </xs:complexType>
  <xs:simpleType name="PasswordComplexityValues">
    <xs:restriction base="xs:string">
      <xs:enumeration value="pin" />
      <xs:enumeration value="alpha" />
      <xs:enumeration value="strong" />
    </xs:restriction>
  </xs:simpleType>
  <xs:simpleType name="PrimaryProtocolValues">
    <xs:restriction base="xs:string">
      <xs:enumeration value="SSL" />
      <xs:enumeration value="IPsec" />
    </xs:restriction>
  </xs:simpleType>
  <xs:simpleType name="AuthMethodValues">
    <xs:restriction base="xs:string">
      <xs:enumeration value="EAP-MD5" />
      <xs:enumeration value="EAP-MSCHAPv2" />
      <xs:enumeration value="EAP-GTC" />
      <xs:enumeration value="EAP-AnyConnect" />
      <xs:enumeration value="IKE-RSA" />
      <xs:enumeration value="IKE-ECDSA" />
    </xs:restriction>
  </xs:simpleType>
  <xs:simpleType name="CertificateStores">
    <xs:restriction base="xs:string">
      <xs:enumeration value="All">
        <xs:annotation>
          <xs:documentation>Use certificates from all available certificate stores.</xs:documentation>
        </xs:annotation>
      </xs:enumeration>
      <xs:enumeration value="Machine">
        <xs:annotation>
          <xs:documentation>Use certificates only from the Windows machine certificate store.</xs:documentation>
        </xs:annotation>
      </xs:enumeration>
      <xs:enumeration value="User">
        <xs:annotation>
          <xs:documentation>Use certificates only from the Windows user certificate store.</xs:documentation>
        </xs:annotation>
      </xs:enumeration>
    </xs:restriction>
  </xs:simpleType>
  <xs:simpleType name="CertificateStoresMac">
    <xs:restriction base="xs:string">
      <xs:enumeration value="All">
        <xs:annotation>
          <xs:documentation>Use certificates from all available macOS keychains and file stores.</xs:documentation>
        </xs:annotation>
      </xs:enumeration>
      <xs:enumeration value="System">
        <xs:annotation>
          <xs:documentation>Use certificates only from the macOS system keychain and system file store.</xs:documentation>
        </xs:annotation>
      </xs:enumeration>
      <xs:enumeration value="Login">
        <xs:annotation>
          <xs:documentation>Use certificates only from the macOS login and smartcard keychains, as well as the user file store.</xs:documentation>
        </xs:annotation>
      </xs:enumeration>
    </xs:restriction>
  </xs:simpleType>
  <xs:simpleType name="CertificatePolicyRule">
    <xs:restriction base="xs:string">
      <xs:enumeration value="Auto" />
      <xs:enumeration value="Manual" />
      <xs:enumeration value="None" />
    </xs:restriction>
  </xs:simpleType>
  <xs:simpleType name="IPProtocolSupportValues">
    <xs:restriction base="xs:string">
      <xs:enumeration value="IPv4" />
      <xs:enumeration value="IPv6" />
      <xs:enumeration value="IPv4,IPv6" />
      <xs:enumeration value="IPv6,IPv4" />
    </xs:restriction>
  </xs:simpleType>
  <xs:simpleType name="ProxySettingsValues">
    <xs:restriction base="xs:string">
      <xs:enumeration value="Native">
        <xs:annotation>
          <xs:documentation>Use browser settings.</xs:documentation>
        </xs:annotation>
      </xs:enumeration>
      <xs:enumeration value="IgnoreProxy">
        <xs:annotation>
          <xs:documentation>Use no proxy settings.</xs:documentation>
        </xs:annotation>
      </xs:enumeration>
      <xs:enumeration value="Override">
        <xs:annotation>
          <xs:documentation>Use AnyConnect proxy settings.</xs:documentation>
        </xs:annotation>
      </xs:enumeration>
    </xs:restriction>
  </xs:simpleType>
</xs:schema>
