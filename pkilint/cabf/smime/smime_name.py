import validators
import json
from pyasn1_alt_modules import rfc5280, rfc8398

from pkilint import validation, pkix, oid
from pkilint.cabf import cabf_name
from pkilint.cabf.cabf_name import CabfOrganizationIdentifierAttributeValidator
from pkilint.cabf.smime.smime_constants import Generation, ValidationLevel
from pkilint.common import organization_id
from pkilint.common.organization_id import OrganizationIdentifierLeiValidator
from pkilint.itu import x520_name, asn1_util
from pkilint.pkix import certificate, name, Rfc2119Word, general_name

SHALL = pkix.Rfc2119Word.SHALL
SHALL_NOT = pkix.Rfc2119Word.SHALL_NOT
MAY = pkix.Rfc2119Word.MAY

_OID_METADATA = '''
{
    "2.5.4.0" : {
        "OID": "2.5.4.0",
        "Name": "objectClass",
        "Sub children": "0",
        "Sub Nodes Total": "0",
        "Description": "Object classes"
    },
    "2.5.4.1" : {
        "OID": "2.5.4.1",
        "Name": "aliasedEntryName",
        "Sub children": "1",
        "Sub Nodes Total": "1",
        "Description": "Attribute type \\"Aliased entry name\\""
    },
    "2.5.4.2" : {
        "OID": "2.5.4.2",
        "Name": "knowledgeInformation",
        "Sub children": "0",
        "Sub Nodes Total": "0",
        "Description": "knowledgeInformation attribute type"
    },
    "2.5.4.3" : {
        "OID": "2.5.4.3",
        "Name": "commonName",
        "Sub children": "1",
        "Sub Nodes Total": "1",
        "Description": "Common name"
    },
    "2.5.4.4" : {
        "OID": "2.5.4.4",
        "Name": "surname",
        "Sub children": "1",
        "Sub Nodes Total": "1",
        "Description": "Attribute \\"surname\\""
    },
    "2.5.4.5" : {
        "OID": "2.5.4.5",
        "Name": "serialNumber",
        "Sub children": "1",
        "Sub Nodes Total": "1",
        "Description": "Serial number attribute type"
    },
    "2.5.4.6" : {
        "OID": "2.5.4.6",
        "Name": "countryName",
        "Sub children": "1",
        "Sub Nodes Total": "1",
        "Description": "Country name"
    },
    "2.5.4.7" : {
        "OID": "2.5.4.7",
        "Name": "localityName",
        "Sub children": "2",
        "Sub Nodes Total": "3",
        "Description": "Locality Name"
    },
    "2.5.4.8" : {
        "OID": "2.5.4.8",
        "Name": "stateOrProvinceName",
        "Sub children": "2",
        "Sub Nodes Total": "3",
        "Description": "State or Province name"
    },
    "2.5.4.9" : {
        "OID": "2.5.4.9",
        "Name": "streetAddress",
        "Sub children": "2",
        "Sub Nodes Total": "3",
        "Description": "Street address"
    },
    "2.5.4.10" : {
        "OID": "2.5.4.10",
        "Name": "organizationName",
        "Sub children": "2",
        "Sub Nodes Total": "3",
        "Description": "Organization name"
    },
    "2.5.4.11" : {
        "OID": "2.5.4.11",
        "Name": "organizationUnitName",
        "Sub children": "2",
        "Sub Nodes Total": "3",
        "Description": "Organization unit name"
    },
    "2.5.4.12" : {
        "OID": "2.5.4.12",
        "Name": "title",
        "Sub children": "1",
        "Sub Nodes Total": "1",
        "Description": "Title attribute type"
    },
    "2.5.4.13" : {
        "OID": "2.5.4.13",
        "Name": "description",
        "Sub children": "1",
        "Sub Nodes Total": "1",
        "Description": "Description attribute type"
    },
    "2.5.4.14" : {
        "OID": "2.5.4.14",
        "Name": "searchGuide",
        "Sub children": "1",
        "Sub Nodes Total": "1",
        "Description": "Search guide attribute type"
    },
    "2.5.4.15" : {
        "OID": "2.5.4.15",
        "Name": "businessCategory",
        "Sub children": "1",
        "Sub Nodes Total": "1",
        "Description": "Business category attribute type"
    },
    "2.5.4.16" : {
        "OID": "2.5.4.16",
        "Name": "postalAddress",
        "Sub children": "2",
        "Sub Nodes Total": "3",
        "Description": "Postal address attribute type"
    },
    "2.5.4.17" : {
        "OID": "2.5.4.17",
        "Name": "postalCode",
        "Sub children": "2",
        "Sub Nodes Total": "3",
        "Description": "Postal code attribute type"
    },
    "2.5.4.18" : {
        "OID": "2.5.4.18",
        "Name": "postOfficeBox",
        "Sub children": "2",
        "Sub Nodes Total": "3",
        "Description": "Post office box attribute type"
    },
    "2.5.4.19" : {
        "OID": "2.5.4.19",
        "Name": "physicalDeliveryOfficeName",
        "Sub children": "2",
        "Sub Nodes Total": "3",
        "Description": "physicalDeliveryOfficeName attribute type"
    },
    "2.5.4.20" : {
        "OID": "2.5.4.20",
        "Name": "telephoneNumber",
        "Sub children": "2",
        "Sub Nodes Total": "3",
        "Description": "Telephone number attribute type"
    },
    "2.5.4.21" : {
        "OID": "2.5.4.21",
        "Name": "telexNumber",
        "Sub children": "2",
        "Sub Nodes Total": "3",
        "Description": "Telex number attribute type"
    },
    "2.5.4.22" : {
        "OID": "2.5.4.22",
        "Name": "teletexTerminalIdentifier",
        "Sub children": "2",
        "Sub Nodes Total": "3",
        "Description": "Teletex terminal identifier attribute type"
    },
    "2.5.4.23" : {
        "OID": "2.5.4.23",
        "Name": "facsimileTelephoneNumber",
        "Sub children": "2",
        "Sub Nodes Total": "3",
        "Description": "Facsimile telephone number attribute type"
    },
    "2.5.4.24" : {
        "OID": "2.5.4.24",
        "Name": "x121Address",
        "Sub children": "1",
        "Sub Nodes Total": "1",
        "Description": "X121 address attribute type"
    },
    "2.5.4.25" : {
        "OID": "2.5.4.25",
        "Name": "internationalISDNNumber",
        "Sub children": "2",
        "Sub Nodes Total": "3",
        "Description": "International ISDN (Integrated Services Digital Network) number attribute type"
    },
    "2.5.4.26" : {
        "OID": "2.5.4.26",
        "Name": "registeredAddress",
        "Sub children": "1",
        "Sub Nodes Total": "1",
        "Description": "Registered address attribute type"
    },
    "2.5.4.27" : {
        "OID": "2.5.4.27",
        "Name": "destinationIndicator",
        "Sub children": "1",
        "Sub Nodes Total": "1",
        "Description": "Destination indicator attribute type"
    },
    "2.5.4.28" : {
        "OID": "2.5.4.28",
        "Name": "preferredDeliveryMethod",
        "Sub children": "1",
        "Sub Nodes Total": "1",
        "Description": "Preferred delivery method attribute type"
    },
    "2.5.4.29" : {
        "OID": "2.5.4.29",
        "Name": "presentationAddress",
        "Sub children": "1",
        "Sub Nodes Total": "1",
        "Description": "Presentation address attribute type"
    },
    "2.5.4.30" : {
        "OID": "2.5.4.30",
        "Name": "supportedApplicationContext",
        "Sub children": "1",
        "Sub Nodes Total": "1",
        "Description": "Supported application context attribute type"
    },
    "2.5.4.31" : {
        "OID": "2.5.4.31",
        "Name": "member",
        "Sub children": "1",
        "Sub Nodes Total": "1",
        "Description": "Member attribute type"
    },
    "2.5.4.32" : {
        "OID": "2.5.4.32",
        "Name": "owner",
        "Sub children": "1",
        "Sub Nodes Total": "1",
        "Description": "Owner attribute type"
    },
    "2.5.4.33" : {
        "OID": "2.5.4.33",
        "Name": "roleOccupant",
        "Sub children": "1",
        "Sub Nodes Total": "1",
        "Description": "Role occupant attribute type"
    },
    "2.5.4.34" : {
        "OID": "2.5.4.34",
        "Name": "seeAlso",
        "Sub children": "1",
        "Sub Nodes Total": "1",
        "Description": "seeAlso attribute type"
    },
    "2.5.4.35" : {
        "OID": "2.5.4.35",
        "Name": "userPassword",
        "Sub children": "1",
        "Sub Nodes Total": "1",
        "Description": "userPassword attribute type"
    },
    "2.5.4.36" : {
        "OID": "2.5.4.36",
        "Name": "userCertificate",
        "Sub children": "1",
        "Sub Nodes Total": "1",
        "Description": "userCertificate attribute type"
    },
    "2.5.4.37" : {
        "OID": "2.5.4.37",
        "Name": "cACertificate",
        "Sub children": "1",
        "Sub Nodes Total": "1",
        "Description": "cAcertificate attribute type"
    },
    "2.5.4.38" : {
        "OID": "2.5.4.38",
        "Name": "authorityRevocationList",
        "Sub children": "1",
        "Sub Nodes Total": "1",
        "Description": "authorityRevocationList attribute type"
    },
    "2.5.4.39" : {
        "OID": "2.5.4.39",
        "Name": "certificateRevocationList",
        "Sub children": "1",
        "Sub Nodes Total": "1",
        "Description": "certificateRevocationList attribute type"
    },
    "2.5.4.40" : {
        "OID": "2.5.4.40",
        "Name": "crossCertificatePair",
        "Sub children": "1",
        "Sub Nodes Total": "1",
        "Description": "crossCertificatePair attribute type"
    },
    "2.5.4.41" : {
        "OID": "2.5.4.41",
        "Name": "name",
        "Sub children": "0",
        "Sub Nodes Total": "0",
        "Description": "Name attribute type"
    },
    "2.5.4.42" : {
        "OID": "2.5.4.42",
        "Name": "givenName",
        "Sub children": "1",
        "Sub Nodes Total": "1",
        "Description": "Given name attribute type"
    },
    "2.5.4.43" : {
        "OID": "2.5.4.43",
        "Name": "initials",
        "Sub children": "1",
        "Sub Nodes Total": "1",
        "Description": "Initials attribute type"
    },
    "2.5.4.44" : {
        "OID": "2.5.4.44",
        "Name": "generationQualifier",
        "Sub children": "1",
        "Sub Nodes Total": "1",
        "Description": "generationQualifier attribute type"
    },
    "2.5.4.45" : {
        "OID": "2.5.4.45",
        "Name": "uniqueIdentifier",
        "Sub children": "1",
        "Sub Nodes Total": "1",
        "Description": "uniqueIdentifier attribute type"
    },
    "2.5.4.46" : {
        "OID": "2.5.4.46",
        "Name": "dnQualifier",
        "Sub children": "1",
        "Sub Nodes Total": "1",
        "Description": "dnQualifier attribute type"
    },
    "2.5.4.47" : {
        "OID": "2.5.4.47",
        "Name": "enhancedSearchGuide",
        "Sub children": "1",
        "Sub Nodes Total": "1",
        "Description": "enhancedSearchGuide attribute type"
    },
    "2.5.4.48" : {
        "OID": "2.5.4.48",
        "Name": "protocolInformation",
        "Sub children": "1",
        "Sub Nodes Total": "1",
        "Description": "protocolInformation attribute type"
    },
    "2.5.4.49" : {
        "OID": "2.5.4.49",
        "Name": "distinguishedName",
        "Sub children": "1",
        "Sub Nodes Total": "1",
        "Description": "distinguishedName attribute type"
    },
    "2.5.4.50" : {
        "OID": "2.5.4.50",
        "Name": "uniqueMember",
        "Sub children": "1",
        "Sub Nodes Total": "1",
        "Description": "uniqueMember attribute type"
    },
    "2.5.4.51" : {
        "OID": "2.5.4.51",
        "Name": "houseIdentifier",
        "Sub children": "1",
        "Sub Nodes Total": "1",
        "Description": "houseIdentifier attribute type"
    },
    "2.5.4.52" : {
        "OID": "2.5.4.52",
        "Name": "supportedAlgorithms",
        "Sub children": "1",
        "Sub Nodes Total": "1",
        "Description": "supportedAlgorithms attribute type"
    },
    "2.5.4.53" : {
        "OID": "2.5.4.53",
        "Name": "deltaRevocationList",
        "Sub children": "1",
        "Sub Nodes Total": "1",
        "Description": "deltaRevocationList attribute type"
    },
    "2.5.4.54" : {
        "OID": "2.5.4.54",
        "Name": "dmdName",
        "Sub children": "1",
        "Sub Nodes Total": "1",
        "Description": "DMD Name attribute type"
    },
    "2.5.4.55" : {
        "OID": "2.5.4.55",
        "Name": "clearance",
        "Sub children": "1",
        "Sub Nodes Total": "1",
        "Description": "Attribute type \\"Clearance\\""
    },
    "2.5.4.56" : {
        "OID": "2.5.4.56",
        "Name": "defaultDirQop",
        "Sub children": "1",
        "Sub Nodes Total": "1",
        "Description": "Attribute type \\"Default Dir Qop\\""
    },
    "2.5.4.57" : {
        "OID": "2.5.4.57",
        "Name": "attributeIntegrityInfo",
        "Sub children": "1",
        "Sub Nodes Total": "1",
        "Description": "Attribute type \\"Attribute integrity info\\""
    },
    "2.5.4.58" : {
        "OID": "2.5.4.58",
        "Name": "attributeCertificate",
        "Sub children": "1",
        "Sub Nodes Total": "1",
        "Description": "attributeCertificate attribute type"
    },
    "2.5.4.59" : {
        "OID": "2.5.4.59",
        "Name": "attributeCertificateRevocationList",
        "Sub children": "1",
        "Sub Nodes Total": "1",
        "Description": "attributeCertificateRevocationList attribute type"
    },
    "2.5.4.60" : {
        "OID": "2.5.4.60",
        "Name": "confKeyInfo",
        "Sub children": "1",
        "Sub Nodes Total": "1",
        "Description": "Attribute type \\"Conf key info\\""
    },
    "2.5.4.61" : {
        "OID": "2.5.4.61",
        "Name": "aACertificate",
        "Sub children": "0",
        "Sub Nodes Total": "0",
        "Description": "aACertificate attribute type"
    },
    "2.5.4.62" : {
        "OID": "2.5.4.62",
        "Name": "attributeDescriptorCertificate",
        "Sub children": "0",
        "Sub Nodes Total": "0",
        "Description": "attributeDescriptorCertificate attribute type"
    },
    "2.5.4.63" : {
        "OID": "2.5.4.63",
        "Name": "attributeAuthorityRevocationList",
        "Sub children": "0",
        "Sub Nodes Total": "0",
        "Description": "attributeAuthorityRevocationList attribute type"
    },
    "2.5.4.64" : {
        "OID": "2.5.4.64",
        "Name": "family-information",
        "Sub children": "0",
        "Sub Nodes Total": "0",
        "Description": "Family-information attribute type"
    },
    "2.5.4.65" : {
        "OID": "2.5.4.65",
        "Name": "pseudonym",
        "Sub children": "0",
        "Sub Nodes Total": "0",
        "Description": "Pseudonym attribute type"
    },
    "2.5.4.66" : {
        "OID": "2.5.4.66",
        "Name": "communicationsService",
        "Sub children": "0",
        "Sub Nodes Total": "0",
        "Description": "communicationsService attribute type"
    },
    "2.5.4.67" : {
        "OID": "2.5.4.67",
        "Name": "communicationsNetwork",
        "Sub children": "0",
        "Sub Nodes Total": "0",
        "Description": "communicationsNetwork attribute type"
    },
    "2.5.4.68" : {
        "OID": "2.5.4.68",
        "Name": "certificationPracticeStmt",
        "Sub children": "0",
        "Sub Nodes Total": "0",
        "Description": "certificationPracticeStmt attribute type (Certification practice statement attribute)"
    },
    "2.5.4.69" : {
        "OID": "2.5.4.69",
        "Name": "certificatePolicy",
        "Sub children": "0",
        "Sub Nodes Total": "0",
        "Description": "certificatePolicy attribute type"
    },
    "2.5.4.70" : {
        "OID": "2.5.4.70",
        "Name": "pkiPath",
        "Sub children": "0",
        "Sub Nodes Total": "0",
        "Description": "pkiPath attribute type"
    },
    "2.5.4.71" : {
        "OID": "2.5.4.71",
        "Name": "privPolicy",
        "Sub children": "0",
        "Sub Nodes Total": "0",
        "Description": "privPolicy attribute type"
    },
    "2.5.4.72" : {
        "OID": "2.5.4.72",
        "Name": "role",
        "Sub children": "0",
        "Sub Nodes Total": "0",
        "Description": "role attribute type"
    },
    "2.5.4.73" : {
        "OID": "2.5.4.73",
        "Name": "delegationPath",
        "Sub children": "0",
        "Sub Nodes Total": "0",
        "Description": "delegationPath attribute type"
    },
    "2.5.4.74" : {
        "OID": "2.5.4.74",
        "Name": "protPrivPolicy",
        "Sub children": "0",
        "Sub Nodes Total": "0",
        "Description": "protPrivPolicy ATTRIBUTE ::= {\\nWITH SYNTAX AttributeCertificate\\nEQUALITY MATCHING RULE attributeCertificateExactMatch\\nID id-at-…"
    },
    "2.5.4.75" : {
        "OID": "2.5.4.75",
        "Name": "xMLPrivilegeInfo",
        "Sub children": "0",
        "Sub Nodes Total": "0",
        "Description": "xmlPrivilegeInfo ATTRIBUTE ::= {\\nWITH SYNTAX UTF8String --contains XML-encoded privilege information\\nID id-at-xMLPrivilegeInfo }"
    },
    "2.5.4.76" : {
        "OID": "2.5.4.76",
        "Name": "xmlPrivPolicy",
        "Sub children": "0",
        "Sub Nodes Total": "0",
        "Description": "None"
    },
    "2.5.4.77" : {
        "OID": "2.5.4.77",
        "Name": "uuidpair",
        "Sub children": "0",
        "Sub Nodes Total": "0",
        "Description": "uUIDPair"
    },
    "2.5.4.78" : {
        "OID": "2.5.4.78",
        "Name": "tagOid",
        "Sub children": "0",
        "Sub Nodes Total": "0",
        "Description": "tagOid ATTRIBUTE ::= {\\nWITH SYNTAX OBJECT IDENTIFIER\\nEQUALITY MATCHING RULE objectIdentifierMatch\\nSINGLE VALUE TRUE\\nLDAP-SYNTAX…"
    },
    "2.5.4.79" : {
        "OID": "2.5.4.79",
        "Name": "uiiFormat",
        "Sub children": "0",
        "Sub Nodes Total": "0",
        "Description": "uiiFormat ATTRIBUTE ::= {\\nWITH SYNTAX UiiFormat\\nSINGLE VALUE TRUE\\nLDAP-SYNTAX uiiForm.&amp;id\\nLDAP-NAME {\\"uiiFormat\\"}\\nID id-at-…"
    },
    "2.5.4.80" : {
        "OID": "2.5.4.80",
        "Name": "uiiInUrh",
        "Sub children": "0",
        "Sub Nodes Total": "0",
        "Description": "uiiInUrn ATTRIBUTE ::= {\\nWITH SYNTAX UTF8String\\nEQUALITY MATCHING RULE caseExactMatch\\nSINGLE VALUE TRUE\\nLDAP-SYNTAX directorySt…"
    },
    "2.5.4.81" : {
        "OID": "2.5.4.81",
        "Name": "contentUrl",
        "Sub children": "0",
        "Sub Nodes Total": "0",
        "Description": "contentUrl ATTRIBUTE ::= {\\nSUBTYPE OF url\\nLDAP-SYNTAX directoryString.&amp;id\\nLDAP-NAME {\\"contentUrl\\"}\\nID id-at-contentUrl }"
    },
    "2.5.4.82" : {
        "OID": "2.5.4.82",
        "Name": "permission",
        "Sub children": "0",
        "Sub Nodes Total": "0",
        "Description": "permission ATTRIBUTE ::= {\\nWITH SYNTAX DualStringSyntax\\nEQUALITY MATCHING RULE dualStringMatch\\nID id-at-permission }"
    },
    "2.5.4.83" : {
        "OID": "2.5.4.83",
        "Name": "uri",
        "Sub children": "0",
        "Sub Nodes Total": "0",
        "Description": "uri ATTRIBUTE ::= {\\nWITH SYNTAX URI\\nEQUALITY MATCHING RULE uriMatch\\nLDAP-SYNTAX directoryString.&amp;id\\nLDAP-NAME {\\"uri\\"}\\nID id…"
    },
    "2.5.4.84" : {
        "OID": "2.5.4.84",
        "Name": "pwdAttribute",
        "Sub children": "0",
        "Sub Nodes Total": "0",
        "Description": "pwdAttribute ATTRIBUTE ::= {\\nWITH SYNTAX ATTRIBUTE.&amp;id\\nEQUALITY MATCHING RULE objectIdentifierMatch\\nSINGLE VALUE TRUE\\nLDAP-…"
    },
    "2.5.4.85" : {
        "OID": "2.5.4.85",
        "Name": "userPwd",
        "Sub children": "0",
        "Sub Nodes Total": "0",
        "Description": "userPwd ATTRIBUTE ::= {\\nWITH SYNTAX UserPwd\\nEQUALITY MATCHING RULE userPwdMatch\\nSINGLE VALUE TRUE\\nLDAP-SYNTAX userPwdDescriptio…"
    },
    "2.5.4.86" : {
        "OID": "2.5.4.86",
        "Name": "urn",
        "Sub children": "0",
        "Sub Nodes Total": "0",
        "Description": "urn ATTRIBUTE ::= {\\nSUBTYPE OF uri\\nLDAP-SYNTAX directoryString.&amp;id\\nLDAP-NAME {\\"urn\\"}\\nID id-at-urn }"
    },
    "2.5.4.87" : {
        "OID": "2.5.4.87",
        "Name": "url",
        "Sub children": "0",
        "Sub Nodes Total": "0",
        "Description": "url ATTRIBUTE ::= {\\nSUBTYPE OF uri\\nLDAP-SYNTAX directoryString.&amp;id\\nLDAP-NAME {\\"url\\"}\\nID id-at-url }"
    },
    "2.5.4.88" : {
        "OID": "2.5.4.88",
        "Name": "utmCoordinates",
        "Sub children": "0",
        "Sub Nodes Total": "0",
        "Description": "utmCoordinates ATTRIBUTE ::= {\\nWITH SYNTAX UtmCoordinates\\nSINGLE VALUE TRUE\\nLDAP-SYNTAX utmCoords.&amp;id\\nLDAP-NAME {\\"utmCoordi…"
    },
    "2.5.4.89" : {
        "OID": "2.5.4.89",
        "Name": "urnC",
        "Sub children": "0",
        "Sub Nodes Total": "0",
        "Description": "urnC ATTRIBUTE ::= {\\nWITH SYNTAX PrintableString\\nEQUALITY MATCHING RULE caseExactMatch\\nSINGLE VALUE TRUE\\nLDAP-SYNTAX printableS…"
    },
    "2.5.4.90" : {
        "OID": "2.5.4.90",
        "Name": "uii",
        "Sub children": "0",
        "Sub Nodes Total": "0",
        "Description": "uii ATTRIBUTE ::= {\\nWITH SYNTAX BIT STRING\\nEQUALITY MATCHING RULE bitStringMatch\\nLDAP-SYNTAX bitString.&amp;id\\nLDAP-NAME {\\"uii\\"…"
    },
    "2.5.4.91" : {
        "OID": "2.5.4.91",
        "Name": "epc",
        "Sub children": "0",
        "Sub Nodes Total": "0",
        "Description": "epc ATTRIBUTE ::= {\\nWITH SYNTAX BIT STRING\\nEQUALITY MATCHING RULE bitStringMatch\\nLDAP-SYNTAX bitString.&amp;id\\nLDAP-NAME {\\"epc\\"…"
    },
    "2.5.4.92" : {
        "OID": "2.5.4.92",
        "Name": "tagAfi",
        "Sub children": "0",
        "Sub Nodes Total": "0",
        "Description": "tagAfi ATTRIBUTE ::= {\\nWITH SYNTAX OCTET STRING\\nEQUALITY MATCHING RULE octetStringMatch\\nLDAP-SYNTAX octetString.&amp;id\\nLDAP-NA…"
    },
    "2.5.4.93" : {
        "OID": "2.5.4.93",
        "Name": "epcFormat",
        "Sub children": "0",
        "Sub Nodes Total": "0",
        "Description": "epcFormat ATTRIBUTE ::= {\\nWITH SYNTAX EpcFormat\\nSINGLE VALUE TRUE\\nLDAP-SYNTAX epcForm.&amp;id\\nLDAP-NAME {\\"epcFormat\\"}\\nID id-at-…"
    },
    "2.5.4.94" : {
        "OID": "2.5.4.94",
        "Name": "epcInUrn",
        "Sub children": "0",
        "Sub Nodes Total": "0",
        "Description": "epcInUrn ATTRIBUTE ::= {\\nSUBTYPE OF urn\\nSINGLE VALUE TRUE\\nLDAP-SYNTAX directoryString.&amp;id\\nLDAP-NAME {\\"epcInUrn\\"}\\nID id-at-e…"
    },
    "2.5.4.95" : {
        "OID": "2.5.4.95",
        "Name": "ldapUrl",
        "Sub children": "0",
        "Sub Nodes Total": "0",
        "Description": "ldapUrl ATTRIBUTE ::= {\\nSUBTYPE OF url\\nLDAP-SYNTAX directoryString.&amp;id\\nLDAP-NAME {\\"ldapUrl\\"}\\nID id-at-ldapUrl }"
    },
    "2.5.4.96" : {
        "OID": "2.5.4.96",
        "Name": "ldapUrl",
        "Sub children": "0",
        "Sub Nodes Total": "0",
        "Description": "tagLocation ATTRIBUTE ::= {\\nSUBTYPE OF utmCoordinates\\nSINGLE VALUE TRUE\\nLDAP-SYNTAX utmCoords.&amp;id\\nLDAP-NAME {\\"tagLocation\\"}…"
    },
    "2.5.4.97" : {
        "OID": "2.5.4.97",
        "Name": "organizationIdentifier",
        "Sub children": "0",
        "Sub Nodes Total": "0",
        "Description": "organizationIdentifier ATTRIBUTE ::= {\\nWITH SYNTAX UnboundedDirectoryString\\nEQUALITY MATCHING RULE caseIgnoreMatch\\nSUBSTRINGS M…"
    }
}
'''



_MV_ATTRIBUTES = {
    rfc5280.id_at_commonName: (MAY, MAY, MAY),
    rfc5280.id_at_organizationName: (SHALL_NOT, SHALL_NOT, SHALL_NOT),
    rfc5280.id_at_organizationalUnitName: (SHALL_NOT, SHALL_NOT, SHALL_NOT),
    x520_name.id_at_organizationIdentifier: (SHALL_NOT, SHALL_NOT, SHALL_NOT),
    rfc5280.id_at_givenName: (SHALL_NOT, SHALL_NOT, SHALL_NOT),
    rfc5280.id_at_surname: (SHALL_NOT, SHALL_NOT, SHALL_NOT),
    rfc5280.id_at_pseudonym: (SHALL_NOT, SHALL_NOT, SHALL_NOT),
    rfc5280.id_at_serialNumber: (MAY, MAY, MAY),
    rfc5280.id_emailAddress: (MAY, MAY, MAY),
    rfc5280.id_at_title: (SHALL_NOT, SHALL_NOT, SHALL_NOT),
    x520_name.id_at_streetAddress: (SHALL_NOT, SHALL_NOT, SHALL_NOT),
    rfc5280.id_at_localityName: (SHALL_NOT, SHALL_NOT, SHALL_NOT),
    rfc5280.id_at_stateOrProvinceName: (SHALL_NOT, SHALL_NOT, SHALL_NOT),
    x520_name.id_at_postalCode: (SHALL_NOT, SHALL_NOT, SHALL_NOT),
    rfc5280.id_at_countryName: (SHALL_NOT, SHALL_NOT, SHALL_NOT),
}

_OV_ATTRIBUTES = {
    rfc5280.id_at_commonName: (MAY, MAY, MAY),
    rfc5280.id_at_organizationName: (SHALL, SHALL, SHALL),
    rfc5280.id_at_organizationalUnitName: (MAY, MAY, MAY),
    x520_name.id_at_organizationIdentifier: (SHALL, SHALL, SHALL),
    rfc5280.id_at_givenName: (SHALL_NOT, SHALL_NOT, SHALL_NOT),
    rfc5280.id_at_surname: (SHALL_NOT, SHALL_NOT, SHALL_NOT),
    rfc5280.id_at_pseudonym: (SHALL_NOT, SHALL_NOT, SHALL_NOT),
    rfc5280.id_at_serialNumber: (MAY, MAY, MAY),
    rfc5280.id_emailAddress: (MAY, MAY, MAY),
    rfc5280.id_at_title: (SHALL_NOT, SHALL_NOT, SHALL_NOT),
    x520_name.id_at_streetAddress: (MAY, MAY, SHALL_NOT),
    rfc5280.id_at_localityName: (MAY, MAY, MAY),
    rfc5280.id_at_stateOrProvinceName: (MAY, MAY, MAY),
    x520_name.id_at_postalCode: (MAY, MAY, SHALL_NOT),
    rfc5280.id_at_countryName: (MAY, MAY, MAY),
}

_SV_ATTRIBUTES = {
    rfc5280.id_at_commonName: (MAY, MAY, MAY),
    rfc5280.id_at_organizationName: (SHALL, SHALL, SHALL),
    rfc5280.id_at_organizationalUnitName: (MAY, MAY, MAY),
    x520_name.id_at_organizationIdentifier: (SHALL, SHALL, SHALL),
    rfc5280.id_at_givenName: (MAY, MAY, MAY),
    rfc5280.id_at_surname: (MAY, MAY, MAY),
    rfc5280.id_at_pseudonym: (MAY, MAY, MAY),
    rfc5280.id_at_serialNumber: (MAY, MAY, MAY),
    rfc5280.id_emailAddress: (MAY, MAY, MAY),
    rfc5280.id_at_title: (MAY, MAY, MAY),
    x520_name.id_at_streetAddress: (MAY, MAY, SHALL_NOT),
    rfc5280.id_at_localityName: (MAY, MAY, MAY),
    rfc5280.id_at_stateOrProvinceName: (MAY, MAY, MAY),
    x520_name.id_at_postalCode: (MAY, MAY, SHALL_NOT),
    rfc5280.id_at_countryName: (MAY, MAY, MAY),
}

_IV_ATTRIBUTES = {
    rfc5280.id_at_commonName: (MAY, MAY, MAY),
    rfc5280.id_at_organizationName: (SHALL_NOT, SHALL_NOT, SHALL_NOT),
    rfc5280.id_at_organizationalUnitName: (SHALL_NOT, SHALL_NOT, SHALL_NOT),
    x520_name.id_at_organizationIdentifier: (SHALL_NOT, SHALL_NOT, SHALL_NOT),
    rfc5280.id_at_givenName: (MAY, MAY, MAY),
    rfc5280.id_at_surname: (MAY, MAY, MAY),
    rfc5280.id_at_pseudonym: (MAY, MAY, MAY),
    rfc5280.id_at_serialNumber: (MAY, MAY, MAY),
    rfc5280.id_emailAddress: (MAY, MAY, MAY),
    rfc5280.id_at_title: (MAY, MAY, MAY),
    x520_name.id_at_streetAddress: (MAY, MAY, SHALL_NOT),
    rfc5280.id_at_localityName: (MAY, MAY, MAY),
    rfc5280.id_at_stateOrProvinceName: (MAY, MAY, MAY),
    x520_name.id_at_postalCode: (MAY, MAY, SHALL_NOT),
    rfc5280.id_at_countryName: (MAY, MAY, MAY),
}

_GENERATION_INDEXES = {
    Generation.LEGACY: 0,
    Generation.MULTIPURPOSE: 1,
    Generation.STRICT: 2,
}

_VALIDATION_LEVEL_TO_TABLE = {
    ValidationLevel.MAILBOX: _MV_ATTRIBUTES,
    ValidationLevel.ORGANIZATION: _OV_ATTRIBUTES,
    ValidationLevel.SPONSORED: _SV_ATTRIBUTES,
    ValidationLevel.INDIVIDUAL: _IV_ATTRIBUTES,
}

_VALIDATION_LEVEL_TO_OTHER_ATTRIBUTE_ALLOWANCE = {
    ValidationLevel.MAILBOX: (False, False, False),
    ValidationLevel.ORGANIZATION: (True, False, False),
    ValidationLevel.SPONSORED: (True, False, False),
    ValidationLevel.INDIVIDUAL: (True, False, False),
}

_REQUIRED_ONE_OF_N = {
    (ValidationLevel.SPONSORED, Generation.LEGACY): {rfc5280.id_at_givenName, rfc5280.id_at_surname,
                                                     rfc5280.id_at_pseudonym, rfc5280.id_at_commonName},
    (ValidationLevel.INDIVIDUAL, Generation.LEGACY): {rfc5280.id_at_givenName, rfc5280.id_at_surname,
                                                      rfc5280.id_at_pseudonym, rfc5280.id_at_commonName},
    (ValidationLevel.SPONSORED, Generation.MULTIPURPOSE): {rfc5280.id_at_givenName, rfc5280.id_at_surname,
                                                           rfc5280.id_at_pseudonym},
    (ValidationLevel.INDIVIDUAL, Generation.MULTIPURPOSE): {rfc5280.id_at_givenName, rfc5280.id_at_surname,
                                                            rfc5280.id_at_pseudonym},
    (ValidationLevel.SPONSORED, Generation.STRICT): {rfc5280.id_at_givenName, rfc5280.id_at_surname,
                                                     rfc5280.id_at_pseudonym},
    (ValidationLevel.INDIVIDUAL, Generation.STRICT): {rfc5280.id_at_givenName, rfc5280.id_at_surname,
                                                      rfc5280.id_at_pseudonym},
}


class SubscriberSubjectValidator(validation.Validator):
    VALIDATION_MISSING_ATTRIBUTE = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'cabf.smime.missing_required_attribute'
    )

    VALIDATION_PROHIBITED_ATTRIBUTE = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'cabf.smime.prohibited_attribute'
    )

    VALIDATION_MIXED_NAME_AND_PSEUDONYM_ATTRIBUTES = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'cabf.smime.mixed_name_and_pseudonym_attributes'
    )

    def __init__(self, validation_level, generation):
        super().__init__(validations=[
            self.VALIDATION_PROHIBITED_ATTRIBUTE,
            self.VALIDATION_MISSING_ATTRIBUTE,
            self.VALIDATION_MIXED_NAME_AND_PSEUDONYM_ATTRIBUTES,
        ],
            pdu_class=rfc5280.RDNSequence,
            predicate=lambda n: n.path != 'certificate.tbsCertificate.issuer.rdnSequence')

        self._attribute_table = {
            k: v[_GENERATION_INDEXES[generation]] for k, v in _VALIDATION_LEVEL_TO_TABLE[validation_level].items()
        }

        self._required_attributes = {k for k, v in self._attribute_table.items() if v == SHALL}
        self._prohibited_attributes = {k for k, v, in self._attribute_table.items() if v == SHALL_NOT}
        self._required_one_of_n_attributes = _REQUIRED_ONE_OF_N.get((validation_level, generation))

        self._allow_other_oids = _VALIDATION_LEVEL_TO_OTHER_ATTRIBUTE_ALLOWANCE[validation_level][
            _GENERATION_INDEXES[generation]]

    def validate(self, node):
        findings = []

        attributes = set()
        for rdn in node.children.values():
            attributes.update((atv.children['type'].pdu for atv in rdn.children.values()))

        # extract json
        oid_metadata = json.loads(_OID_METADATA)

        findings.extend((
            validation.ValidationFindingDescription(self.VALIDATION_MISSING_ATTRIBUTE,
                                                    f'{oid_metadata[str(a)].name}')
            for a in self._required_attributes - attributes
        ))

        if self._required_one_of_n_attributes and len(self._required_one_of_n_attributes.intersection(attributes)) == 0:
            oids = oid.format_oids(self._required_one_of_n_attributes)
            findings.append(validation.ValidationFindingDescription(self.VALIDATION_MISSING_ATTRIBUTE,
                                                                    f'Missing one of these required attributes: {oids} ') # list all oids with more information
                            )

        findings.extend((
            validation.ValidationFindingDescription(self.VALIDATION_PROHIBITED_ATTRIBUTE,
                                                    f'Prohibited attribute: {a}')
            for a in self._prohibited_attributes.intersection(attributes)
        ))

        if rfc5280.id_at_pseudonym in attributes and (
                any({rfc5280.id_at_givenName, rfc5280.id_at_surname}.intersection(attributes))):
            findings.append(
                validation.ValidationFindingDescription(self.VALIDATION_MIXED_NAME_AND_PSEUDONYM_ATTRIBUTES, None))

        if not self._allow_other_oids:
            findings.extend((
                validation.ValidationFindingDescription(self.VALIDATION_PROHIBITED_ATTRIBUTE,
                                                        f'Prohibited other attribute: {a}')
                for a in attributes - set(self._attribute_table.keys())
            ))

        return validation.ValidationResult(self, node, findings)


class CabfSmimeOrganizationIdentifierAttributeValidator(CabfOrganizationIdentifierAttributeValidator):
    _REFERENCE_PROHIBITED = (Rfc2119Word.MUST_NOT,
                             'cabf.smime.prohibited_organization_identifier_reference_present_for_scheme')

    _LEI_SCHEME = organization_id.OrganizationIdentifierElementAllowance(
        country_codes=({organization_id.COUNTRY_CODE_GLOBAL_SCHEME},
                       CabfOrganizationIdentifierAttributeValidator.VALIDATION_ORGANIZATION_ID_INVALID_COUNTRY),
        state_province=CabfOrganizationIdentifierAttributeValidator.STATE_PROVINCE_PROHIBITED,
        reference=CabfOrganizationIdentifierAttributeValidator.REFERENCE_REQUIRED
    )
    _GOV_SCHEME = organization_id.OrganizationIdentifierElementAllowance(
        country_codes=(organization_id.ISO3166_1_COUNTRY_CODES,
                       CabfOrganizationIdentifierAttributeValidator.VALIDATION_ORGANIZATION_ID_INVALID_COUNTRY),
        state_province=(Rfc2119Word.MAY, None),
        reference=_REFERENCE_PROHIBITED
    )
    _INT_SCHEME = organization_id.OrganizationIdentifierElementAllowance(
        country_codes=({organization_id.COUNTRY_CODE_GLOBAL_SCHEME},
                       CabfOrganizationIdentifierAttributeValidator.VALIDATION_ORGANIZATION_ID_INVALID_COUNTRY),
        state_province=CabfOrganizationIdentifierAttributeValidator.STATE_PROVINCE_PROHIBITED,
        reference=_REFERENCE_PROHIBITED
    )

    def __init__(self):
        super().__init__(
            {
                'LEI': self._LEI_SCHEME,
                'GOV': self._GOV_SCHEME,
                'INT': self._INT_SCHEME,
            },
            enforce_strict_state_province_format=False
        )


class SubscriberAttributeDependencyValidator(validation.Validator):
    VALIDATION_MISSING_REQUIRED_ATTRIBUTE = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'cabf.smime.required_attribute_missing_for_dependent_attribute'
    )

    _ATTRIBUTE_DEPENDENCIES = [
        (x520_name.id_at_streetAddress, {rfc5280.id_at_localityName, rfc5280.id_at_stateOrProvinceName}),
        (rfc5280.id_at_stateOrProvinceName, {rfc5280.id_at_countryName}),
        (rfc5280.id_at_localityName, {rfc5280.id_at_countryName}),
        (x520_name.id_at_postalCode, {rfc5280.id_at_countryName}),
    ]

    def __init__(self):
        super().__init__(
            validations=[self.VALIDATION_MISSING_REQUIRED_ATTRIBUTE],
            pdu_class=rfc5280.RDNSequence,
            predicate=lambda n: n.path != 'certificate.tbsCertificate.issuer.rdnSequence'
        )

    def validate(self, node):
        attributes = set()
        for rdn in node.children.values():
            attributes.update((atv.children['type'].pdu for atv in rdn.children.values()))

        for dependent_attribute, required_attributes in self._ATTRIBUTE_DEPENDENCIES:
            if dependent_attribute in attributes:
                if not attributes & required_attributes:
                    oids = oid.format_oids(required_attributes)

                    if len(required_attributes) > 1:
                        message = f'one of {oids} is not present'
                    else:
                        message = f'{oids} is not present'

                    raise validation.ValidationFindingEncountered(
                        self.VALIDATION_MISSING_REQUIRED_ATTRIBUTE,
                        f'{dependent_attribute} is present but {message}'
                    )


def create_subscriber_certificate_subject_validator_container(
        validation_level, generation
):
    dn_validators = [
        SubscriberSubjectValidator(validation_level, generation),
        SubscriberAttributeDependencyValidator(),
        SubjectAlternativeNameContainsSubjectEmailAddressesValidator(),
        cabf_name.ValidCountryValidator(),
        CommonNameValidator(validation_level, generation),
        CabfSmimeOrganizationIdentifierAttributeValidator(),
        OrganizationIdentifierLeiValidator(),
        OrganizationIdentifierCountryNameConsistentValidator(),
        cabf_name.RelativeDistinguishedNameContainsOneElementValidator(),
        cabf_name.SignificantAttributeValueValidator(),
    ]

    return certificate.create_subject_validator_container(
        dn_validators, pdu_class=rfc5280.Name,
        predicate=lambda n: n.path != 'certificate.tbsCertificate.issuer'
    )


class SubjectAlternativeNameContainsSubjectEmailAddressesValidator(
    validation.Validator
):
    VALIDATION_EMAIL_ADDRESS_IN_ATTRIBUTE_MISSING_FROM_SAN = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'cabf.smime.email_address_in_attribute_not_in_san'
    )

    VALIDATION_UNPARSED_ATTRIBUTE = validation.ValidationFinding(
        validation.ValidationFindingSeverity.NOTICE,
        'cabf.smime.unparsed_attribute_value_encountered'
    )

    def __init__(self):
        super().__init__(
            validations=[
                self.VALIDATION_EMAIL_ADDRESS_IN_ATTRIBUTE_MISSING_FROM_SAN,
                self.VALIDATION_UNPARSED_ATTRIBUTE,
            ],
            pdu_class=rfc5280.AttributeTypeAndValue,
            # emailAddress presence in SAN is checked by PKIX lint
            predicate=lambda n: n.children['type'].pdu != rfc5280.id_emailAddress
        )

    def validate(self, node):
        oid = node.children['type'].pdu

        value_str = asn1_util.get_string_value_from_attribute_node(node)

        if value_str is None:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_UNPARSED_ATTRIBUTE,
                f'Unparsed attribute {str(oid)} encountered'
            )

        if bool(validators.email(value_str)):
            san_email_addresses = get_email_addresses_from_san(node.document)

            if value_str not in san_email_addresses:
                raise validation.ValidationFindingEncountered(
                    self.VALIDATION_EMAIL_ADDRESS_IN_ATTRIBUTE_MISSING_FROM_SAN,
                    f'Attribute {str(oid)} with value "{value_str}" not found in SAN'
                )


class CommonNameValidator(validation.Validator):
    VALIDATION_COMMON_NAME_UNKNOWN_VALUE_SOURCE = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'cabf.smime.common_name_value_unknown_source'
    )

    VALIDATION_UNPARSED_COMMON_NAME_VALUE = validation.ValidationFinding(
        validation.ValidationFindingSeverity.NOTICE,
        'cabf.smime.unparsed_common_name_value'
    )

    def __init__(self, validation_level, generation):
        super().__init__(
            validations=[self.VALIDATION_COMMON_NAME_UNKNOWN_VALUE_SOURCE, self.VALIDATION_UNPARSED_COMMON_NAME_VALUE],
            pdu_class=rfc5280.X520CommonName
        )

        self._validation_level = validation_level
        self._generation = generation

    @staticmethod
    def _is_value_in_dirstring_atvs(atvs, expected_value_node):
        expected_value_str = str(expected_value_node.pdu)

        return any(expected_value_str == asn1_util.get_string_value_from_attribute_node(a) for a in atvs)

    def validate(self, node):
        try:
            _, cn_value_node = node.child
        except ValueError:
            raise validation.ValidationFindingEncountered(self.VALIDATION_UNPARSED_COMMON_NAME_VALUE)

        parent_name_node = next((n for n in node.parents if isinstance(n.pdu, rfc5280.Name)))

        if self._validation_level in {ValidationLevel.SPONSORED, ValidationLevel.INDIVIDUAL}:
            # legacy sponsored and individual profiles allow the Personal Name in CN without being in other
            # subject attributes
            if self._generation == Generation.LEGACY:
                return

            # we don't need the index
            pseudonym_nodes = [t[0] for t in
                               name.get_name_attributes_by_type(parent_name_node, rfc5280.id_at_pseudonym)]

            if CommonNameValidator._is_value_in_dirstring_atvs(pseudonym_nodes, cn_value_node):
                return

            # if there's a GN or SN, assume it's in the CN
            if (
                    any(name.get_name_attributes_by_type(parent_name_node, rfc5280.id_at_givenName)) or
                    any(name.get_name_attributes_by_type(parent_name_node, rfc5280.id_at_surname))):
                return
        elif self._validation_level == ValidationLevel.ORGANIZATION:
            orgname_nodes = [t[0] for t in
                             name.get_name_attributes_by_type(parent_name_node, rfc5280.id_at_organizationName)]

            if CommonNameValidator._is_value_in_dirstring_atvs(orgname_nodes, cn_value_node):
                return

        email_addresses = get_email_addresses_from_san(node.document)

        if str(cn_value_node.pdu) not in email_addresses:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_COMMON_NAME_UNKNOWN_VALUE_SOURCE,
                f'Unknown CN value source: "{str(cn_value_node.pdu)}"'
            )


class OrganizationIdentifierCountryNameConsistentValidator(validation.Validator):
    VALIDATION_ORGID_COUNTRYNAME_INCONSISTENT = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'cabf.smime.org_identifier_and_country_name_attribute_inconsistent'
    )

    def __init__(self):
        super().__init__(validations=self.VALIDATION_ORGID_COUNTRYNAME_INCONSISTENT,
                         pdu_class=rfc5280.X520countryName)

    def validate(self, node):
        country_name_value = str(node.pdu)

        for atv, _ in node.document.get_subject_attributes_by_type(x520_name.id_at_organizationIdentifier):
            x520_value_str = asn1_util.get_string_value_from_attribute_node(atv)

            if x520_value_str is None:
                continue

            try:
                parsed_org_id = organization_id.parse_organization_identifier(x520_value_str)
            except ValueError:
                continue

            orgid_country_name = parsed_org_id.country

            # skip this orgId attribute if it contains the global scheme identifier
            if orgid_country_name == organization_id.COUNTRY_CODE_GLOBAL_SCHEME:
                continue

            if orgid_country_name != country_name_value:
                raise validation.ValidationFindingEncountered(
                    self.VALIDATION_ORGID_COUNTRYNAME_INCONSISTENT,
                    f'CountryName attribute value: "{country_name_value}", '
                    f'OrganizationIdentifier attribute country name value: "{orgid_country_name}"'
                )


def get_email_addresses_from_san(cert_document):
    san_ext_and_idx = cert_document.get_extension_by_oid(rfc5280.id_ce_subjectAltName)

    if san_ext_and_idx is None:
        return []

    san_ext, _ = san_ext_and_idx

    email_addresses = []
    for gn in san_ext.navigate('extnValue.subjectAltName').children.values():
        name, value = gn.child

        if name == general_name.GeneralNameTypeName.RFC822_NAME:
            email_addresses.append(value.pdu)
        elif (
                name == general_name.GeneralNameTypeName.OTHER_NAME and
                value.navigate('type-id').pdu == rfc8398.id_on_SmtpUTF8Mailbox
        ):
            email_addresses.append(value.navigate('value').child[1].pdu)

    return email_addresses

